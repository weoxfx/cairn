//! Encrypted wallet file: Argon2id -> ChaCha20-Poly1305.
//! We store the BIP39 *entropy* (not the words) encrypted; words can be rebuilt from it.
//!
//! v1 files are testnet-only and use the original AAD. v2 files authenticate the
//! network, fingerprint and KDF metadata in the AAD, so editing any of those fields
//! makes decryption fail instead of silently relabelling a mainnet wallet.

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// Defaults for new wallets (OWASP minimum is 19 MB / 2 passes; this is far above it).
const MEM_KIB: u32 = 131_072;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
const AAD_V1: &[u8] = b"cairn-keystore-v1";
const MAX_FILE_BYTES: u64 = 65_536;

#[derive(Serialize, Deserialize, Clone)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn default_strong() -> Self {
        KdfParams {
            memory_kib: MEM_KIB,
            iterations: ITERATIONS,
            parallelism: PARALLELISM,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Keystore {
    pub version: u32,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    pub fingerprint: String,
    pub network: String,
}

/// A successfully decrypted wallet. The mnemonic is zeroized on drop by `bip39`.
pub struct Opened {
    pub mnemonic: Mnemonic,
    pub fingerprint: String,
    pub network: Network,
}

fn network_id(network: Network) -> Result<&'static str, String> {
    match network {
        Network::Bitcoin => Ok("mainnet"),
        Network::Testnet | Network::Testnet4 | Network::Signet => Ok("testnet"),
        _ => Err("unsupported network".into()),
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        _ => Err("unsupported wallet version or network".into()),
    }
}

/// Canonical metadata bound to a v2 ciphertext.
fn aad_v2(
    network: Network,
    fingerprint: &str,
    p: &KdfParams,
    salt: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    Ok(format!(
        "cairn-keystore-v2\nnetwork={}\nfingerprint={fingerprint}\nkdf=argon2id\n\
         memory_kib={}\niterations={}\nparallelism={}\nsalt={}\nnonce={}\n",
        network_id(network)?,
        p.memory_kib,
        p.iterations,
        p.parallelism,
        hex::encode(salt),
        hex::encode(nonce)
    )
    .into_bytes())
}

/// A tampered wallet file must not be able to weaken the KDF or exhaust memory.
fn validate_params(p: &KdfParams) -> Result<(), String> {
    let ok = (19_456..=1_048_576).contains(&p.memory_kib)
        && (2..=20).contains(&p.iterations)
        && (1..=16).contains(&p.parallelism);
    if ok {
        Ok(())
    } else {
        Err("unsafe or unsupported KDF parameters in wallet file".into())
    }
}

/// Random bytes straight from the OS.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| format!("OS randomness failed: {e}"))?;
    Ok(buf)
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn wallet_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let dir = PathBuf::from(home).join(".cairn").join("wallets");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn wallet_path(name: &str) -> Result<PathBuf, String> {
    if !valid_name(name) {
        return Err("Name may only use letters, numbers, - and _ (max 32)".into());
    }
    Ok(wallet_dir()?.join(format!("{name}.cairn")))
}

pub fn list_wallets() -> Result<Vec<String>, String> {
    let mut out = vec![];
    for entry in fs::read_dir(wallet_dir()?).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|e| e.to_str()) == Some("cairn") {
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn derive_key(password: &str, salt: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>, String> {
    validate_params(p)?;
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(32))
        .map_err(|e| format!("bad KDF params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| format!("KDF failed: {e}"))?;
    Ok(key)
}

/// Fingerprint of the master key (public, lets users confirm the right wallet opened).
/// The fingerprint is a hash of the master public key, so it is the same on every
/// network; the keystore authenticates the wallet network separately in the AAD.
pub fn fingerprint(mnemonic: &Mnemonic, network: Network) -> Result<String, String> {
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let mut master = Xpriv::new_master(network, seed.as_ref()).map_err(|e| e.to_string())?;
    let secp = Secp256k1::new();
    let fp = master.fingerprint(&secp).to_string();
    master.private_key.non_secure_erase();
    Ok(fp)
}

pub fn save(
    name: &str,
    password: &str,
    mnemonic: &Mnemonic,
    network: Network,
) -> Result<(), String> {
    save_with(
        name,
        password,
        mnemonic,
        network,
        KdfParams::default_strong(),
    )
}

/// Encrypt entropy with the password and write the wallet file atomically.
pub fn save_with(
    name: &str,
    password: &str,
    mnemonic: &Mnemonic,
    network: Network,
    params: KdfParams,
) -> Result<(), String> {
    let path = wallet_path(name)?;
    if path.exists() {
        return Err("A wallet with that name already exists".into());
    }

    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<12>()?;
    let key = derive_key(password, &salt, &params)?;
    let fp = fingerprint(mnemonic, network)?;
    let aad = aad_v2(network, &fp, &params, &salt, &nonce)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: entropy.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| "encryption failed".to_string())?;

    let ks = Keystore {
        version: 2,
        kdf: "argon2id".into(),
        kdf_params: params,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        fingerprint: fp,
        network: network_id(network)?.into(),
    };
    let json = serde_json::to_vec_pretty(&ks).map_err(|e| e.to_string())?;

    // Temp file (0600) -> fsync -> rename -> fsync directory, so a crash can't corrupt the wallet.
    // A random suffix keeps concurrent saves from clobbering each other's temp file.
    let tmp = path.with_extension(format!("{}.tmp", hex::encode(random_bytes::<8>()?)));
    let written = (|| -> Result<(), String> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(&json).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Open, validate and read the wallet in one step. `O_NOFOLLOW` (and `O_NONBLOCK`
/// so a planted FIFO cannot hang us) means the checks and the read act on the same
/// file descriptor, closing the old check/read race.
fn read_wallet_file(path: &Path) -> Result<Vec<u8>, String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot read wallet: {e}"))?;
    let meta = f
        .metadata()
        .map_err(|e| format!("cannot read wallet: {e}"))?;
    if !meta.is_file() {
        return Err("wallet path is not a regular file".into());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err("wallet file is unexpectedly large".into());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    let mut data = Vec::new();
    f.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("cannot read wallet: {e}"))?;
    if data.len() as u64 > MAX_FILE_BYTES {
        return Err("wallet file is unexpectedly large".into());
    }
    Ok(data)
}

/// Decrypt a wallet. Returns the mnemonic, fingerprint and authenticated network.
/// Wrong password, a tampered file and an unsupported format all produce the same
/// generic error where possible, so the file cannot be used as an oracle.
pub fn open(name: &str, password: &str) -> Result<Opened, String> {
    let path = wallet_path(name)?;
    let data = read_wallet_file(&path)?;
    let ks: Keystore =
        serde_json::from_slice(&data).map_err(|_| "corrupt wallet file".to_string())?;
    if ks.kdf != "argon2id" {
        return Err("unsupported wallet version or network".into());
    }
    validate_params(&ks.kdf_params)?;

    let bad = || "wrong password or damaged wallet file".to_string();
    let salt = hex::decode(&ks.salt).map_err(|_| bad())?;
    let nonce = hex::decode(&ks.nonce).map_err(|_| bad())?;
    let ct = hex::decode(&ks.ciphertext).map_err(|_| bad())?;
    if nonce.len() != 12 || salt.len() < 16 {
        return Err(bad());
    }

    let key = derive_key(password, &salt, &ks.kdf_params)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));

    let (plain, network) = match ks.version {
        // v1 existed before mainnet support and was always testnet. Its AAD does
        // not bind the network, so only accept it as testnet.
        1 => {
            if ks.network != "testnet" {
                return Err("unsupported wallet version or network".into());
            }
            let plain = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: AAD_V1,
                    },
                )
                .map_err(|_| bad())?;
            (plain, Network::Testnet)
        }
        2 => {
            let network = parse_network(&ks.network)?;
            let aad = aad_v2(network, &ks.fingerprint, &ks.kdf_params, &salt, &nonce)?;
            let plain = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| bad())?;
            (plain, network)
        }
        _ => return Err("unsupported wallet version or network".into()),
    };

    let entropy = Zeroizing::new(plain);
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|_| bad())?;
    let fp = fingerprint(&mnemonic, network)?;
    if fp != ks.fingerprint {
        return Err(bad());
    }
    Ok(Opened {
        mnemonic,
        fingerprint: fp,
        network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }

    fn test_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-test-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("HOME", &dir);
        dir
    }

    #[test]
    fn roundtrip_wrong_password_tamper_and_duplicate() {
        let dir = test_home("roundtrip");
        let pw = "correct horse battery staple";
        let m = Mnemonic::from_entropy(&[7u8; 32]).unwrap();

        save_with("t1", pw, &m, Network::Testnet, fast()).unwrap();
        let opened = open("t1", pw).unwrap();
        assert_eq!(m.to_string(), opened.mnemonic.to_string());
        assert_eq!(
            opened.fingerprint,
            fingerprint(&m, Network::Testnet).unwrap()
        );
        assert_eq!(opened.network, Network::Testnet);

        assert!(open("t1", "a totally wrong password").is_err());
        assert!(
            save_with("t1", pw, &m, Network::Testnet, fast()).is_err(),
            "must not overwrite existing wallet"
        );

        // Flip one hex digit of the ciphertext: must fail authentication.
        let path = wallet_path("t1").unwrap();
        let mut ks: Keystore = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut c = ks.ciphertext.clone().into_bytes();
        c[0] = if c[0] == b'0' { b'1' } else { b'0' };
        ks.ciphertext = String::from_utf8(c).unwrap();
        fs::write(&path, serde_json::to_vec(&ks).unwrap()).unwrap();
        assert!(open("t1", pw).is_err(), "tampered file must be rejected");

        // A file that tries to weaken the KDF must be rejected before any work is done.
        ks.kdf_params = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        fs::write(&path, serde_json::to_vec(&ks).unwrap()).unwrap();
        assert!(
            open("t1", pw).is_err(),
            "weakened KDF params must be rejected"
        );

        // Symlinks and oversized files must be refused.
        let dir_path = wallet_dir().unwrap();
        let link = dir_path.join("link.cairn");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            open("link", pw).is_err(),
            "symlinked wallet must be rejected"
        );
        let big = dir_path.join("big.cairn");
        fs::write(&big, vec![b'x'; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(
            open("big", pw).is_err(),
            "oversized wallet must be rejected"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mainnet_roundtrip_and_network_is_authenticated() {
        let dir = test_home("mainnet");
        let pw = "a strong passphrase for mainnet";
        let m = Mnemonic::from_entropy(&[42u8; 32]).unwrap();

        save_with("m1", pw, &m, Network::Bitcoin, fast()).unwrap();
        let opened = open("m1", pw).unwrap();
        assert_eq!(opened.network, Network::Bitcoin);
        assert_eq!(
            opened.fingerprint,
            fingerprint(&m, Network::Bitcoin).unwrap()
        );

        // Relabel mainnet as testnet in the JSON: AAD must reject it.
        let path = wallet_path("m1").unwrap();
        let mut ks: Keystore = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        ks.network = "testnet".into();
        fs::write(&path, serde_json::to_vec(&ks).unwrap()).unwrap();
        assert!(
            open("m1", pw).is_err(),
            "unauthenticated network relabel must fail"
        );

        // Changing the stored fingerprint must also fail authentication.
        ks.network = "mainnet".into();
        ks.fingerprint = "00000000".into();
        fs::write(&path, serde_json::to_vec(&ks).unwrap()).unwrap();
        assert!(open("m1", pw).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_testnet_wallet_still_opens() {
        let dir = test_home("v1");
        let pw = "old wallet password";
        let m = Mnemonic::from_entropy(&[5u8; 16]).unwrap();
        let params = fast();
        let salt = random_bytes::<16>().unwrap();
        let nonce = random_bytes::<12>().unwrap();
        let key = derive_key(pw, &salt, &params).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &m.to_entropy(),
                    aad: AAD_V1,
                },
            )
            .unwrap();
        let ks = Keystore {
            version: 1,
            kdf: "argon2id".into(),
            kdf_params: params,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ct),
            fingerprint: fingerprint(&m, Network::Testnet).unwrap(),
            network: "testnet".into(),
        };
        fs::create_dir_all(wallet_dir().unwrap()).unwrap();
        fs::write(
            wallet_path("old").unwrap(),
            serde_json::to_vec(&ks).unwrap(),
        )
        .unwrap();

        let opened = open("old", pw).unwrap();
        assert_eq!(opened.network, Network::Testnet);
        assert_eq!(opened.mnemonic.to_string(), m.to_string());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kdf_param_limits() {
        assert!(validate_params(&KdfParams::default_strong()).is_ok());
        assert!(validate_params(&KdfParams {
            memory_kib: 4_194_304,
            iterations: 3,
            parallelism: 1
        })
        .is_err());
        assert!(validate_params(&KdfParams {
            memory_kib: 262_144,
            iterations: 1,
            parallelism: 1
        })
        .is_err());
        assert!(validate_params(&KdfParams {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 0
        })
        .is_err());
    }

    #[test]
    fn wallet_name_validation() {
        assert!(valid_name("my-wallet_1"));
        assert!(!valid_name(""));
        assert!(!valid_name("../evil"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(&"x".repeat(33)));
    }
}
