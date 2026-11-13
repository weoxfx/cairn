//! Encrypted wallet file: Argon2id -> ChaCha20-Poly1305.
//! We store the BIP39 *entropy* (not the words) encrypted; words can be rebuilt from it.
//!
//! v1 files are testnet-only and use the original AAD. v2 files authenticate the
//! network, fingerprint and KDF metadata in the AAD, so editing any of those fields
//! makes decryption fail instead of silently relabelling a mainnet wallet.

use crate::hardening;
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

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

/// Address format a wallet derives. Stored in the header of a v4 file and
/// authenticated along with the rest of the metadata, so a tampered file cannot
/// silently change which addresses (or which derivation purpose) the wallet uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AddressType {
    /// BIP84, `m/84'/coin'/0'` — `bc1q…` / `tb1q…`.
    #[default]
    P2wpkh,
    /// BIP86 key-path only, `m/86'/coin'/0'` — `bc1p…` / `tb1p…`.
    P2tr,
}

impl AddressType {
    pub fn id(self) -> &'static str {
        match self {
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2tr => "p2tr",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            AddressType::P2wpkh => "Native SegWit (BIP84)",
            AddressType::P2tr => "Taproot (BIP86)",
        }
    }

    /// BIP purpose used in the derivation path.
    pub fn purpose(self) -> u32 {
        match self {
            AddressType::P2wpkh => 84,
            AddressType::P2tr => 86,
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2tr" => Ok(AddressType::P2tr),
            _ => Err("unsupported address type".into()),
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
    /// v3 only: whether the wallet uses a BIP39 passphrase. The passphrase
    /// itself is never stored; it is required again on every unlock.
    #[serde(default)]
    pub passphrase: bool,
    /// v4 only: `p2wpkh` or `p2tr`. Files written before v4 were always BIP84 and
    /// default to `p2wpkh`.
    #[serde(default)]
    pub address_type: Option<String>,
}

/// A successfully decrypted wallet. The mnemonic and passphrase live in locked
/// allocations (best effort) and are zeroized on drop.
///
/// Fields are crate-private on purpose: this value is the proof that a wallet
/// file was authenticated with its password, so it must not be constructible
/// from a bare mnemonic outside this module. `Signer::from_opened` relies on it.
pub struct Opened {
    pub(crate) mnemonic: Box<Mnemonic>,
    pub(crate) passphrase: Zeroizing<String>,
    pub fingerprint: String,
    pub network: Network,
    /// Authenticated address format of this wallet.
    pub address_type: AddressType,
}

impl Drop for Opened {
    fn drop(&mut self) {
        // Wipe while the allocation is still locked, then release it.
        self.mnemonic.zeroize();
        hardening::unlock_memory(
            self.mnemonic.as_ref() as *const Mnemonic as *const u8,
            std::mem::size_of::<Mnemonic>(),
        );
    }
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

/// v3 binds the presence of a BIP39 passphrase as well as the network. The
/// passphrase itself is never written to disk; changing the flag makes
/// decryption fail.
fn aad_v3(
    network: Network,
    fingerprint: &str,
    p: &KdfParams,
    salt: &[u8],
    nonce: &[u8],
    passphrase: bool,
) -> Result<Vec<u8>, String> {
    Ok(format!(
        "cairn-keystore-v3\nnetwork={}\nfingerprint={fingerprint}\nkdf=argon2id\n\
         memory_kib={}\niterations={}\nparallelism={}\nsalt={}\nnonce={}\npassphrase={}\n",
        network_id(network)?,
        p.memory_kib,
        p.iterations,
        p.parallelism,
        hex::encode(salt),
        hex::encode(nonce),
        if passphrase { "true" } else { "false" }
    )
    .into_bytes())
}

/// v4 binds the address type as well: switching a wallet between BIP84 and BIP86
/// in the header makes decryption fail instead of showing other addresses.
fn aad_v4(
    network: Network,
    fingerprint: &str,
    p: &KdfParams,
    salt: &[u8],
    nonce: &[u8],
    passphrase: bool,
    address_type: AddressType,
) -> Result<Vec<u8>, String> {
    Ok(format!(
        "cairn-keystore-v4\nnetwork={}\nfingerprint={fingerprint}\nkdf=argon2id\n\
         memory_kib={}\niterations={}\nparallelism={}\nsalt={}\nnonce={}\npassphrase={}\n\
         address_type={}\n",
        network_id(network)?,
        p.memory_kib,
        p.iterations,
        p.parallelism,
        hex::encode(salt),
        hex::encode(nonce),
        if passphrase { "true" } else { "false" },
        address_type.id()
    )
    .into_bytes())
}

/// A tampered wallet file must not be able to weaken the KDF or exhaust memory.
pub fn validate_params(p: &KdfParams) -> Result<(), String> {
    // Upper bounds are deliberately tight: a tampered file cannot make us burn
    // gigabytes of memory or minutes of CPU before authentication fails. New
    // wallets use 128 MiB / 3 passes, well inside the accepted window.
    let ok = (19_456..=262_144).contains(&p.memory_kib)
        && (2..=10).contains(&p.iterations)
        && (1..=4).contains(&p.parallelism);
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
    let base = PathBuf::from(home).join(".cairn");
    crate::hardening::ensure_private_dir(&base)?;
    let dir = base.join("wallets");
    crate::hardening::ensure_private_dir(&dir)?;
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
#[allow(dead_code)] // compatibility/test entry point; production uses fingerprint_with
pub fn fingerprint(mnemonic: &Mnemonic, network: Network) -> Result<String, String> {
    fingerprint_with(mnemonic, network, "")
}

/// Fingerprint for a seed derived with a BIP39 passphrase.
pub fn fingerprint_with(
    mnemonic: &Mnemonic,
    network: Network,
    passphrase: &str,
) -> Result<String, String> {
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let mut master = Xpriv::new_master(network, seed.as_ref()).map_err(|e| e.to_string())?;
    let secp = Secp256k1::new();
    let fp = master.fingerprint(&secp).to_string();
    master.private_key.non_secure_erase();
    Ok(fp)
}

#[allow(dead_code)] // compatibility/test entry point
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
#[allow(dead_code)] // compatibility/test entry point
pub fn save_with(
    name: &str,
    password: &str,
    mnemonic: &Mnemonic,
    network: Network,
    params: KdfParams,
) -> Result<(), String> {
    save_with_passphrase(
        name,
        password,
        mnemonic,
        network,
        None,
        params,
        AddressType::P2wpkh,
    )
}

/// Save a wallet with an optional BIP39 passphrase and an address format.
///
/// New wallets are always written as v4, which authenticates the network, the
/// fingerprint, the KDF parameters, whether a BIP39 passphrase is in use, and the
/// address type (BIP84 or BIP86).
pub fn save_with_passphrase(
    name: &str,
    password: &str,
    mnemonic: &Mnemonic,
    network: Network,
    passphrase: Option<&str>,
    params: KdfParams,
    address_type: AddressType,
) -> Result<(), String> {
    let passphrase = passphrase.filter(|p| !p.is_empty());
    let path = wallet_path(name)?;
    if path.exists() {
        return Err("A wallet with that name already exists".into());
    }

    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<12>()?;
    let key = derive_key(password, &salt, &params)?;
    let fp = fingerprint_with(mnemonic, network, passphrase.unwrap_or(""))?;
    let version = 4;
    let aad = aad_v4(
        network,
        &fp,
        &params,
        &salt,
        &nonce,
        passphrase.is_some(),
        address_type,
    )?;

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
        version,
        kdf: "argon2id".into(),
        kdf_params: params,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        fingerprint: fp,
        network: network_id(network)?.into(),
        passphrase: passphrase.is_some(),
        address_type: Some(address_type.id().into()),
    };
    let json = serde_json::to_vec_pretty(&ks).map_err(|e| e.to_string())?;

    // Temp file (0600) -> fsync -> no-replace link -> fsync directory. A hard
    // link fails atomically if the destination exists, so two concurrent
    // creations cannot silently replace each other (L-05). A random suffix
    // keeps concurrent temp files apart.
    let tmp = path.with_extension(format!("{}.tmp", hex::encode(random_bytes::<8>()?)));
    let written = (|| -> Result<(), String> {
        let mut f = crate::hardening::create_private(&tmp).map_err(|e| e.to_string())?;
        f.write_all(&json).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let linked = fs::hard_link(&tmp, &path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            "A wallet with that name already exists".to_string()
        } else {
            e.to_string()
        }
    });
    let _ = fs::remove_file(&tmp);
    linked?;
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
    let f = crate::hardening::open_read(path).map_err(|e| format!("cannot read wallet: {e}"))?;
    let meta = f
        .metadata()
        .map_err(|e| format!("cannot read wallet: {e}"))?;
    if !meta.is_file() {
        return Err("wallet path is not a regular file".into());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err("wallet file is unexpectedly large".into());
    }
    if crate::hardening::mode_of(&meta) & 0o077 != 0 {
        crate::hardening::restrict(&f).map_err(|e| e.to_string())?;
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

/// Public (non-secret) properties of a wallet file, for `cairn security check`.
/// Nothing here decrypts the wallet or exposes key material; the recorded values
/// are exactly the header fields an attacker or a damaged disk could change.
pub struct FileInfo {
    pub version: u32,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub passphrase: bool,
    pub fingerprint: String,
    pub network: String,
    pub size: u64,
    /// Mode bits observed *before* [`read_wallet_file`] tightens them to 0600.
    pub mode: u32,
    pub dir_mode: u32,
}

pub fn inspect(name: &str) -> Result<FileInfo, String> {
    let path = wallet_path(name)?;
    // Read the permissions first: read_wallet_file silently repairs a file that
    // is group/world readable, and that repair must still be reported.
    let before = fs::symlink_metadata(&path).map_err(|e| format!("cannot read wallet: {e}"))?;
    if !before.is_file() {
        return Err("wallet path is not a regular file".into());
    }
    let dir_mode = path
        .parent()
        .and_then(|d| fs::symlink_metadata(d).ok())
        .map(|m| crate::hardening::mode_of(&m))
        .unwrap_or(0);
    let data = read_wallet_file(&path)?;
    let ks: Keystore =
        serde_json::from_slice(&data).map_err(|_| "corrupt wallet file".to_string())?;
    Ok(FileInfo {
        version: ks.version,
        kdf: ks.kdf,
        kdf_params: ks.kdf_params,
        passphrase: ks.passphrase,
        fingerprint: ks.fingerprint,
        network: ks.network,
        size: data.len() as u64,
        mode: crate::hardening::mode_of(&before),
        dir_mode,
    })
}

/// Whether opening this wallet will require a BIP39 passphrase. This reads only
/// public header fields; the password is still required to decrypt.
pub fn requires_passphrase(name: &str) -> Result<bool, String> {
    let path = wallet_path(name)?;
    let data = read_wallet_file(&path)?;
    let ks: Keystore =
        serde_json::from_slice(&data).map_err(|_| "corrupt wallet file".to_string())?;
    Ok(ks.version >= 3 && ks.passphrase)
}

/// Decrypt a wallet without a BIP39 passphrase.
#[allow(dead_code)] // compatibility/test entry point; production uses open_with
pub fn open(name: &str, password: &str) -> Result<Opened, String> {
    open_with(name, password, None)
}

/// Decrypt a wallet. Returns the mnemonic, fingerprint and authenticated network.
/// Wrong password, a tampered file and an unsupported format all produce the same
/// generic error where possible, so the file cannot be used as an oracle.
pub fn open_with(name: &str, password: &str, passphrase: Option<&str>) -> Result<Opened, String> {
    let path = wallet_path(name)?;
    let data = read_wallet_file(&path)?;
    let ks: Keystore =
        serde_json::from_slice(&data).map_err(|_| "corrupt wallet file".to_string())?;
    if ks.kdf != "argon2id" {
        return Err("unsupported wallet version or network".into());
    }
    validate_params(&ks.kdf_params)?;

    let pass = Zeroizing::new(passphrase.unwrap_or("").to_string());
    let supplied = !pass.is_empty();

    let bad = || "wrong password or damaged wallet file".to_string();
    let salt = hex::decode(&ks.salt).map_err(|_| bad())?;
    let nonce = hex::decode(&ks.nonce).map_err(|_| bad())?;
    let ct = hex::decode(&ks.ciphertext).map_err(|_| bad())?;
    if nonce.len() != 12 || !(16..=64).contains(&salt.len()) || ct.is_empty() || ct.len() > 64 {
        return Err(bad());
    }

    let key = derive_key(password, &salt, &ks.kdf_params)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));

    let (plain, network, address_type) = match ks.version {
        // v1 existed before mainnet support and was always testnet. Its AAD does
        // not bind the network, so only accept it as testnet.
        1 => {
            if ks.network != "testnet" || supplied || ks.passphrase {
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
            (plain, Network::Testnet, AddressType::P2wpkh)
        }
        2 => {
            if supplied || ks.passphrase {
                return Err("unsupported wallet version or network".into());
            }
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
            (plain, network, AddressType::P2wpkh)
        }
        3 => {
            if !ks.passphrase {
                return Err("unsupported wallet version or network".into());
            }
            if !supplied {
                return Err("this wallet requires a BIP39 passphrase".into());
            }
            let network = parse_network(&ks.network)?;
            let aad = aad_v3(
                network,
                &ks.fingerprint,
                &ks.kdf_params,
                &salt,
                &nonce,
                true,
            )?;
            let plain = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| bad())?;
            (plain, network, AddressType::P2wpkh)
        }
        4 => {
            let network = parse_network(&ks.network)?;
            // The passphrase is never stored; whether one was used is
            // authenticated, so a caller cannot skip it (or add one).
            if supplied != ks.passphrase {
                return Err("this wallet has a different BIP39 passphrase requirement".into());
            }
            // A v4 file must name its address type; a missing or unknown value
            // means the header was damaged, so refuse rather than guess.
            let address_type = AddressType::parse(ks.address_type.as_deref().ok_or_else(bad)?)?;
            let aad = aad_v4(
                network,
                &ks.fingerprint,
                &ks.kdf_params,
                &salt,
                &nonce,
                passphrase.is_some(),
                address_type,
            )?;
            let plain = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| bad())?;
            (plain, network, address_type)
        }
        _ => return Err("unsupported wallet version or network".into()),
    };

    let entropy = Zeroizing::new(plain);
    let mnemonic = Box::new(Mnemonic::from_entropy(&entropy).map_err(|_| bad())?);
    let fp = fingerprint_with(&mnemonic, network, &pass)?;
    if fp != ks.fingerprint {
        return Err(bad());
    }
    hardening::lock_memory(
        mnemonic.as_ref() as *const Mnemonic as *const u8,
        std::mem::size_of::<Mnemonic>(),
    );
    let opened_pass = if ks.version >= 3 {
        pass
    } else {
        Zeroizing::new(String::new())
    };
    Ok(Opened {
        mnemonic,
        passphrase: opened_pass,
        fingerprint: fp,
        network,
        address_type,
    })
}

/// Fuzzing entry point for the wallet file parser. Enabled only by the
/// `fuzzing` feature. It exercises JSON, parameter bounds, hex decoding and AAD
/// construction without running Argon2 (which would make fuzzing far too slow).
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_keystore(data: &[u8]) {
    let Ok(ks) = serde_json::from_slice::<Keystore>(data) else {
        return;
    };
    let _ = validate_params(&ks.kdf_params);
    let Ok(salt) = hex::decode(&ks.salt) else {
        return;
    };
    let Ok(nonce) = hex::decode(&ks.nonce) else {
        return;
    };
    let Ok(ct) = hex::decode(&ks.ciphertext) else {
        return;
    };
    if nonce.len() != 12 || !(16..=64).contains(&salt.len()) || ct.is_empty() || ct.len() > 64 {
        return;
    }
    if let Ok(network) = parse_network(&ks.network) {
        let _ = aad_v2(network, &ks.fingerprint, &ks.kdf_params, &salt, &nonce);
        let _ = aad_v3(
            network,
            &ks.fingerprint,
            &ks.kdf_params,
            &salt,
            &nonce,
            ks.passphrase,
        );
    }
    let _ = network_id(Network::Testnet);
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
        #[cfg(unix)]
        {
            let link = dir_path.join("link.cairn");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(
                open("link", pw).is_err(),
                "symlinked wallet must be rejected"
            );
        }
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
            passphrase: false,
            address_type: None,
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
    fn taproot_wallet_round_trips_and_binds_address_type() {
        let dir = test_home("v4");
        let pw = "a strong wallet password";
        let m = Mnemonic::from_entropy(&[9u8; 32]).unwrap();
        save_with_passphrase(
            "t1",
            pw,
            &m,
            Network::Bitcoin,
            None,
            fast(),
            AddressType::P2tr,
        )
        .unwrap();
        assert_eq!(inspect("t1").unwrap().version, 4);
        let opened = open("t1", pw).unwrap();
        assert_eq!(opened.address_type, AddressType::P2tr);
        assert_eq!(opened.mnemonic.to_string(), m.to_string());

        // Editing the header to a different address type must fail the AAD check
        // instead of quietly switching the wallet to BIP84 addresses.
        let path = wallet_path("t1").unwrap();
        let data = fs::read_to_string(&path).unwrap();
        assert!(data.contains("\"p2tr\""));
        fs::write(&path, data.replace("p2tr", "p2wpkh")).unwrap();
        assert!(open("t1", pw).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn passphrase_wallet_requires_and_authenticates_passphrase() {
        let dir = test_home("passphrase");
        let pw = "a strong wallet password";
        let pass = "correct horse battery staple";
        let m = Mnemonic::from_entropy(&[33u8; 32]).unwrap();

        save_with_passphrase(
            "p1",
            pw,
            &m,
            Network::Bitcoin,
            Some(pass),
            fast(),
            AddressType::P2wpkh,
        )
        .unwrap();
        assert!(requires_passphrase("p1").unwrap());

        let opened = open_with("p1", pw, Some(pass)).unwrap();
        assert_eq!(opened.network, Network::Bitcoin);
        assert_eq!(opened.mnemonic.to_string(), m.to_string());
        assert_eq!(opened.passphrase.as_str(), pass);
        assert_eq!(
            opened.fingerprint,
            fingerprint_with(&m, Network::Bitcoin, pass).unwrap()
        );

        // The same password with no passphrase, or a wrong passphrase, must fail.
        assert!(open("p1", pw).is_err());
        assert!(open_with("p1", pw, Some("wrong passphrase")).is_err());
        // A v2 wallet must not silently accept a passphrase.
        save_with("p2", pw, &m, Network::Bitcoin, fast()).unwrap();
        assert!(!requires_passphrase("p2").unwrap());
        assert!(open_with("p2", pw, Some(pass)).is_err());

        // Flipping the stored passphrase flag must break authentication.
        let path = wallet_path("p1").unwrap();
        let mut ks: Keystore = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        ks.passphrase = false;
        fs::write(&path, serde_json::to_vec(&ks).unwrap()).unwrap();
        assert!(open_with("p1", pw, Some(pass)).is_err());

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
        // The old 1 GiB / 20-pass ceiling is no longer accepted.
        assert!(validate_params(&KdfParams {
            memory_kib: 1_048_576,
            iterations: 3,
            parallelism: 1
        })
        .is_err());
        assert!(validate_params(&KdfParams {
            memory_kib: 262_144,
            iterations: 11,
            parallelism: 1
        })
        .is_err());
        assert!(validate_params(&KdfParams {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 8
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
