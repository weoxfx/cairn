//! Key derivation: BIP39 seed -> BIP32 -> BIP84 (native SegWit, bech32 addresses).
//! Path: m/84'/coin'/0'/chain/index   (coin 0 = mainnet, 1 = testnet; chain 0 = receive, 1 = change)
//!
//! After unlock we keep only a `Watch` (account xpub). The seed is dropped, so the
//! network code never has access to anything that can spend.

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{Address, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf, Witness};
use std::str::FromStr;
use zeroize::Zeroizing;

pub fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin {
        0
    } else {
        1
    }
}

pub fn derivation_path(network: Network, chain: u32, index: u32) -> String {
    format!("m/84'/{}'/0'/{chain}/{index}", coin_type(network))
}

/// Strict BIP84 path check used by both signing paths.
pub fn parse_bip84_path(path: &DerivationPath, network: Network) -> Option<(u32, u32)> {
    let parts: Vec<&ChildNumber> = path.into_iter().collect();
    match parts.as_slice() {
        [ChildNumber::Hardened { index: 84 }, ChildNumber::Hardened { index: coin }, ChildNumber::Hardened { index: 0 }, ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }]
            if *coin == coin_type(network) && *chain <= 1 =>
        {
            Some((*chain, *index))
        }
        _ => None,
    }
}

fn master(mnemonic: &Mnemonic, network: Network) -> Result<Xpriv, String> {
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    Xpriv::new_master(network, seed.as_ref()).map_err(|e| e.to_string())
}

/// Address from the private key path (used to cross-check the watch-only derivation).
#[cfg(test)]
pub fn address_at(
    mnemonic: &Mnemonic,
    network: Network,
    chain: u32,
    index: u32,
) -> Result<String, String> {
    let secp = Secp256k1::new();
    let master = master(mnemonic, network)?;
    let path = DerivationPath::from_str(&derivation_path(network, chain, index))
        .map_err(|e| e.to_string())?;
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| e.to_string())?;
    let pubkey = CompressedPublicKey(child.to_keypair(&secp).public_key());
    Ok(Address::p2wpkh(&pubkey, network).to_string())
}

#[cfg(test)]
pub fn receive_address(
    mnemonic: &Mnemonic,
    network: Network,
    index: u32,
) -> Result<String, String> {
    address_at(mnemonic, network, 0, index)
}

/// Public-only wallet view: can derive addresses, cannot spend.
pub struct Watch {
    xpub: Xpub,
    network: Network,
}

impl Watch {
    pub fn from_mnemonic(mnemonic: &Mnemonic, network: Network) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let mut master = master(mnemonic, network)?;
        let path = DerivationPath::from_str(&format!("m/84'/{}'/0'", coin_type(network)))
            .map_err(|e| e.to_string())?;
        let mut acct = match master.derive_priv(&secp, &path) {
            Ok(acct) => acct,
            Err(e) => {
                master.private_key.non_secure_erase();
                return Err(e.to_string());
            }
        };
        let xpub = Xpub::from_priv(&secp, &acct);
        // Only the public key is kept; erase the temporary private keys.
        acct.private_key.non_secure_erase();
        master.private_key.non_secure_erase();
        Ok(Watch { xpub, network })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn xpub_string(&self) -> String {
        self.xpub.to_string()
    }

    /// `count` addresses on `chain`, starting at `start`.
    pub fn addresses(&self, chain: u32, start: u32, count: u32) -> Result<Vec<String>, String> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let chain_key = self
            .xpub
            .ckd_pub(&secp, ChildNumber::from_normal_idx(chain).map_err(e)?)
            .map_err(e)?;
        let end = start.checked_add(count).ok_or("address range overflow")?;
        (start..end)
            .map(|i| -> Result<String, String> {
                let child = chain_key
                    .ckd_pub(&secp, ChildNumber::from_normal_idx(i).map_err(e)?)
                    .map_err(e)?;
                let pk = CompressedPublicKey(child.public_key);
                Ok(Address::p2wpkh(&pk, self.network).to_string())
            })
            .collect()
    }

    pub fn address_at(&self, chain: u32, index: u32) -> Result<String, String> {
        Ok(self.addresses(chain, index, 1)?.remove(0))
    }

    /// Public key for `chain/index`, used to describe our inputs in a PSBT.
    pub fn pubkey_at(&self, chain: u32, index: u32) -> Result<PublicKey, String> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let chain_key = self
            .xpub
            .ckd_pub(&secp, ChildNumber::from_normal_idx(chain).map_err(e)?)
            .map_err(e)?;
        let child = chain_key
            .ckd_pub(&secp, ChildNumber::from_normal_idx(index).map_err(e)?)
            .map_err(e)?;
        Ok(child.public_key)
    }
}

/// Spending keys. Only created briefly when sending or signing an offline PSBT.
///
/// The master key is kept for the life of the signer so BIP174 full derivation
/// paths can be resolved. The account key is kept for normal address
/// derivation so no extra secret copies are made per call. The heap allocation
/// is locked with `mlock` when the OS allows it, and `Drop` erases both keys
/// (best effort).
struct SignerInner {
    master: Xpriv,
    account: Xpriv,
    network: Network,
}

pub struct Signer {
    inner: Box<SignerInner>,
}

impl Signer {
    pub fn from_mnemonic(mnemonic: &Mnemonic, network: Network) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let mut master = master(mnemonic, network)?;
        let path = DerivationPath::from_str(&format!("m/84'/{}'/0'", coin_type(network)))
            .map_err(|e| e.to_string())?;
        let account = match master.derive_priv(&secp, &path) {
            Ok(account) => account,
            Err(e) => {
                master.private_key.non_secure_erase();
                return Err(e.to_string());
            }
        };
        let inner = Box::new(SignerInner {
            master,
            account,
            network,
        });
        // Best effort: keep the key material out of swap. If the OS refuses
        // (for example a low RLIMIT_MEMLOCK), signing still proceeds.
        crate::hardening::lock_memory(
            inner.as_ref() as *const SignerInner as *const u8,
            std::mem::size_of::<SignerInner>(),
        );
        Ok(Signer { inner })
    }

    pub fn network(&self) -> Network {
        self.inner.network
    }

    pub fn account_xpub(&self) -> Result<String, String> {
        Ok(Xpub::from_priv(&Secp256k1::new(), &self.inner.account).to_string())
    }

    /// Master fingerprint, as used by BIP174 key origins.
    pub fn fingerprint(&self) -> Fingerprint {
        self.inner.master.fingerprint(&Secp256k1::new())
    }

    pub fn key_at(&self, chain: u32, index: u32) -> Result<(SecretKey, PublicKey), String> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let path = [
            ChildNumber::from_normal_idx(chain).map_err(e)?,
            ChildNumber::from_normal_idx(index).map_err(e)?,
        ];
        let mut child = self.inner.account.derive_priv(&secp, &path).map_err(e)?;
        let mut kp = child.to_keypair(&secp);
        let sk = kp.secret_key();
        let pk = kp.public_key();
        // Best effort: drop intermediate secret copies as soon as possible.
        kp.non_secure_erase();
        child.private_key.non_secure_erase();
        Ok((sk, pk))
    }

    /// Sign every P2WPKH input of `psbt` and finalize it for broadcasting.
    ///
    /// This deliberately does not use `Psbt::sign` followed by "pick the first
    /// partial signature": each input is validated against exactly one BIP84 key
    /// origin, the expected script and SIGHASH_ALL before a signature is made.
    /// Keys are found through the BIP174 `bip32_derivation` key origins.
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<(), String> {
        let secp = Secp256k1::new();
        let tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        let master_fp = self.fingerprint();
        let mut jobs = Vec::with_capacity(psbt.inputs.len());

        for (i, input) in psbt.inputs.iter().enumerate() {
            if !input.partial_sigs.is_empty()
                || input.final_script_witness.is_some()
                || input.final_script_sig.is_some()
            {
                return Err(format!("input {i} is already signed"));
            }
            if input.bip32_derivation.len() != 1 {
                return Err(format!("input {i} must have exactly one BIP32 key origin"));
            }
            let (origin_pubkey, (fp, path)) = input.bip32_derivation.iter().next().unwrap();
            if *fp != master_fp {
                return Err(format!(
                    "input {i} belongs to a different wallet (fingerprint mismatch)"
                ));
            }
            let (chain, index) = parse_bip84_path(path, self.inner.network)
                .ok_or_else(|| format!("input {i} has an unexpected derivation path"))?;
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| format!("input {i} has no witness UTXO"))?;
            if !matches!(input.ecdsa_hash_ty(), Ok(EcdsaSighashType::All)) {
                return Err(format!("input {i} does not use SIGHASH_ALL"));
            }
            let sighash = cache
                .p2wpkh_signature_hash(i, &utxo.script_pubkey, utxo.value, EcdsaSighashType::All)
                .map_err(|e| e.to_string())?;
            let (mut sk, pk) = self.key_at(chain, index)?;
            if pk != *origin_pubkey {
                sk.non_secure_erase();
                return Err(format!("input {i}: key does not match this wallet"));
            }
            let expected = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
            if expected != utxo.script_pubkey {
                sk.non_secure_erase();
                return Err(format!("input {i}: key does not match the coin's script"));
            }
            // Validation is complete. Do not keep every input's secret key in
            // memory at once; re-derive it for the signing pass below.
            sk.non_secure_erase();
            jobs.push((i, chain, index, pk, sighash));
        }

        for (i, chain, index, pk, sighash) in jobs {
            let (mut sk, derived_pk) = self.key_at(chain, index)?;
            if derived_pk != pk {
                sk.non_secure_erase();
                return Err(format!("input {i}: key derivation changed unexpectedly"));
            }
            let sig = secp.sign_ecdsa(&Message::from(sighash), &sk);
            sk.non_secure_erase();
            let signature = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            let input = &mut psbt.inputs[i];
            input.final_script_witness = Some(Witness::p2wpkh(&signature, &pk));
            input.partial_sigs.clear();
        }
        Ok(())
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        // Best-effort erase (the secp256k1 type has no automatic zeroize).
        self.inner.master.private_key.non_secure_erase();
        self.inner.account.private_key.non_secure_erase();
        crate::hardening::unlock_memory(
            self.inner.as_ref() as *const SignerInner as *const u8,
            std::mem::size_of::<SignerInner>(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bip39_zero_entropy_vector() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(m.to_string(), ABANDON);
        let m24 = Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        assert!(m24.to_string().ends_with("abandon art"));
    }

    #[test]
    fn bip84_official_vector_first_address() {
        // From the BIP84 spec: mainnet m/84'/0'/0'/0/0 for the "abandon ... about" seed.
        let m = Mnemonic::parse(ABANDON).unwrap();
        assert_eq!(
            receive_address(&m, Network::Bitcoin, 0).unwrap(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    #[test]
    fn watch_only_matches_private_derivation() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        for net in [Network::Bitcoin, Network::Testnet] {
            let w = Watch::from_mnemonic(&m, net).unwrap();
            for chain in 0..2 {
                for idx in 0..4 {
                    assert_eq!(
                        w.address_at(chain, idx).unwrap(),
                        address_at(&m, net, chain, idx).unwrap()
                    );
                }
            }
        }
        let w = Watch::from_mnemonic(&m, Network::Bitcoin).unwrap();
        assert_eq!(
            w.address_at(0, 0).unwrap(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    #[test]
    fn testnet_addresses_are_tb1_and_distinct() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let w = Watch::from_mnemonic(&m, Network::Testnet).unwrap();
        let a0 = w.address_at(0, 0).unwrap();
        assert!(a0.starts_with("tb1q"));
        assert_ne!(a0, w.address_at(0, 1).unwrap());
        assert_ne!(a0, w.address_at(1, 0).unwrap());
        assert!(w.xpub_string().starts_with("tpub"));
    }

    #[test]
    fn strict_bip84_paths_are_network_aware() {
        let test: DerivationPath = "m/84'/1'/0'/0/7".parse().unwrap();
        let main: DerivationPath = "m/84'/0'/0'/1/9".parse().unwrap();
        assert_eq!(parse_bip84_path(&test, Network::Testnet), Some((0, 7)));
        assert_eq!(parse_bip84_path(&main, Network::Bitcoin), Some((1, 9)));
        assert_eq!(parse_bip84_path(&main, Network::Testnet), None);
        assert_eq!(parse_bip84_path(&test, Network::Bitcoin), None);
        let wrong: DerivationPath = "m/44'/1'/0'/0/7".parse().unwrap();
        assert_eq!(parse_bip84_path(&wrong, Network::Testnet), None);
    }

    #[test]
    fn invalid_mnemonic_checksum_rejected() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Mnemonic::parse(bad).is_err());
    }
}
