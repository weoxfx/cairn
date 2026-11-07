//! Key derivation: BIP39 seed -> BIP32 -> BIP84 (native SegWit, bech32 addresses).
//! Path: m/84'/coin'/0'/chain/index   (coin 0 = mainnet, 1 = testnet; chain 0 = receive, 1 = change)
//!
//! After unlock we keep only a `Watch` (account xpub). The seed is dropped, so the
//! network code never has access to anything that can spend.

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, Witness};
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
        let master = master(mnemonic, network)?;
        let path = DerivationPath::from_str(&format!("m/84'/{}'/0'", coin_type(network)))
            .map_err(|e| e.to_string())?;
        let acct = master
            .derive_priv(&secp, &path)
            .map_err(|e| e.to_string())?;
        Ok(Watch {
            xpub: Xpub::from_priv(&secp, &acct),
            network,
        })
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
        (start..start + count)
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
/// derivation so no extra secret copies are made per call. `Drop` erases both
/// (best effort).
pub struct Signer {
    master: Xpriv,
    account: Xpriv,
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
        Ok(Signer { master, account })
    }

    pub fn account_xpub(&self) -> Result<String, String> {
        Ok(Xpub::from_priv(&Secp256k1::new(), &self.account).to_string())
    }

    /// Master fingerprint, as used by BIP174 key origins.
    pub fn fingerprint(&self) -> Fingerprint {
        self.master.fingerprint(&Secp256k1::new())
    }

    pub fn key_at(&self, chain: u32, index: u32) -> Result<(SecretKey, PublicKey), String> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let path = [
            ChildNumber::from_normal_idx(chain).map_err(e)?,
            ChildNumber::from_normal_idx(index).map_err(e)?,
        ];
        let child = self.account.derive_priv(&secp, &path).map_err(e)?;
        let kp = child.to_keypair(&secp);
        Ok((kp.secret_key(), kp.public_key()))
    }

    /// Sign every P2WPKH input of `psbt` and finalize it for broadcasting.
    /// Keys are found through the BIP174 `bip32_derivation` key origins.
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<(), String> {
        let secp = Secp256k1::new();
        match psbt.sign(&self.master, &secp) {
            Ok(_) => {}
            Err((_used, errors)) => {
                return Err(format!(
                    "could not sign {} input(s); first error: {:?}",
                    errors.len(),
                    errors.values().next()
                ));
            }
        }
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            let (pk, sig) = input
                .partial_sigs
                .iter()
                .next()
                .map(|(k, v)| (*k, *v))
                .ok_or_else(|| format!("input {i} was not signed"))?;
            input.final_script_witness = Some(Witness::p2wpkh(&sig, &pk.inner));
            input.partial_sigs.clear();
        }
        Ok(())
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        // Best-effort erase (the secp256k1 type has no automatic zeroize).
        self.master.private_key.non_secure_erase();
        self.account.private_key.non_secure_erase();
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
    fn invalid_mnemonic_checksum_rejected() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Mnemonic::parse(bad).is_err());
    }
}
