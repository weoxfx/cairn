//! BIP44/BIP32 derivation for EVM accounts and EIP-55 address encoding.
//!
//! Path: `m/44'/60'/0'/0/index` (BIP44 coin type 60, account 0, external
//! chain, address index). The seed shape is the same one the Bitcoin side
//! uses, so one Cairn mnemonic gives a Bitcoin wallet and an EVM account.
//!
//! As with the Bitcoin wallet, after unlocking only the account xpub is kept:
//! the watch view derives addresses, the signer is built separately and erased.

use crate::hardening;
use crate::keystore;
use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use sha3::{Digest, Keccak256};
use std::str::FromStr;
use zeroize::Zeroizing;

pub const COIN_TYPE: u32 = 60;
pub const ACCOUNT_PATH: &str = "m/44'/60'/0'";
/// External chain index; Ethereum has no change addresses.
pub const EXTERNAL_CHAIN: u32 = 0;

pub fn derivation_path(index: u32) -> String {
    format!("m/44'/{COIN_TYPE}'/0'/{EXTERNAL_CHAIN}/{index}")
}

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// `keccak256(uncompressed_pubkey[1..])[12..]`.
pub fn address_from_public_key(pk: &bitcoin::secp256k1::PublicKey) -> [u8; 20] {
    let ser = pk.serialize_uncompressed();
    let h = keccak(&ser[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

/// EIP-55 mixed-case checksum.
pub fn checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = keccak(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse a 20-byte address. A mixed-case value must match its EIP-55
/// checksum; all-lowercase and all-uppercase hex are accepted as unchecksummed
/// input, which is what every wallet and block explorer emits for pastes.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.trim();
    let hexpart = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hexpart.len() != 40 {
        return Err(format!(
            "address must be 40 hex characters (got {})",
            hexpart.len()
        ));
    }
    if !hexpart.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("address contains a non-hex character".into());
    }
    let bytes = hex::decode(hexpart).map_err(|_| "invalid address hex".to_string())?;
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes);
    let has_lower = hexpart.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = hexpart.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        let expected = checksum(&a);
        if &expected[2..] != hexpart {
            return Err("address checksum does not match (EIP-55)".into());
        }
    }
    Ok(a)
}

pub fn is_zero(addr: &[u8; 20]) -> bool {
    addr.iter().all(|b| *b == 0)
}

pub fn short(addr: &str) -> String {
    if addr.len() <= 12 {
        return addr.to_string();
    }
    format!("{}…{}", &addr[..8], &addr[addr.len() - 6..])
}

/// Watch-only EVM account: derives public addresses, cannot sign.
pub struct EvmWatch {
    xpub: Xpub,
}

impl EvmWatch {
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &Mnemonic,
        passphrase: &str,
    ) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
        let mut master =
            Xpriv::new_master(Network::Bitcoin, seed.as_ref()).map_err(|e| e.to_string())?;
        let path = DerivationPath::from_str(ACCOUNT_PATH).map_err(|e| e.to_string())?;
        let account = master
            .derive_priv(&secp, &path)
            .map_err(|e| e.to_string())?;
        let xpub = Xpub::from_priv(&secp, &account);
        master.private_key.non_secure_erase();
        Ok(EvmWatch { xpub })
    }

    pub fn from_opened(opened: &keystore::Opened) -> Result<Self, String> {
        Self::from_mnemonic_with_passphrase(&opened.mnemonic, &opened.passphrase)
    }

    pub fn xpub_string(&self) -> String {
        self.xpub.to_string()
    }

    pub fn address_at(&self, index: u32) -> Result<[u8; 20], String> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let chain = self
            .xpub
            .ckd_pub(
                &secp,
                ChildNumber::from_normal_idx(EXTERNAL_CHAIN).map_err(e)?,
            )
            .map_err(e)?;
        let child = chain
            .ckd_pub(&secp, ChildNumber::from_normal_idx(index).map_err(e)?)
            .map_err(e)?;
        Ok(address_from_public_key(&child.public_key))
    }

    pub fn address_string(&self, index: u32) -> Result<String, String> {
        Ok(checksum(&self.address_at(index)?))
    }
}

struct SignerInner {
    master: Xpriv,
    account: Xpriv,
}

/// Spending keys, unlocked only for an EVM send or a signature.
pub struct EvmSigner {
    inner: Box<SignerInner>,
}

impl EvmSigner {
    /// The only way to obtain EVM signing keys: from an authenticated keystore
    /// value, so the passphrase is the one the wallet was unlocked with.
    pub fn from_opened(opened: &keystore::Opened) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let seed = Zeroizing::new(opened.mnemonic.to_seed(opened.passphrase.as_str()));
        let mut master =
            Xpriv::new_master(Network::Bitcoin, seed.as_ref()).map_err(|e| e.to_string())?;
        let path = DerivationPath::from_str(ACCOUNT_PATH).map_err(|e| e.to_string())?;
        let account = match master.derive_priv(&secp, &path) {
            Ok(a) => a,
            Err(e) => {
                master.private_key.non_secure_erase();
                return Err(e.to_string());
            }
        };
        let inner = Box::new(SignerInner { master, account });
        hardening::lock_memory(
            inner.as_ref() as *const SignerInner as *const u8,
            std::mem::size_of::<SignerInner>(),
        );
        Ok(EvmSigner { inner })
    }

    pub fn key_at(&self, index: u32) -> Result<SecretKey, String> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let path = [
            ChildNumber::from_normal_idx(EXTERNAL_CHAIN).map_err(e)?,
            ChildNumber::from_normal_idx(index).map_err(e)?,
        ];
        let mut child = self.inner.account.derive_priv(&secp, &path).map_err(e)?;
        let key =
            SecretKey::from_slice(&child.private_key.secret_bytes()).map_err(|e| e.to_string());
        child.private_key.non_secure_erase();
        key
    }

    pub fn address_at(&self, index: u32) -> Result<[u8; 20], String> {
        let key = self.key_at(index)?;
        Ok(address_from_public_key(&key.public_key(&Secp256k1::new())))
    }
}

impl Drop for EvmSigner {
    fn drop(&mut self) {
        self.inner.master.private_key.non_secure_erase();
        self.inner.account.private_key.non_secure_erase();
        hardening::unlock_memory(
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
    fn bip44_vector_first_account() {
        // Widely published BIP44 first address for the all-zero-entropy mnemonic.
        let m = Mnemonic::parse(ABANDON).unwrap();
        let w = EvmWatch::from_mnemonic_with_passphrase(&m, "").unwrap();
        assert_eq!(
            w.address_string(0).unwrap(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_ne!(w.address_at(0).unwrap(), w.address_at(1).unwrap());
    }

    #[test]
    fn watch_and_signer_agree() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let opened = keystore::Opened {
            mnemonic: Box::new(m),
            passphrase: Zeroizing::new(String::new()),
            fingerprint: "73c5da0a".into(),
            network: bitcoin::Network::Bitcoin,
        };
        let watch = EvmWatch::from_opened(&opened).unwrap();
        let signer = EvmSigner::from_opened(&opened).unwrap();
        for i in 0..4 {
            assert_eq!(watch.address_at(i).unwrap(), signer.address_at(i).unwrap());
        }
    }

    #[test]
    fn eip55_checksums_match_the_spec() {
        for s in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let a = parse_address(s).unwrap();
            assert_eq!(checksum(&a), s);
        }
    }

    #[test]
    fn bad_checksum_and_bad_length_are_rejected() {
        // Correct length, wrong case pattern.
        assert!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").is_err());
        assert!(parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda9").is_err());
        assert!(parse_address("0xZZ58effd232b4033e47d90003d41ec34ecaeda94").is_err());
        // Lowercase form is accepted as unchecksummed input.
        assert!(parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").is_ok());
    }

    #[test]
    fn path_and_short_form() {
        assert_eq!(derivation_path(0), "m/44'/60'/0'/0/0");
        assert_eq!(
            short("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            "0x9858Ef…aEda94"
        );
    }
}
