//! Key derivation: BIP39 seed -> BIP32 -> BIP84 (native SegWit) or BIP86 (Taproot).
//! Path: m/84'|86'/coin'/0'/chain/index  (coin 0 = mainnet, 1 = testnet;
//! chain 0 = receive, 1 = change). The wallet's address type is stored in the
//! keystore header and authenticated, so it cannot be swapped behind your back.
//!
//! After unlock we keep only a `Watch` (account xpub). The seed is dropped, so the
//! network code never has access to anything that can spend.

use crate::error::Result;

use crate::keystore::{self, AddressType};
use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Address, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf, TxOut, Witness};
use std::str::FromStr;
use zeroize::Zeroizing;

pub fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin {
        0
    } else {
        1
    }
}

pub fn derivation_path(network: Network, kind: AddressType, chain: u32, index: u32) -> String {
    format!(
        "m/{}'/{}'/0'/{chain}/{index}",
        kind.purpose(),
        coin_type(network)
    )
}

/// Strict account-path check shared by every signing path.
///
/// Only `m/84'|86'/coin'/0'/{0,1}/index` is accepted, the coin type must match the
/// wallet's network, and the purpose selects the script type. Anything else is
/// rejected rather than guessed at.
pub fn parse_account_path(
    path: &DerivationPath,
    network: Network,
) -> Result<(AddressType, u32, u32)> {
    let parts: Vec<&ChildNumber> = path.into_iter().collect();
    let (purpose, coin, chain, index) = match parts.as_slice() {
        [ChildNumber::Hardened { index: purpose }, ChildNumber::Hardened { index: coin }, ChildNumber::Hardened { index: 0 }, ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }]
            if *chain <= 1 =>
        {
            (*purpose, *coin, *chain, *index)
        }
        _ => return Err("unexpected derivation path".into()),
    };
    if coin != coin_type(network) {
        return Err("derivation path is for a different network".into());
    }
    let kind = match purpose {
        84 => AddressType::P2wpkh,
        86 => AddressType::P2tr,
        _ => return Err("unsupported derivation purpose".into()),
    };
    Ok((kind, chain, index))
}

/// BIP84-only variant, kept for the legacy P2WPKH paths and their tests.
#[allow(dead_code)] // compatibility/test entry point
pub fn parse_bip84_path(path: &DerivationPath, network: Network) -> Option<(u32, u32)> {
    match parse_account_path(path, network) {
        Ok((AddressType::P2wpkh, chain, index)) => Some((chain, index)),
        _ => None,
    }
}

#[cfg(test)]
fn master(mnemonic: &Mnemonic, network: Network) -> Result<Xpriv> {
    master_with_passphrase(mnemonic, network, "")
}

fn master_with_passphrase(
    mnemonic: &Mnemonic,
    network: Network,
    passphrase: &str,
) -> Result<Xpriv> {
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    Xpriv::new_master(network, seed.as_ref())
        .map_err(|e| e.to_string())
        .map_err(crate::error::Error::from)
}

/// Address from the private key path (used to cross-check the watch-only derivation).
#[cfg(test)]
pub fn address_at(mnemonic: &Mnemonic, network: Network, chain: u32, index: u32) -> Result<String> {
    let secp = Secp256k1::new();
    let master = master(mnemonic, network)?;
    let path =
        DerivationPath::from_str(&derivation_path(network, AddressType::P2wpkh, chain, index))
            .map_err(|e| e.to_string())?;
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| e.to_string())?;
    let pubkey = CompressedPublicKey(child.to_keypair(&secp).public_key());
    Ok(Address::p2wpkh(&pubkey, network).to_string())
}

#[cfg(test)]
pub fn receive_address(mnemonic: &Mnemonic, network: Network, index: u32) -> Result<String> {
    address_at(mnemonic, network, 0, index)
}

/// Public-only wallet view: can derive addresses, cannot spend.
pub struct Watch {
    xpub: Xpub,
    network: Network,
    kind: AddressType,
}

impl Watch {
    #[allow(dead_code)] // compatibility/test entry point
    pub fn from_mnemonic(mnemonic: &Mnemonic, network: Network) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(mnemonic, network, "")
    }

    #[allow(dead_code)] // compatibility/test entry point
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &Mnemonic,
        network: Network,
        passphrase: &str,
    ) -> Result<Self> {
        Self::with_kind(mnemonic, network, passphrase, AddressType::P2wpkh)
    }

    /// Build from an authenticated wallet file. The address type comes from the
    /// keystore header, never from the caller.
    pub fn from_opened(opened: &keystore::Opened) -> Result<Self> {
        Self::with_kind(
            &opened.mnemonic,
            opened.network,
            &opened.passphrase,
            opened.address_type,
        )
    }

    pub fn with_kind(
        mnemonic: &Mnemonic,
        network: Network,
        passphrase: &str,
        kind: AddressType,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let mut master = master_with_passphrase(mnemonic, network, passphrase)?;
        let path =
            DerivationPath::from_str(&format!("m/{}'/{}'/0'", kind.purpose(), coin_type(network)))
                .map_err(|e| e.to_string())?;
        let mut acct = match master.derive_priv(&secp, &path) {
            Ok(acct) => acct,
            Err(e) => {
                master.private_key.non_secure_erase();
                return Err(e.to_string().into());
            }
        };
        let xpub = Xpub::from_priv(&secp, &acct);
        // Only the public key is kept; erase the temporary private keys.
        acct.private_key.non_secure_erase();
        master.private_key.non_secure_erase();
        Ok(Watch {
            xpub,
            network,
            kind,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn kind(&self) -> AddressType {
        self.kind
    }

    /// Address for a public key, in this wallet's script type.
    fn address_for(&self, pk: PublicKey) -> String {
        match self.kind {
            AddressType::P2wpkh => {
                Address::p2wpkh(&CompressedPublicKey(pk), self.network).to_string()
            }
            AddressType::P2tr => Address::p2tr(
                &Secp256k1::new(),
                XOnlyPublicKey::from(pk),
                None,
                self.network,
            )
            .to_string(),
        }
    }

    /// Script for `chain/index`, in this wallet's script type.
    pub fn script_at(&self, chain: u32, index: u32) -> Result<ScriptBuf> {
        let pk = self.pubkey_at(chain, index)?;
        Ok(match self.kind {
            AddressType::P2wpkh => ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash()),
            AddressType::P2tr => {
                ScriptBuf::new_p2tr(&Secp256k1::new(), XOnlyPublicKey::from(pk), None)
            }
        })
    }

    pub fn xpub_string(&self) -> String {
        self.xpub.to_string()
    }

    /// BIP84 descriptor for one chain (`0` receive, `1` change), suitable for
    /// watch-only imports in Bitcoin Core, Sparrow and other wallets.
    pub fn descriptor(&self, chain: u32) -> Result<String> {
        if chain > 1 {
            return Err("chain must be 0 (receive) or 1 (change)".into());
        }
        let fn_name = match self.kind {
            AddressType::P2wpkh => "wpkh",
            AddressType::P2tr => "tr",
        };
        Ok(format!(
            "{fn_name}([{}/{}'/{}'/0']{}/{}/*)",
            self.xpub.fingerprint(),
            self.kind.purpose(),
            coin_type(self.network),
            self.xpub,
            chain
        ))
    }

    /// `count` addresses on `chain`, starting at `start`.
    pub fn addresses(&self, chain: u32, start: u32, count: u32) -> Result<Vec<String>> {
        let secp = Secp256k1::new();
        let e = |x: bitcoin::bip32::Error| x.to_string();
        let chain_key = self
            .xpub
            .ckd_pub(&secp, ChildNumber::from_normal_idx(chain).map_err(e)?)
            .map_err(e)?;
        let end = start.checked_add(count).ok_or("address range overflow")?;
        (start..end)
            .map(|i| -> Result<String> {
                let child = chain_key
                    .ckd_pub(&secp, ChildNumber::from_normal_idx(i).map_err(e)?)
                    .map_err(e)?;
                Ok(self.address_for(child.public_key))
            })
            .collect()
    }

    pub fn address_at(&self, chain: u32, index: u32) -> Result<String> {
        Ok(self.addresses(chain, index, 1)?.remove(0))
    }

    /// Public key for `chain/index`, used to describe our inputs in a PSBT.
    pub fn pubkey_at(&self, chain: u32, index: u32) -> Result<PublicKey> {
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
    kind: AddressType,
}

pub struct Signer {
    inner: Box<SignerInner>,
}

impl Signer {
    /// The only way to obtain signing keys.
    ///
    /// A [`keystore::Opened`] value can only be produced by
    /// [`keystore::open_with`], which verifies the AEAD tag with the password and
    /// re-derives the fingerprint from the decrypted seed. Holding one therefore
    /// means the wallet file was authenticated in this session.
    ///
    /// The network and BIP39 passphrase are taken from that authenticated value
    /// rather than from the caller, so a signer cannot be built for a different
    /// chain, or with a different passphrase, than the one the wallet was
    /// unlocked with.
    pub fn from_opened(opened: &keystore::Opened) -> Result<Self> {
        Self::derive(
            &opened.mnemonic,
            opened.network,
            &opened.passphrase,
            opened.address_type,
        )
    }

    /// Address format this signer derives keys for.
    pub fn kind(&self) -> AddressType {
        self.inner.kind
    }

    /// Test-only: derive directly from a mnemonic. Kept out of the public API so
    /// no non-test code path can sign without unlocking a wallet first.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_mnemonic(mnemonic: &Mnemonic, network: Network) -> Result<Self> {
        Self::derive(mnemonic, network, "", AddressType::P2wpkh)
    }

    /// Test-only counterpart of [`Signer::from_opened`] for passphrase seeds.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_mnemonic_with_passphrase(
        mnemonic: &Mnemonic,
        network: Network,
        passphrase: &str,
    ) -> Result<Self> {
        Self::derive(mnemonic, network, passphrase, AddressType::P2wpkh)
    }

    /// Test-only: derive keys for an explicit address type (BIP84 or BIP86).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_mnemonic_with_kind(
        mnemonic: &Mnemonic,
        network: Network,
        kind: AddressType,
    ) -> Result<Self> {
        Self::derive(mnemonic, network, "", kind)
    }

    fn derive(
        mnemonic: &Mnemonic,
        network: Network,
        passphrase: &str,
        kind: AddressType,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let mut master = master_with_passphrase(mnemonic, network, passphrase)?;
        let path =
            DerivationPath::from_str(&format!("m/{}'/{}'/0'", kind.purpose(), coin_type(network)))
                .map_err(|e| e.to_string())?;
        let account = match master.derive_priv(&secp, &path) {
            Ok(account) => account,
            Err(e) => {
                master.private_key.non_secure_erase();
                return Err(e.to_string().into());
            }
        };
        let inner = Box::new(SignerInner {
            master,
            account,
            network,
            kind,
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

    pub fn account_xpub(&self) -> Result<String> {
        Ok(Xpub::from_priv(&Secp256k1::new(), &self.inner.account).to_string())
    }

    /// Master fingerprint, as used by BIP174 key origins.
    pub fn fingerprint(&self) -> Fingerprint {
        self.inner.master.fingerprint(&Secp256k1::new())
    }

    pub fn key_at(&self, chain: u32, index: u32) -> Result<(SecretKey, PublicKey)> {
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

    /// Derive a key at an absolute path from the wallet master key.
    ///
    /// Used by multisig vaults, whose cosigner keys live at
    /// `m/48'/coin'/0'/2'/chain/index` rather than under the single-sig account.
    pub fn key_at_absolute(&self, path: &DerivationPath) -> Result<(SecretKey, PublicKey)> {
        let secp = Secp256k1::new();
        let mut child = self
            .inner
            .master
            .derive_priv(&secp, path)
            .map_err(|e| e.to_string())?;
        let mut kp = child.to_keypair(&secp);
        let sk = kp.secret_key();
        let pk = kp.public_key();
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
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<()> {
        let secp = Secp256k1::new();
        let tx = psbt.unsigned_tx.clone();
        let master_fp = self.fingerprint();

        // Taproot sighashes commit to every input's value and script, so all the
        // witness UTXOs must be present before anything is signed.
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                input
                    .witness_utxo
                    .clone()
                    .ok_or_else(|| format!("input {i} has no witness UTXO"))
            })
            .collect::<std::result::Result<_, String>>()?;

        // Pass 1: validate every input and record where its key lives. Nothing is
        // signed until the whole PSBT has been checked.
        let mut jobs: Vec<(usize, u32, u32)> = Vec::with_capacity(psbt.inputs.len());
        for (i, input) in psbt.inputs.iter().enumerate() {
            if !input.partial_sigs.is_empty()
                || input.final_script_witness.is_some()
                || input.final_script_sig.is_some()
            {
                return Err(format!("input {i} is already signed").into());
            }
            let utxo = &prevouts[i];
            if utxo.script_pubkey.is_p2tr() {
                let internal = input
                    .tap_internal_key
                    .ok_or_else(|| format!("input {i} has no taproot internal key"))?;
                if input.tap_key_origins.len() != 1 {
                    return Err(
                        format!("input {i} must have exactly one taproot key origin").into(),
                    );
                }
                let (origin_xonly, (_, (fp, path))) = input.tap_key_origins.iter().next().unwrap();
                if *fp != master_fp {
                    return Err(format!(
                        "input {i} belongs to a different wallet (fingerprint mismatch)"
                    )
                    .into());
                }
                let (_, chain, index) = parse_account_path(path, self.inner.network)
                    .map_err(|e| format!("input {i}: {e}"))?;
                let (mut sk, pk) = self.key_at(chain, index)?;
                let xonly = XOnlyPublicKey::from(pk);
                let expected = ScriptBuf::new_p2tr(&secp, xonly, None);
                sk.non_secure_erase();
                if xonly != *origin_xonly || xonly != internal {
                    return Err(format!("input {i}: key does not match this wallet").into());
                }
                if expected != utxo.script_pubkey {
                    return Err(format!("input {i}: key does not match the coin's script").into());
                }
                jobs.push((i, chain, index));
            } else {
                if input.bip32_derivation.len() != 1 {
                    return Err(format!("input {i} must have exactly one BIP32 key origin").into());
                }
                let (origin_pubkey, (fp, path)) = input.bip32_derivation.iter().next().unwrap();
                if *fp != master_fp {
                    return Err(format!(
                        "input {i} belongs to a different wallet (fingerprint mismatch)"
                    )
                    .into());
                }
                let (_, chain, index) = parse_account_path(path, self.inner.network)
                    .map_err(|e| format!("input {i}: {e}"))?;
                if !matches!(input.ecdsa_hash_ty(), Ok(EcdsaSighashType::All)) {
                    return Err(format!("input {i} does not use SIGHASH_ALL").into());
                }
                let (mut sk, pk) = self.key_at(chain, index)?;
                let expected = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
                sk.non_secure_erase();
                if pk != *origin_pubkey {
                    return Err(format!("input {i}: key does not match this wallet").into());
                }
                if expected != utxo.script_pubkey {
                    return Err(format!("input {i}: key does not match the coin's script").into());
                }
                jobs.push((i, chain, index));
            }
            // Validation is complete. Do not keep every input's secret key in
            // memory at once; re-derive it for the signing pass below.
        }

        // Pass 2: sign.
        let mut cache = SighashCache::new(&tx);
        for (i, chain, index) in jobs {
            let (mut sk, _) = self.key_at(chain, index)?;
            if prevouts[i].script_pubkey.is_p2tr() {
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| e.to_string())?;
                let keypair = Keypair::from_secret_key(&secp, &sk);
                sk.non_secure_erase();
                // Deterministic nonces: no extra randomness is needed or used.
                let sig = secp.sign_schnorr_no_aux_rand(
                    &Message::from_digest(sighash.to_byte_array()),
                    &keypair,
                );
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                let input = &mut psbt.inputs[i];
                input.final_script_witness = Some(witness);
                input.partial_sigs.clear();
            } else {
                let sighash = cache
                    .p2wpkh_signature_hash(
                        i,
                        &prevouts[i].script_pubkey,
                        prevouts[i].value,
                        EcdsaSighashType::All,
                    )
                    .map_err(|e| e.to_string())?;
                let sig = secp.sign_ecdsa(&Message::from(sighash), &sk);
                let pk = self.key_at(chain, index)?.1;
                sk.non_secure_erase();
                let signature = bitcoin::ecdsa::Signature {
                    signature: sig,
                    sighash_type: EcdsaSighashType::All,
                };
                let input = &mut psbt.inputs[i];
                input.final_script_witness = Some(Witness::p2wpkh(&signature, &pk));
                input.partial_sigs.clear();
            }
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
    fn bip86_official_vector_first_address() {
        // From the BIP86 spec: mainnet m/86'/0'/0'/0/0 for the "abandon ... about" seed.
        let m = Mnemonic::parse(ABANDON).unwrap();
        let w = Watch::with_kind(&m, Network::Bitcoin, "", AddressType::P2tr).unwrap();
        assert_eq!(
            w.address_at(0, 0).unwrap(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        let d = w.descriptor(0).unwrap();
        assert!(d.starts_with("tr(["));
        assert!(d.contains("/86'/0'/0']"));
        assert!(d.ends_with("/0/*)"));

        // The BIP84 wallet for the same seed is a different wallet entirely.
        let legacy = Watch::from_mnemonic(&m, Network::Bitcoin).unwrap();
        assert_ne!(
            legacy.address_at(0, 0).unwrap(),
            w.address_at(0, 0).unwrap()
        );

        let t = Watch::with_kind(&m, Network::Testnet, "", AddressType::P2tr).unwrap();
        assert!(t.address_at(0, 0).unwrap().starts_with("tb1p"));
        assert_eq!(t.kind(), AddressType::P2tr);
    }

    #[test]
    fn account_paths_select_the_script_type() {
        let legacy: DerivationPath = "m/84'/0'/0'/0/3".parse().unwrap();
        let taproot: DerivationPath = "m/86'/0'/0'/1/4".parse().unwrap();
        assert_eq!(
            parse_account_path(&legacy, Network::Bitcoin),
            Ok((AddressType::P2wpkh, 0, 3))
        );
        assert_eq!(
            parse_account_path(&taproot, Network::Bitcoin),
            Ok((AddressType::P2tr, 1, 4))
        );
        // Wrong network, wrong purpose, or a stray hardened index is refused.
        assert!(parse_account_path(&taproot, Network::Testnet).is_err());
        let wrong: DerivationPath = "m/44'/0'/0'/0/0".parse().unwrap();
        assert!(parse_account_path(&wrong, Network::Bitcoin).is_err());
        let hardened: DerivationPath = "m/86'/0'/0'/0'/0".parse().unwrap();
        assert!(parse_account_path(&hardened, Network::Bitcoin).is_err());
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
    fn passphrase_changes_derivation_and_descriptors_are_well_formed() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let plain = Watch::from_mnemonic(&m, Network::Bitcoin).unwrap();
        let with_pass =
            Watch::from_mnemonic_with_passphrase(&m, Network::Bitcoin, "correct horse").unwrap();
        assert_ne!(
            plain.address_at(0, 0).unwrap(),
            with_pass.address_at(0, 0).unwrap()
        );

        let d = plain.descriptor(0).unwrap();
        assert!(d.starts_with("wpkh(["));
        assert!(d.contains("/84'/0'/0']"));
        assert!(d.ends_with("/0/*)"));
        let c = plain.descriptor(1).unwrap();
        assert!(c.ends_with("/1/*)"));
        assert!(plain.descriptor(2).is_err());

        let t = Watch::from_mnemonic(&m, Network::Testnet).unwrap();
        assert!(t.descriptor(0).unwrap().contains("/84'/1'/0']"));
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
    fn signer_from_opened_uses_the_unlocked_passphrase_and_network() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let opened = keystore::Opened {
            mnemonic: Box::new(m.clone()),
            passphrase: Zeroizing::new("correct horse".to_string()),
            fingerprint: "73c5da0a".into(),
            network: Network::Testnet,
            address_type: AddressType::P2wpkh,
        };
        let signer = Signer::from_opened(&opened).unwrap();
        let expected =
            Signer::from_mnemonic_with_passphrase(&m, Network::Testnet, "correct horse").unwrap();
        assert_eq!(
            signer.account_xpub().unwrap(),
            expected.account_xpub().unwrap()
        );
        assert_eq!(signer.network(), Network::Testnet);

        // Deriving with an empty passphrase must not match: the passphrase comes
        // from the opened wallet, never from the caller.
        let plain = Signer::from_mnemonic(&m, Network::Testnet).unwrap();
        assert_ne!(
            signer.account_xpub().unwrap(),
            plain.account_xpub().unwrap()
        );
    }

    #[test]
    fn invalid_mnemonic_checksum_rejected() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Mnemonic::parse(bad).is_err());
    }
}
