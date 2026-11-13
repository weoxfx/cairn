//! n-of-m P2WSH multisig vaults, coordinated with PSBT files.
//!
//! A vault is public data only: the cosigner xpubs, their origin paths and the
//! threshold, kept at `~/.cairn/multisig/<name>.json`. Spending is deliberately a
//! sequence of files, so no single machine ever needs more than one key:
//!
//! ```text
//! cairn multisig psbt --name V --to ADDR --amount 0.01   (any machine)
//! cairn multisig sign --name V --psbt unsigned.psbt      (cosigner A)
//! cairn multisig sign --name V --psbt unsigned.psbt      (cosigner B)
//! cairn multisig combine a.psbt b.psbt --out signed.psbt
//! cairn multisig finalize --psbt signed.psbt --broadcast
//! ```
//!
//! The witness script is a plain `OP_m <key…> OP_n OP_CHECKMULTISIG` with the
//! cosigner keys sorted (BIP67), so the address does not depend on the order the
//! xpubs were entered in. Every signature is checked against the BIP143 sighash
//! before it is produced, and again before a transaction is finalized.

use crate::chain;
use crate::esplora::{self, Utxo};
use crate::hardening;
use crate::keystore;
use crate::network;
use crate::send;
use crate::ui::{banner, fmt_btc, hint, kv, ok, pause, section, spin, table, warn};
use crate::wallet::{self, Signer};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_16};
use bitcoin::psbt::Psbt;
use bitcoin::script::{Builder, Instruction};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use console::style;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use zeroize::Zeroizing;

/// Most cosigners a standard P2WSH multisig can hold.
const MAX_COSIGNERS: u32 = 15;
/// Addresses scanned per chain when looking for the vault's coins.
const GAP: u32 = 25;
/// Hard ceiling for a PSBT file, matching the offline signer's bound.
const MAX_PSBT_BYTES: u64 = 5_000_000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Cosigner {
    pub label: String,
    pub fingerprint: String,
    pub xpub: String,
    /// Origin of the xpub, e.g. `m/48'/0'/0'/2'`.
    pub path: String,
}

impl Cosigner {
    fn xpub(&self) -> Result<Xpub, String> {
        Xpub::from_str(&self.xpub).map_err(|e| format!("invalid cosigner xpub: {e}"))
    }

    fn origin(&self) -> Result<DerivationPath, String> {
        DerivationPath::from_str(&self.path).map_err(|e| format!("invalid cosigner path: {e}"))
    }

    fn fingerprint(&self) -> Result<Fingerprint, String> {
        Fingerprint::from_str(&self.fingerprint).map_err(|_| "invalid cosigner fingerprint".into())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub version: u32,
    pub name: String,
    pub network: String,
    pub threshold: u32,
    pub cosigners: Vec<Cosigner>,
    pub created: u64,
}

fn network_id(network: Network) -> &'static str {
    if network == Network::Bitcoin {
        "mainnet"
    } else {
        "testnet"
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        _ => Err("vault has an unsupported network".into()),
    }
}

impl Vault {
    pub fn new(name: &str, network: Network, threshold: u32, cosigners: Vec<Cosigner>) -> Self {
        Vault {
            version: 1,
            name: name.to_string(),
            network: network_id(network).to_string(),
            threshold,
            cosigners,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    pub fn network(&self) -> Result<Network, String> {
        parse_network(&self.network)
    }

    fn check(&self) -> Result<(), String> {
        let m = self.cosigners.len() as u32;
        if !(2..=MAX_COSIGNERS).contains(&m) {
            return Err(format!("a vault needs 2 to {MAX_COSIGNERS} cosigners"));
        }
        if self.threshold < 1 || self.threshold > m {
            return Err(format!("threshold must be between 1 and {m}"));
        }
        for c in &self.cosigners {
            let _ = c.xpub()?;
            let _ = c.origin()?;
            let _ = c.fingerprint()?;
        }
        let _ = self.network()?;
        Ok(())
    }

    /// Sorted cosigner keys for one address (BIP67).
    pub fn pubkeys_at(&self, chain: u32, index: u32) -> Result<Vec<PublicKey>, String> {
        self.check()?;
        let secp = Secp256k1::new();
        let step = [
            ChildNumber::from_normal_idx(chain).map_err(|e| e.to_string())?,
            ChildNumber::from_normal_idx(index).map_err(|e| e.to_string())?,
        ];
        let mut keys = Vec::with_capacity(self.cosigners.len());
        for c in &self.cosigners {
            let child = c
                .xpub()?
                .ckd_pub(&secp, step[0])
                .and_then(|k| k.ckd_pub(&secp, step[1]));
            keys.push(PublicKey::new(child.map_err(|e| e.to_string())?.public_key));
        }
        keys.sort_by_key(|k| k.to_bytes());
        Ok(keys)
    }

    pub fn witness_script(&self, chain: u32, index: u32) -> Result<ScriptBuf, String> {
        let keys = self.pubkeys_at(chain, index)?;
        Ok(multisig_script(self.threshold, &keys))
    }

    pub fn address(&self, chain: u32, index: u32) -> Result<Address, String> {
        Ok(Address::p2wsh(
            &self.witness_script(chain, index)?,
            self.network()?,
        ))
    }

    /// Wallet-importable descriptor for the whole vault.
    pub fn descriptor(&self) -> Result<String, String> {
        self.check()?;
        let parts: Vec<String> = self
            .cosigners
            .iter()
            .map(|c| {
                let path = c.path.trim_start_matches('m');
                format!("[{}{}]{}", c.fingerprint, path, c.xpub)
            })
            .collect();
        Ok(format!(
            "wsh(sortedmulti({},{}))",
            self.threshold,
            parts.join(",")
        ))
    }

    /// Stable short identifier derived from the descriptor, so two machines can
    /// confirm they are looking at the same vault.
    pub fn id(&self) -> Result<String, String> {
        let d = self.descriptor()?;
        Ok(bitcoin::hashes::sha256::Hash::hash(d.as_bytes()).to_string()[..16].to_string())
    }

    fn has_fingerprint(&self, fp: &str) -> bool {
        self.cosigners.iter().any(|c| c.fingerprint == fp)
    }
}

/// `OP_m <key…> OP_n OP_CHECKMULTISIG`.
pub fn multisig_script(threshold: u32, keys: &[PublicKey]) -> ScriptBuf {
    let mut b = Builder::new().push_int(threshold as i64);
    for k in keys {
        b = b.push_key(k);
    }
    b.push_int(keys.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

/// Read back a multisig witness script. Refuses anything that is not exactly
/// `OP_m <key…> OP_n OP_CHECKMULTISIG` with a coherent key count.
pub fn parse_multisig(script: &bitcoin::Script) -> Result<(u32, Vec<PublicKey>), String> {
    let items: Vec<Instruction> = script
        .instructions()
        .map(|i| i.map_err(|e| format!("malformed witness script: {e}")))
        .collect::<Result<_, String>>()?;
    if items.last() != Some(&Instruction::Op(OP_CHECKMULTISIG)) {
        return Err("witness script does not end with OP_CHECKMULTISIG".into());
    }
    let mut numbers: Vec<u32> = vec![];
    let mut keys: Vec<PublicKey> = vec![];
    for item in &items[..items.len() - 1] {
        match item {
            Instruction::PushBytes(bytes) => {
                if bytes.len() != 33 {
                    return Err("witness script contains a non-key push".into());
                }
                keys.push(
                    PublicKey::from_slice(bytes.as_bytes())
                        .map_err(|_| "witness script contains an invalid key".to_string())?,
                );
            }
            Instruction::Op(op) => {
                let byte = op.to_u8();
                if (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&byte) {
                    numbers.push(u32::from(byte - OP_PUSHNUM_1.to_u8()) + 1);
                } else {
                    return Err("witness script is not a plain multisig".into());
                }
            }
        }
    }
    let (threshold, total) = match numbers[..] {
        [t, n] => (t, n),
        _ => return Err("witness script is missing its threshold or key count".into()),
    };
    if total as usize != keys.len() || threshold == 0 || threshold > total {
        return Err("witness script has an inconsistent multisig header".into());
    }
    Ok((threshold, keys))
}

// ---------------- vault files ----------------

fn dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let base = PathBuf::from(home).join(".cairn").join("multisig");
    hardening::ensure_private_dir(&base)?;
    Ok(base)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn vault_path(name: &str) -> Result<PathBuf, String> {
    if !valid_name(name) {
        return Err("vault names may use letters, digits, - and _ only".into());
    }
    Ok(dir()?.join(format!("{name}.json")))
}

pub fn load(name: &str) -> Result<Vault, String> {
    let path = vault_path(name)?;
    let data = std::fs::read_to_string(&path)
        .map_err(|_| format!("no vault named '{name}' (try `cairn multisig list`)"))?;
    let vault: Vault = serde_json::from_str(&data).map_err(|_| "corrupt vault file".to_string())?;
    vault.check()?;
    Ok(vault)
}

fn save(vault: &Vault) -> Result<PathBuf, String> {
    vault.check()?;
    let path = vault_path(&vault.name)?;
    if path.exists() {
        return Err(format!(
            "a vault named '{}' already exists; refusing to overwrite it",
            vault.name
        ));
    }
    let json = serde_json::to_vec_pretty(vault).map_err(|e| e.to_string())?;
    hardening::write_private(&path, &json)?;
    Ok(path)
}

fn list_vaults() -> Result<Vec<Vault>, String> {
    let mut out = vec![];
    for entry in std::fs::read_dir(dir()?).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(data) = std::fs::read_to_string(&p) {
            if let Ok(v) = serde_json::from_str::<Vault>(&data) {
                out.push(v);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ---------------- keys ----------------

fn cosigner_from_seed(seed: &[u8], network: Network, label: &str) -> Result<Cosigner, String> {
    let secp = Secp256k1::new();
    let mut master = Xpriv::new_master(network, seed).map_err(|e| format!("invalid seed: {e}"))?;
    let path = DerivationPath::from_str(&format!("m/48'/{}'/0'/2'", wallet::coin_type(network)))
        .map_err(|e| e.to_string())?;
    let mut account = master
        .derive_priv(&secp, &path)
        .map_err(|e| e.to_string())?;
    // The descriptor origin uses the *master* fingerprint; an xpub only records
    // its parent's, which would not match the signing wallet.
    let fingerprint = master.fingerprint(&secp);
    let xpub = Xpub::from_priv(&secp, &account);
    account.private_key.non_secure_erase();
    master.private_key.non_secure_erase();
    Ok(Cosigner {
        label: label.to_string(),
        fingerprint: fingerprint.to_string(),
        xpub: xpub.to_string(),
        path: format!("m/48'/{}'/0'/2'", wallet::coin_type(network)),
    })
}

/// This device's cosigner key, derived from the authenticated wallet seed.
fn device_cosigner(opened: &keystore::Opened, label: &str) -> Result<Cosigner, String> {
    let seed = Zeroizing::new(opened.mnemonic.to_seed(opened.passphrase.as_str()));
    cosigner_from_seed(seed.as_ref(), opened.network, label)
}

/// Sign every input of `psbt` this signer owns, returning how many it signed.
///
/// Each input is validated against the vault before a signature is made: the
/// witness script must be the vault's script for the path in the PSBT, every
/// listed origin must be one of the vault's cosigners, and the key must really
/// be the one the witness script names.
pub fn sign_psbt(vault: &Vault, signer: &Signer, psbt: &mut Psbt) -> Result<u32, String> {
    vault.check()?;
    let network = vault.network()?;
    if signer.network() != network {
        return Err("this wallet is for a different network than the vault".into());
    }
    let master_fp = signer.fingerprint().to_string();
    if !vault.has_fingerprint(&master_fp) {
        return Err(format!(
            "this wallet ({master_fp}) is not a cosigner of vault '{}'",
            vault.name
        ));
    }
    let origin = vault
        .cosigners
        .iter()
        .find(|c| c.fingerprint == master_fp)
        .ok_or("cosigner key missing from the vault")?
        .origin()?;
    let origin_parts: Vec<ChildNumber> = origin.as_ref().to_vec();

    let secp = Secp256k1::new();
    let tx = psbt.unsigned_tx.clone();
    let mut jobs: Vec<(usize, DerivationPath, PublicKey, ScriptBuf, Amount)> = vec![];

    for (i, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {i} has no witness UTXO"))?;
        let script = input
            .witness_script
            .clone()
            .ok_or_else(|| format!("input {i} has no witness script"))?;
        if !utxo.script_pubkey.is_p2wsh()
            || Address::p2wsh(&script, network).script_pubkey() != utxo.script_pubkey
        {
            return Err(format!(
                "input {i}: witness UTXO does not pay this witness script"
            ));
        }
        let (threshold, keys) = parse_multisig(&script)?;
        if threshold != vault.threshold || keys.len() != vault.cosigners.len() {
            return Err(format!(
                "input {i}: witness script does not match this vault"
            ));
        }
        // Every listed origin must belong to a vault cosigner, and the script
        // must be the one that vault produces at that path.
        let mut ours: Option<(bitcoin::secp256k1::PublicKey, &DerivationPath)> = None;
        for (pubkey, (fp, path)) in &input.bip32_derivation {
            if !vault.has_fingerprint(&fp.to_string()) {
                return Err(format!(
                    "input {i} lists a key origin that is not a cosigner of this vault"
                ));
            }
            if !keys.iter().any(|k| k.inner == *pubkey) {
                return Err(format!(
                    "input {i}: a listed key is not in the witness script"
                ));
            }
            let parts: Vec<ChildNumber> = path.as_ref().to_vec();
            if parts.len() != origin_parts.len() + 2 || parts[..origin_parts.len()] != origin_parts
            {
                return Err(format!(
                    "input {i}: a listed path is not a vault address path"
                ));
            }
            let chain = match parts[origin_parts.len()] {
                ChildNumber::Normal { index } => index,
                _ => return Err(format!("input {i} has an invalid chain")),
            };
            let index = match parts[origin_parts.len() + 1] {
                ChildNumber::Normal { index } => index,
                _ => return Err(format!("input {i} has an invalid address index")),
            };
            if vault.witness_script(chain, index)? != script {
                return Err(format!(
                    "input {i}: witness script is not for this derivation"
                ));
            }
            if fp.to_string() == master_fp {
                ours = Some((*pubkey, path));
            }
        }
        let (pubkey, path) = ours.ok_or_else(|| {
            format!("input {i} has no key origin for this wallet (not ours to sign)")
        })?;
        let (mut sk, pk) = signer.key_at_absolute(path)?;
        sk.non_secure_erase();
        if pk != pubkey {
            return Err(format!("input {i}: key does not match this wallet"));
        }
        jobs.push((i, path.clone(), PublicKey::new(pubkey), script, utxo.value));
    }

    let mut cache = SighashCache::new(&tx);
    let mut signed = 0u32;
    for (i, path, pubkey, script, value) in jobs {
        let sighash = cache
            .p2wsh_signature_hash(i, &script, value, EcdsaSighashType::All)
            .map_err(|e| e.to_string())?;
        let (mut sk, _) = signer.key_at_absolute(&path)?;
        let sig = secp.sign_ecdsa(&Message::from(sighash), &sk);
        sk.non_secure_erase();
        let signature = Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::All,
        };
        if let Some(existing) = psbt.inputs[i].partial_sigs.get(&pubkey) {
            if *existing != signature {
                return Err(format!("input {i} already carries a different signature"));
            }
        }
        psbt.inputs[i].partial_sigs.insert(pubkey, signature);
        signed += 1;
    }
    Ok(signed)
}

// ---------------- spending ----------------

/// A coin of the vault: which derivation path it sits on matters, because the
/// PSBT key origins and the witness script are derived from it.
#[derive(Clone)]
pub struct Coin {
    pub utxo: Utxo,
    pub chain: u32,
    pub index: u32,
}

pub struct Spend {
    pub inputs: Vec<Coin>,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub change: Option<(Address, u64)>,
    pub rate: f64,
}

fn fee_for(rate: f64, vbytes: u64) -> u64 {
    (rate * vbytes as f64).ceil() as u64
}

/// Conservative size estimate: base bytes plus one witness per input.
fn estimate_vbytes(threshold: u32, script_len: usize, inputs: usize, outputs: usize) -> u64 {
    let witness = 1 + 1 + (threshold as u64) * 74 + 1 + script_len as u64;
    let base = 42 + inputs as u64 * 164 + outputs as u64 * 172;
    (base + inputs as u64 * witness).div_ceil(4)
}

fn output_vbytes(spk: &bitcoin::Script) -> u64 {
    8 + 1 + spk.len() as u64
}

/// Largest-first selection with exact fee accounting, mirroring the single-sig
/// send flow: change below the dust limit goes to the fee, and everything must
/// add up before a PSBT exists.
pub fn plan_spend(
    vault: &Vault,
    mut coins: Vec<Coin>,
    to: Address,
    amount: Option<u64>,
    rate: f64,
    change_index: u32,
) -> Result<Spend, String> {
    if !(1.0..=network::MAX_FEE_RATE).contains(&rate) {
        return Err(format!(
            "fee rate must be between 1 and {:.0} sat/vB",
            network::MAX_FEE_RATE
        ));
    }
    let script_len = vault.witness_script(0, 0)?.len();
    let to_spk = to.script_pubkey();
    let change = vault.address(1, change_index)?;
    let change_spk = change.script_pubkey();
    let size = |inputs: usize, outgoing: &[&bitcoin::Script]| -> u64 {
        let mut v = estimate_vbytes(vault.threshold, script_len, inputs, 0);
        for spk in outgoing {
            v += output_vbytes(spk);
        }
        v
    };

    coins.sort_by_key(|c| std::cmp::Reverse(c.utxo.value));
    let total: u64 = coins
        .iter()
        .try_fold(0u64, |acc, c| acc.checked_add(c.utxo.value))
        .ok_or("amount overflow")?;
    if total > network::MAX_MONEY_SATS {
        return Err("coins exceed the 21 million BTC supply".into());
    }

    match amount {
        None => {
            let fee = fee_for(rate, size(coins.len(), &[&to_spk]));
            if coins.is_empty() || total < fee + send::dust_limit(&to_spk) {
                return Err("the vault's coins are too small to cover the fee".into());
            }
            send::check_fee(fee, total - fee)?;
            Ok(Spend {
                inputs: coins,
                to,
                amount: total - fee,
                fee,
                change: None,
                rate,
            })
        }
        Some(amt) => {
            let dust = send::dust_limit(&to_spk);
            if amt < dust {
                return Err(format!("Amount is below the dust limit ({dust} sats)"));
            }
            let mut sel: Vec<Coin> = vec![];
            let mut sum = 0u64;
            for c in coins {
                sum = sum.checked_add(c.utxo.value).ok_or("amount overflow")?;
                sel.push(c);
                let fee_change = fee_for(rate, size(sel.len(), &[&to_spk, &change_spk]));
                if sum >= amt + fee_change
                    && sum - amt - fee_change >= send::dust_limit(&change_spk)
                {
                    send::check_fee(fee_change, amt)?;
                    return Ok(Spend {
                        inputs: sel,
                        to,
                        amount: amt,
                        fee: fee_change,
                        change: Some((change, sum - amt - fee_change)),
                        rate,
                    });
                }
                let fee_plain = fee_for(rate, size(sel.len(), &[&to_spk]));
                if sum >= amt + fee_plain {
                    let fee = sum - amt;
                    send::check_fee(fee, amt)?;
                    return Ok(Spend {
                        inputs: sel,
                        to,
                        amount: amt,
                        fee,
                        change: None,
                        rate,
                    });
                }
            }
            Err("not enough coins for this amount plus the fee".into())
        }
    }
}

/// Unsigned PSBT with the witness script, the value, and a key origin for every
/// cosigner, so each of them can sign the same file.
pub fn build_psbt(vault: &Vault, spend: &Spend) -> Result<Psbt, String> {
    vault.check()?;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: spend
            .inputs
            .iter()
            .map(|c| TxIn {
                previous_output: OutPoint {
                    txid: c.utxo.txid,
                    vout: c.utxo.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![],
    };
    tx.output.push(TxOut {
        value: Amount::from_sat(spend.amount),
        script_pubkey: spend.to.script_pubkey(),
    });
    if let Some((addr, value)) = &spend.change {
        tx.output.push(TxOut {
            value: Amount::from_sat(*value),
            script_pubkey: addr.script_pubkey(),
        });
    }
    let total_in = spend
        .inputs
        .iter()
        .try_fold(0u64, |a, c| a.checked_add(c.utxo.value))
        .ok_or("amount overflow")?;
    let total_out = tx
        .output
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
        .ok_or("amount overflow")?;
    if total_in != total_out + spend.fee {
        return Err("internal error: inputs do not equal outputs plus fee".into());
    }

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| e.to_string())?;
    let secp = Secp256k1::new();
    for (i, coin) in spend.inputs.iter().enumerate() {
        let script = vault.witness_script(coin.chain, coin.index)?;
        let input = &mut psbt.inputs[i];
        input.witness_script = Some(script.clone());
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(coin.utxo.value),
            script_pubkey: Address::p2wsh(&script, vault.network()?).script_pubkey(),
        });
        input.sighash_type = Some(EcdsaSighashType::All.into());
        for c in &vault.cosigners {
            let step = [
                ChildNumber::from_normal_idx(coin.chain).map_err(|e| e.to_string())?,
                ChildNumber::from_normal_idx(coin.index).map_err(|e| e.to_string())?,
            ];
            let pk = c
                .xpub()?
                .ckd_pub(&secp, step[0])
                .and_then(|k| k.ckd_pub(&secp, step[1]))
                .map_err(|e| e.to_string())?
                .public_key;
            let pk = PublicKey::new(pk);
            let mut parts: Vec<ChildNumber> = c.origin()?.as_ref().to_vec();
            parts.push(step[0]);
            parts.push(step[1]);
            let path = DerivationPath::from(parts);
            input
                .bip32_derivation
                .insert(pk.inner, (c.fingerprint()?, path));
        }
    }
    Ok(psbt)
}

/// Combine partial signatures and build the witness for every input.
///
/// This works on the PSBT alone: it re-parses each witness script, checks the
/// UTXO really pays it, requires the threshold to be met, and verifies every
/// signature it is about to use against the BIP143 sighash.
pub fn finalize(psbt: &mut Psbt) -> Result<Transaction, String> {
    let tx = psbt.unsigned_tx.clone();
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(&tx);

    for i in 0..psbt.inputs.len() {
        let input = &psbt.inputs[i];
        let utxo = input
            .witness_utxo
            .clone()
            .ok_or_else(|| format!("input {i} has no witness UTXO"))?;
        let script = input
            .witness_script
            .clone()
            .ok_or_else(|| format!("input {i} has no witness script"))?;
        if !utxo.script_pubkey.is_p2wsh()
            || utxo.script_pubkey != Address::p2wsh(&script, Network::Bitcoin).script_pubkey()
        {
            return Err(format!(
                "input {i}: witness UTXO does not pay this witness script"
            ));
        }
        let (threshold, keys) = parse_multisig(&script)?;
        let available = input
            .partial_sigs
            .keys()
            .filter(|k| keys.iter().any(|x| x == *k))
            .count();
        if available < threshold as usize {
            return Err(format!(
                "input {i} has {available} of {threshold} required signatures"
            ));
        }
        let sighash = cache
            .p2wsh_signature_hash(i, &script, utxo.value, EcdsaSighashType::All)
            .map_err(|e| e.to_string())?;
        let message = Message::from(sighash);
        // Signatures go in witness-script key order; the extra one is dropped.
        let mut ordered: Vec<Vec<u8>> = vec![];
        for k in &keys {
            if ordered.len() == threshold as usize {
                break;
            }
            if let Some(sig) = input.partial_sigs.get(k) {
                secp.verify_ecdsa(&message, &sig.signature, &k.inner)
                    .map_err(|_| format!("input {i}: a signature does not verify"))?;
                ordered.push(sig.serialize().to_vec());
            }
        }
        let mut witness = Witness::new();
        witness.push([]);
        for sig in ordered {
            witness.push(sig);
        }
        witness.push(script.as_bytes());
        psbt.inputs[i].final_script_witness = Some(witness);
        psbt.inputs[i].partial_sigs.clear();
    }
    psbt.clone().extract_tx().map_err(|e| e.to_string())
}

// ---------------- reading and writing ----------------

fn read_psbt(path: &str) -> Result<Psbt, String> {
    let p = PathBuf::from(path);
    let meta = std::fs::symlink_metadata(&p).map_err(|e| format!("cannot read PSBT: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("PSBT must be a regular file (not a symlink or FIFO)".into());
    }
    if meta.len() > MAX_PSBT_BYTES {
        return Err("PSBT file is unexpectedly large".into());
    }
    let bytes = std::fs::read(&p).map_err(|e| format!("cannot read PSBT: {e}"))?;
    Psbt::deserialize(&bytes).map_err(|e| format!("not a valid PSBT: {e}"))
}

fn write_psbt(path: &str, psbt: &Psbt) -> Result<(), String> {
    hardening::write_private(&PathBuf::from(path), &psbt.serialize())
}

fn confirm(prompt: &str, word: &str) -> Result<bool, String> {
    let answer: String = dialoguer::Input::with_theme(&crate::ui::theme())
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()
        .map_err(|e| e.to_string())?;
    Ok(answer.trim() == word)
}

// ---------------- command line ----------------

struct Opts {
    pos: Vec<String>,
    val: Vec<(String, String)>,
}

const SWITCHES: &[&str] = &["broadcast", "change", "json"];

impl Opts {
    fn get(&self, k: &str) -> Option<&str> {
        self.val
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.val
            .iter()
            .filter(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .collect()
    }
    fn has(&self, k: &str) -> bool {
        self.val.iter().any(|(key, _)| key == k)
    }
    fn need(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or_else(|| format!("--{k} is required"))
    }
}

fn parse(argv: &[String]) -> Result<Opts, String> {
    let mut pos = vec![];
    let mut val = vec![];
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if let Some(k) = a.strip_prefix("--") {
            if SWITCHES.contains(&k) {
                val.push((k.to_string(), "1".to_string()));
            } else {
                let v = it.next().ok_or_else(|| format!("--{k} needs a value"))?;
                if v.starts_with("--") {
                    return Err(format!("--{k} needs a value"));
                }
                val.push((k.to_string(), v.clone()));
            }
        } else {
            pos.push(a.clone());
        }
    }
    Ok(Opts { pos, val })
}

pub fn run(argv: &[String], json: bool) -> Result<(), String> {
    let o = parse(argv)?;
    let json = json || o.has("json");
    match o.pos.first().map(|s| s.as_str()) {
        Some("create") => create(&o, json),
        Some("list") => list(json),
        Some("info") => info(&o, json),
        Some("address") => address(&o, json),
        Some("balance") => balance(&o, json),
        Some("psbt") => create_spend(&o),
        Some("sign") => sign(&o),
        Some("combine") => combine(&o),
        Some("finalize") => finalize_cmd(&o),
        Some(other) => Err(format!(
            "unknown multisig command '{other}' (try: create, list, info, address, balance, psbt, sign, combine, finalize)"
        )),
        None => Err("usage: cairn multisig <create|list|info|address|balance|psbt|sign|combine|finalize>".into()),
    }
}

fn create(o: &Opts, json: bool) -> Result<(), String> {
    let name = o.need("name")?;
    let threshold: u32 = o
        .get("threshold")
        .unwrap_or("2")
        .parse()
        .map_err(|_| "--threshold must be a number")?;
    let supplied = o.all("cosigner");
    let total = supplied.len() as u32 + 1;
    if !(2..=MAX_COSIGNERS).contains(&total) {
        return Err(format!(
            "a vault needs 2 to {MAX_COSIGNERS} cosigners; give {} external xpub(s)",
            total.saturating_sub(1)
        ));
    }

    banner();
    section("Create multisig vault");
    println!();
    let wallet_name = crate::choose_wallet(o.get("wallet"))?;
    let opened = crate::unlock_wallet(&wallet_name)?;
    let network = opened.network;
    let label = o.get("label").unwrap_or("this device").to_string();
    let me = device_cosigner(&opened, &label)?;
    drop(opened);

    let mut cosigners = vec![me];
    for (i, raw) in supplied.iter().enumerate() {
        let (label, xpub) = match raw.split_once(':') {
            Some((l, x)) => (l.trim(), x.trim()),
            None => ("cosigner", raw.trim()),
        };
        let xpub =
            Xpub::from_str(xpub).map_err(|e| format!("cosigner #{}: invalid xpub: {e}", i + 2))?;
        if cosigners.iter().any(|c| c.xpub == xpub.to_string()) {
            return Err("the same xpub was supplied twice".into());
        }
        cosigners.push(Cosigner {
            label: label.to_string(),
            fingerprint: xpub.fingerprint().to_string(),
            xpub: xpub.to_string(),
            path: format!("m/48'/{}'/0'/2'", wallet::coin_type(network)),
        });
    }
    let vault = Vault::new(name, network, threshold, cosigners);
    vault.check()?;
    let path = save(&vault)?;
    let first = vault.address(0, 0)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "vault": vault.name,
                "id": vault.id()?,
                "network": vault.network,
                "threshold": vault.threshold,
                "cosigners": vault.cosigners.iter().map(|c| serde_json::json!({
                    "label": c.label, "fingerprint": c.fingerprint, "xpub": c.xpub,
                })).collect::<Vec<_>>(),
                "descriptor": vault.descriptor()?,
                "address": first.to_string(),
                "path": path.to_string_lossy(),
            })
        );
        return Ok(());
    }
    banner();
    ok("Vault created");
    println!();
    kv("Vault", &format!("{}  ({})", vault.name, vault.id()?));
    kv(
        "Policy",
        &format!("{} of {}", vault.threshold, vault.cosigners.len()),
    );
    kv("Descriptor", &style(vault.descriptor()?).cyan().to_string());
    kv(
        "First address",
        &style(first.to_string()).green().to_string(),
    );
    println!();
    hint("Import the descriptor into your other wallets so every cosigner sees the same vault.");
    hint("Back up every seed: any m keys can spend, and fewer cannot.");
    pause();
    Ok(())
}

fn list(json: bool) -> Result<(), String> {
    let vaults = list_vaults()?;
    if json {
        println!(
            "{}",
            serde_json::json!(vaults
                .iter()
                .map(|v| serde_json::json!({
                    "vault": v.name,
                    "id": v.id().unwrap_or_default(),
                    "network": v.network,
                    "threshold": v.threshold,
                    "cosigners": v.cosigners.len(),
                }))
                .collect::<Vec<_>>())
        );
        return Ok(());
    }
    banner();
    section("Multisig vaults");
    if vaults.is_empty() {
        println!();
        println!("  No vaults yet. Create one with `cairn multisig create`.");
        println!();
        return Ok(());
    }
    println!();
    let rows: Vec<Vec<String>> = vaults
        .iter()
        .map(|v| {
            vec![
                v.name.clone(),
                format!("{} of {}", v.threshold, v.cosigners.len()),
                v.network.clone(),
                v.id().unwrap_or_default(),
            ]
        })
        .collect();
    table(&["vault", "policy", "network", "id"], &rows, &[false; 4]);
    println!();
    Ok(())
}

fn info(o: &Opts, json: bool) -> Result<(), String> {
    let vault = load(o.need("name")?)?;
    let first = vault.address(0, 0)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "vault": vault.name,
                "id": vault.id()?,
                "network": vault.network,
                "threshold": vault.threshold,
                "cosigners": vault.cosigners.iter().map(|c| serde_json::json!({
                    "label": c.label, "fingerprint": c.fingerprint, "path": c.path,
                })).collect::<Vec<_>>(),
                "descriptor": vault.descriptor()?,
                "address": first.to_string(),
            })
        );
        return Ok(());
    }
    banner();
    section(&format!("Vault: {}", vault.name));
    println!();
    kv("Id", &vault.id()?);
    kv(
        "Policy",
        &format!("{} of {}", vault.threshold, vault.cosigners.len()),
    );
    kv("Network", &vault.network);
    kv("Addresses", "P2WSH (sortedmulti)");
    for c in &vault.cosigners {
        kv(
            &c.label,
            &format!("{}  {}", c.fingerprint, short_xpub(&c.xpub)),
        );
    }
    println!();
    kv("Descriptor", &style(vault.descriptor()?).cyan().to_string());
    kv(
        "First address",
        &style(first.to_string()).green().to_string(),
    );
    println!();
    Ok(())
}

fn short_xpub(xpub: &str) -> String {
    if xpub.len() > 24 {
        format!("{}…{}", &xpub[..12], &xpub[xpub.len() - 8..])
    } else {
        xpub.to_string()
    }
}

fn address(o: &Opts, json: bool) -> Result<(), String> {
    let vault = load(o.need("name")?)?;
    let count: u32 = o
        .get("count")
        .unwrap_or("5")
        .parse()
        .map_err(|_| "--count must be a number")?;
    if count == 0 || count > 200 {
        return Err("--count must be between 1 and 200".into());
    }
    let chain = if o.has("change") { 1 } else { 0 };
    let start: u32 = o
        .get("start")
        .unwrap_or("0")
        .parse()
        .map_err(|_| "--start must be a number")?;
    let mut rows = vec![];
    for i in start..start + count {
        rows.push((
            format!("m/48'/…/{chain}/{i}"),
            vault.address(chain, i)?.to_string(),
        ));
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "vault": vault.name,
                "chain": chain,
                "addresses": rows.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }
    banner();
    section("Vault addresses");
    println!();
    for (path, addr) in &rows {
        println!("  {:<20}{}", style(path).dim(), style(addr).green());
    }
    println!();
    Ok(())
}

fn scan(vault: &Vault) -> Result<Vec<Coin>, String> {
    let net = esplora::net_for(vault.network()?)?;
    let mut lookup: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    let mut addrs = vec![];
    for chain in 0..2u32 {
        for i in 0..GAP {
            let a = vault.address(chain, i)?.to_string();
            lookup.insert(a.clone(), (chain, i));
            addrs.push(a);
        }
    }
    let utxos = chain::utxos_for(net, &addrs)?;
    let mut coins = vec![];
    for utxo in utxos {
        if let Some((chain, index)) = lookup.get(&utxo.address) {
            coins.push(Coin {
                utxo,
                chain: *chain,
                index: *index,
            });
        }
    }
    Ok(coins)
}

fn balance(o: &Opts, json: bool) -> Result<(), String> {
    let vault = load(o.need("name")?)?;
    let coins = spin("Scanning the vault…", || scan(&vault))?;
    let total: u64 = coins
        .iter()
        .try_fold(0u64, |a, c| a.checked_add(c.utxo.value))
        .ok_or("amount overflow")?;
    let unit = network::unit(vault.network()?);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "vault": vault.name,
                "coins": coins.len(),
                "sats": total,
                "network": vault.network,
            })
        );
        return Ok(());
    }
    banner();
    section(&format!("Vault balance: {}", vault.name));
    println!();
    kv("Coins", &coins.len().to_string());
    kv(
        "Total",
        &format!("{} {unit}", style(fmt_btc(total as i64)).green()),
    );
    println!();
    if !coins.is_empty() {
        let rows: Vec<Vec<String>> = coins
            .iter()
            .map(|c| {
                vec![
                    format!("{}:{}", &c.utxo.txid.to_string()[..16], c.utxo.vout),
                    fmt_btc(c.utxo.value as i64),
                    format!("{}/{}", c.chain, c.index),
                ]
            })
            .collect();
        table(
            &["coin", "amount", "chain/index"],
            &rows,
            &[false, true, true],
        );
        println!();
    }
    Ok(())
}

fn create_spend(o: &Opts) -> Result<(), String> {
    let vault = load(o.need("name")?)?;
    let network = vault.network()?;
    let to = send::parse_address(o.need("to")?, network)?;
    let amount = send::parse_amount(o.need("amount")?)?;
    let rate: f64 = match o.get("rate") {
        Some(r) => r.parse().map_err(|_| "--rate must be a number")?,
        None => {
            let net = esplora::net_for(network)?;
            chain::fee_rates(net).map(|r| r.normal).unwrap_or(2.0)
        }
    };
    let change_index: u32 = o
        .get("change-index")
        .unwrap_or("0")
        .parse()
        .map_err(|_| "--change-index must be a number")?;

    banner();
    section("Build a vault PSBT");
    println!();
    let coins = spin("Scanning the vault…", || scan(&vault))?;
    if coins.is_empty() {
        return Err("the vault has no coins".into());
    }
    let spend = plan_spend(&vault, coins, to, amount, rate, change_index)?;

    kv("Vault", &format!("{}  ({})", vault.name, vault.id()?));
    kv("Recipient", &style(spend.to.to_string()).cyan().to_string());
    kv(
        "Amount",
        &format!(
            "{} {}",
            fmt_btc(spend.amount as i64),
            network::unit(network)
        ),
    );
    kv(
        "Fee",
        &format!("{} sats at {:.1} sat/vB", spend.fee, spend.rate),
    );
    if let Some((addr, v)) = &spend.change {
        kv("Change", &format!("{}  {}", fmt_btc(*v as i64), addr));
    }
    println!();
    warn("Every cosigner must approve this exact transaction before it can be spent.");
    println!();
    if !confirm("Type CREATE to write the unsigned PSBT", "CREATE")? {
        println!("\nCancelled. Nothing was created.");
        pause();
        return Ok(());
    }

    let psbt = build_psbt(&vault, &spend)?;
    let out = o
        .get("out")
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}-unsigned.psbt", vault.name));
    write_psbt(&out, &psbt)?;

    banner();
    ok("Unsigned vault PSBT written");
    println!();
    kv("File", &style(&out).cyan().to_string());
    kv("TxID", &psbt.unsigned_tx.compute_txid().to_string());
    println!();
    hint("Give the same file to k cosigners, then combine their signatures.");
    pause();
    Ok(())
}

fn sign(o: &Opts) -> Result<(), String> {
    let vault = load(o.need("name")?)?;
    let input = o.need("psbt")?.to_string();
    let mut psbt = read_psbt(&input)?;
    banner();
    section("Sign a vault PSBT");
    println!();
    let wallet_name = crate::choose_wallet(o.get("wallet"))?;
    let opened = crate::unlock_wallet(&wallet_name)?;
    let signer = Signer::from_opened(&opened)?;
    drop(opened);

    let signed = sign_psbt(&vault, &signer, &mut psbt)?;
    drop(signer);
    let out = o
        .get("out")
        .map(|s| s.to_string())
        .unwrap_or_else(|| input.replace(".psbt", "-signed.psbt"));
    let out = if out == input {
        format!("{input}.signed")
    } else {
        out
    };
    write_psbt(&out, &psbt)?;
    banner();
    ok("Signed");
    println!();
    kv("Inputs signed", &signed.to_string());
    kv("File", &style(&out).cyan().to_string());
    println!();
    hint("Combine every cosigner's file before finalizing.");
    pause();
    Ok(())
}

fn combine(o: &Opts) -> Result<(), String> {
    if o.pos.len() < 3 {
        return Err("usage: cairn multisig combine <A.psbt> <B.psbt> [...] [--out FILE]".into());
    }
    let mut merged = read_psbt(&o.pos[1])?;
    for path in &o.pos[2..] {
        let other = read_psbt(path)?;
        if other.unsigned_tx != merged.unsigned_tx {
            return Err(format!("{path} is a different transaction"));
        }
        merged
            .combine(other)
            .map_err(|e| format!("cannot combine {path}: {e}"))?;
    }
    let sigs: usize = merged.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    let out = o.get("out").unwrap_or("combined.psbt").to_string();
    write_psbt(&out, &merged)?;
    banner();
    ok("Combined");
    println!();
    kv("Signatures", &sigs.to_string());
    kv("File", &style(&out).cyan().to_string());
    println!();
    pause();
    Ok(())
}

fn finalize_cmd(o: &Opts) -> Result<(), String> {
    let path = o.need("psbt")?;
    let mut psbt = read_psbt(path)?;
    let tx = finalize(&mut psbt)?;
    let network = if o.get("network").map(|n| n == "testnet").unwrap_or(false) {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let total_in: u64 = psbt
        .inputs
        .iter()
        .filter_map(|i| i.witness_utxo.as_ref())
        .try_fold(0u64, |a, u| a.checked_add(u.value.to_sat()))
        .ok_or("amount overflow")?;
    let total_out: u64 = tx
        .output
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
        .ok_or("amount overflow")?;
    let fee = total_in.saturating_sub(total_out);
    send::check_fee_rate(fee, tx.vsize() as u64)?;

    banner();
    ok("Transaction finalized");
    println!();
    kv(
        "TxID",
        &style(tx.compute_txid().to_string()).cyan().to_string(),
    );
    kv("Fee", &format!("{fee} sats"));
    kv("Size", &format!("{} vB", tx.vsize()));
    println!();

    if o.has("broadcast") {
        let net = esplora::net_for(network)?;
        let hex = bitcoin::consensus::encode::serialize_hex(&tx);
        match spin("Broadcasting…", || chain::broadcast(net, &hex)) {
            Ok(server) => {
                ok("Broadcast");
                println!("  {}\n", style(server).cyan());
            }
            Err(e) if e.starts_with("REJECTED:") => return Err(e),
            Err(e) => return Err(format!("Broadcast status unknown: {e}")),
        }
        pause();
        return Ok(());
    }
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);
    if let Some(out) = o.get("out") {
        hardening::write_private(&PathBuf::from(out), hex.as_bytes())?;
        kv("Raw transaction", &style(out).cyan().to_string());
    } else {
        println!("  {hex}");
    }
    println!();
    hint("Broadcast with --broadcast, or send the raw transaction from any node.");
    pause();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    const NET: Network = Network::Testnet;

    fn signer_for(m: &Mnemonic) -> Signer {
        let opened = keystore::Opened {
            mnemonic: Box::new(m.clone()),
            passphrase: Zeroizing::new(String::new()),
            fingerprint: "00000000".into(),
            network: NET,
            address_type: keystore::AddressType::P2wpkh,
        };
        Signer::from_opened(&opened).unwrap()
    }

    fn cosigner_for(m: &Mnemonic, label: &str) -> Cosigner {
        let seed = Zeroizing::new(m.to_seed(""));
        cosigner_from_seed(seed.as_ref(), NET, label).unwrap()
    }

    fn fixture() -> (Vault, Mnemonic, Mnemonic) {
        let a = Mnemonic::from_entropy(&[1u8; 16]).unwrap();
        let b = Mnemonic::from_entropy(&[2u8; 16]).unwrap();
        let c = Mnemonic::from_entropy(&[3u8; 16]).unwrap();
        let vault = Vault::new(
            "test",
            NET,
            2,
            vec![
                cosigner_for(&a, "a"),
                cosigner_for(&b, "b"),
                cosigner_for(&c, "c"),
            ],
        );
        (vault, a, b)
    }

    fn coin(vault: &Vault, value: u64) -> Coin {
        Coin {
            utxo: Utxo {
                txid: bitcoin::Txid::from_byte_array([7u8; 32]),
                vout: 0,
                value,
                address: vault.address(0, 0).unwrap().to_string(),
            },
            chain: 0,
            index: 0,
        }
    }

    #[test]
    fn address_is_independent_of_cosigner_order() {
        let (vault, _, _) = fixture();
        let mut reversed = vault.clone();
        reversed.cosigners.reverse();
        assert_eq!(
            vault.address(0, 0).unwrap(),
            reversed.address(0, 0).unwrap()
        );
        assert_eq!(
            vault.witness_script(0, 0).unwrap(),
            reversed.witness_script(0, 0).unwrap()
        );
        assert!(vault.address(0, 0).unwrap().to_string().starts_with("tb1q"));
        assert!(vault.address(0, 0).unwrap().to_string().len() > 60); // P2WSH
        assert_eq!(
            vault.witness_script(0, 0).unwrap(),
            vault.witness_script(0, 0).unwrap()
        );
        assert_ne!(vault.address(0, 0).unwrap(), vault.address(0, 1).unwrap());
    }

    #[test]
    fn witness_script_round_trips() {
        let (vault, _, _) = fixture();
        let script = vault.witness_script(0, 0).unwrap();
        let (threshold, keys) = parse_multisig(&script).unwrap();
        assert_eq!(threshold, 2);
        assert_eq!(keys, vault.pubkeys_at(0, 0).unwrap());
        assert_eq!(multisig_script(threshold, &keys), script);

        // Only plain multisig is accepted.
        let odd = Builder::new()
            .push_int(2)
            .push_key(&vault.pubkeys_at(0, 0).unwrap()[0])
            .push_int(1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert!(parse_multisig(&odd).is_err());
        let not_multisig = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
        assert!(parse_multisig(&not_multisig).is_err());
    }

    #[test]
    fn two_of_three_signs_combines_and_finalizes() {
        let (vault, m_a, m_b) = fixture();
        let m_c = Mnemonic::from_entropy(&[3u8; 16]).unwrap();
        let to = vault.address(0, 1).unwrap();
        let spend = plan_spend(
            &vault,
            vec![coin(&vault, 100_000)],
            to,
            Some(30_000),
            2.0,
            0,
        )
        .unwrap();
        let mut psbt = build_psbt(&vault, &spend).unwrap();
        assert_eq!(psbt.inputs[0].bip32_derivation.len(), 3);

        // One signature is not enough.
        let a = signer_for(&m_a);
        assert_eq!(sign_psbt(&vault, &a, &mut psbt).unwrap(), 1);
        let mut only_a = psbt.clone();
        assert!(finalize(&mut only_a).is_err());

        // A second cosigner completes it; the third is not needed.
        let mut from_b = read_from(&vault, &spend);
        let b = signer_for(&m_b);
        let c = signer_for(&m_c);
        assert_eq!(sign_psbt(&vault, &b, &mut from_b).unwrap(), 1);
        let mut combined = psbt.clone();
        combined.combine(from_b.clone()).unwrap();
        assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
        let tx = finalize(&mut combined).unwrap();

        // Witness: dummy, two signatures, script.
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 4);
        assert!(witness.nth(0).unwrap().is_empty());
        assert_eq!(
            witness.nth(3).unwrap(),
            vault.witness_script(0, 0).unwrap().as_bytes()
        );

        // The third key alone also works (any 2 of 3).
        let mut from_c = read_from(&vault, &spend);
        assert_eq!(sign_psbt(&vault, &c, &mut from_c).unwrap(), 1);
        let mut pair = from_b;
        pair.combine(from_c).unwrap();
        finalize(&mut pair).unwrap();

        assert!(spend.fee >= 200);
    }

    fn read_from(vault: &Vault, spend: &Spend) -> Psbt {
        build_psbt(vault, spend).unwrap()
    }

    #[test]
    fn a_non_cosigner_and_a_foreign_vault_are_refused() {
        let (vault, m_a, _) = fixture();
        let stranger = Mnemonic::from_entropy(&[9u8; 16]).unwrap();
        let spend = plan_spend(
            &vault,
            vec![coin(&vault, 100_000)],
            vault.address(0, 1).unwrap(),
            Some(30_000),
            2.0,
            0,
        )
        .unwrap();
        let mut psbt = build_psbt(&vault, &spend).unwrap();
        let s = signer_for(&stranger);
        assert!(sign_psbt(&vault, &s, &mut psbt).is_err());

        // Another vault's PSBT is not signed even by a key we control.
        let mut other = vault.clone();
        other.cosigners[2] = cosigner_for(&stranger, "x");
        other.check().unwrap();
        let a = signer_for(&m_a);
        let err = sign_psbt(&other, &a, &mut psbt).unwrap_err();
        assert!(
            err.contains("cosigner")
                || err.contains("does not match this vault")
                || err.contains("witness script"),
            "{err}"
        );
    }

    #[test]
    fn finalize_checks_the_script_and_the_signatures() {
        let (vault, m_a, m_b) = fixture();
        let spend = plan_spend(
            &vault,
            vec![coin(&vault, 100_000)],
            vault.address(0, 1).unwrap(),
            Some(30_000),
            2.0,
            0,
        )
        .unwrap();
        let mut psbt = build_psbt(&vault, &spend).unwrap();
        sign_psbt(&vault, &signer_for(&m_a), &mut psbt).unwrap();
        sign_psbt(&vault, &signer_for(&m_b), &mut psbt).unwrap();
        let txid = psbt.unsigned_tx.compute_txid();

        // A witness UTXO that does not pay this script is refused.
        let mut wrong = psbt.clone();
        if let Some(u) = wrong.inputs[0].witness_utxo.as_mut() {
            u.script_pubkey = vault.address(0, 2).unwrap().script_pubkey();
        }
        assert!(finalize(&mut wrong).is_err());

        // A tampered signature is caught before it reaches the transaction.
        let mut bad = psbt.clone();
        let key = *bad.inputs[0].partial_sigs.keys().next().unwrap();
        bad.inputs[0].partial_sigs.get_mut(&key).unwrap().signature =
            bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64]).unwrap();
        assert!(finalize(&mut bad).is_err());

        let tx = finalize(&mut psbt).unwrap();
        assert_eq!(tx.compute_txid(), txid);
    }

    #[test]
    fn planning_respects_dust_and_the_fee_ceiling() {
        let (vault, _, _) = fixture();
        let to = vault.address(0, 1).unwrap();
        // Leftover below the P2WSH dust limit becomes fee, not change.
        let spend = plan_spend(
            &vault,
            vec![coin(&vault, 30_400)],
            to.clone(),
            Some(30_000),
            1.0,
            0,
        )
        .unwrap();
        assert!(spend.change.is_none());
        assert_eq!(spend.fee, 400);
        // Not enough coins.
        assert!(plan_spend(
            &vault,
            vec![coin(&vault, 1_000)],
            to.clone(),
            Some(30_000),
            1.0,
            0
        )
        .is_err());
        // Absurd rate is refused outright.
        assert!(plan_spend(
            &vault,
            vec![coin(&vault, 1_000_000)],
            to,
            Some(30_000),
            network::MAX_FEE_RATE + 1.0,
            0
        )
        .is_err());
    }
}
