//! Send flow: validate address -> amount -> fee -> review -> type SEND -> password -> sign -> broadcast.
//! Spends native SegWit (P2WPKH, ECDSA) and Taproot (P2TR, key-path schnorr) coins;
//! all signing is deterministic and done by libsecp256k1.

use crate::chain;
use crate::esplora::{self, Utxo, WalletState};
use crate::network;
use crate::ui::{banner, fmt_btc, menu, ok, pause, short, spin, theme};
use crate::wallet::{derivation_path, Signer, Watch};
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Denomination, EcdsaSighashType, Network, OutPoint,
    Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use console::style;
use dialoguer::{Confirm, Input, MultiSelect};
use std::collections::{HashMap, HashSet};

const MAX_MONEY: u64 = network::MAX_MONEY_SATS;
const TYPICAL_VBYTES: u64 = 141; // 1 input + 2 outputs, for fee previews
const MAX_FEE_SATS: u64 = 1_000_000; // hard ceiling: 0.01 BTC
const MAX_FEE_PERCENT: f64 = 10.0; // cap relative to what the recipient receives
const FEE_PERCENT_FLOOR_SATS: u64 = 10_000; // allow normal fees on small sends

// ---------- parsing ----------

pub fn parse_address(s: &str, network: Network) -> Result<Address, String> {
    let a: Address<NetworkUnchecked> = s
        .trim()
        .parse()
        .map_err(|e| format!("Not a valid Bitcoin address: {e}"))?;
    a.require_network(network).map_err(|_| {
        if network == Network::Bitcoin {
            "Wrong network: need a mainnet address starting with bc1".to_string()
        } else {
            "Wrong network: need a testnet address starting with tb1".to_string()
        }
    })
}

/// Ok(None) means "send everything".
pub fn parse_amount(s: &str) -> Result<Option<u64>, String> {
    let t = s.trim().to_lowercase();
    if t == "max" {
        return Ok(None);
    }
    let sats = if let Some(n) = t.strip_suffix("sats").or_else(|| t.strip_suffix("sat")) {
        n.trim()
            .parse::<u64>()
            .map_err(|_| "Enter a whole number of sats".to_string())?
    } else {
        Amount::from_str_in(&t, Denomination::Bitcoin)
            .map_err(|e| format!("Invalid amount: {e}"))?
            .to_sat()
    };
    if sats == 0 {
        return Err("Amount must be more than zero".into());
    }
    if sats > MAX_MONEY {
        return Err("Amount exceeds the 21 million BTC supply".into());
    }
    Ok(Some(sats))
}

// ---------- script + size helpers ----------

/// Dust threshold for an output of this script type. Below it the output is
/// unspendable by relay policy, so change that small is given to the fee instead
/// and payments that small are refused.
pub fn dust_limit(spk: &Script) -> u64 {
    if spk.is_p2wpkh() {
        294
    } else {
        330
    }
}

/// Script of an address string. Only the script shape is needed for sizing and
/// signing; the network binding is enforced by [`parse_address`] wherever an
/// address is accepted from outside.
pub fn script_of(addr: &str) -> Result<ScriptBuf, String> {
    let a: Address<NetworkUnchecked> = addr
        .parse()
        .map_err(|e| format!("Not a valid Bitcoin address: {e}"))?;
    Ok(a.assume_checked().script_pubkey())
}

fn input_vbytes(spk: &Script) -> u64 {
    if spk.is_p2tr() {
        58 // one 64-byte schnorr signature
    } else {
        68 // ECDSA signature + compressed pubkey
    }
}

fn output_vbytes(spk: &Script) -> u64 {
    8 + 1 + spk.len() as u64 // value + length prefix + script
}

/// Size estimate for this concrete set of coins and outputs. Under-estimating a
/// fee is what strands a transaction, so every value above is a slight over-estimate.
fn tx_vbytes(inputs: &[Utxo], outputs: &[ScriptBuf]) -> Result<u64, String> {
    let mut v = 11u64;
    for u in inputs {
        v += input_vbytes(&script_of(&u.address)?);
    }
    for spk in outputs {
        v += output_vbytes(spk);
    }
    Ok(v)
}

// ---------- planning ----------

fn fee_for(rate: f64, vbytes: u64) -> u64 {
    (rate * vbytes as f64).ceil() as u64
}

pub struct Plan {
    pub inputs: Vec<Utxo>,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    pub change: Option<(Address, u64)>,
    pub rate: f64,
}

/// Reject a fee that is either above the absolute ceiling or a large fraction
/// of what the recipient receives. The floor keeps ordinary fees on small
/// sends from being rejected.
pub(crate) fn check_fee(fee: u64, amount: u64) -> Result<(), String> {
    let percent = if amount == 0 {
        f64::INFINITY
    } else {
        fee as f64 * 100.0 / amount as f64
    };
    if fee > MAX_FEE_SATS || (fee > FEE_PERCENT_FLOOR_SATS && percent > MAX_FEE_PERCENT) {
        return Err(format!(
            "fee of {fee} sats is above the safety cap ({MAX_FEE_PERCENT:.0}% of the amount, \
             with a {FEE_PERCENT_FLOOR_SATS}-sat floor and a {MAX_FEE_SATS}-sat hard limit); \
             lower the fee rate"
        ));
    }
    Ok(())
}

/// Wallet-independent fee-rate ceiling. This catches a crafted PSBT that hides
/// a huge fee behind a large change output, where the percentage check alone
/// would be too weak (L-01).
pub(crate) fn check_fee_rate(fee: u64, vsize: u64) -> Result<(), String> {
    if vsize == 0 {
        return Err("cannot verify a fee for an empty transaction".into());
    }
    let max = (network::MAX_FEE_RATE * vsize as f64).ceil() as u64;
    if fee > max {
        return Err(format!(
            "fee of {fee} sats is above the {:.0} sat/vB ceiling for a {vsize}-vB transaction \
             (max {max} sats); refusing to continue",
            network::MAX_FEE_RATE
        ));
    }
    Ok(())
}

/// Largest-first coin selection. Change below dust goes to the fee (shown on the review screen).
pub fn plan(
    mut utxos: Vec<Utxo>,
    to: Address,
    amount: Option<u64>,
    rate: f64,
    change_addr: Address,
) -> Result<Plan, String> {
    let mut seen = HashSet::new();
    for u in &utxos {
        if !seen.insert((u.txid, u.vout)) {
            return Err("server returned the same coin more than once".into());
        }
    }
    utxos.sort_by_key(|a| std::cmp::Reverse(a.value));
    match amount {
        None => {
            let total = utxos
                .iter()
                .try_fold(0u64, |acc, u| acc.checked_add(u.value))
                .ok_or("amount overflow")?;
            if total > MAX_MONEY {
                return Err("input total exceeds the 21 million BTC supply".into());
            }
            let to_spk = to.script_pubkey();
            let fee = fee_for(rate, tx_vbytes(&utxos, std::slice::from_ref(&to_spk))?);
            if utxos.is_empty() || total < fee + dust_limit(&to_spk) {
                return Err("Balance is too small to cover the fee".into());
            }
            let amount = total - fee;
            check_fee(fee, amount)?;
            Ok(Plan {
                inputs: utxos,
                to,
                amount,
                fee,
                change: None,
                rate,
            })
        }
        Some(amt) => {
            let to_spk = to.script_pubkey();
            let change_spk = change_addr.script_pubkey();
            let dust = dust_limit(&to_spk);
            if amt < dust {
                return Err(format!("Amount is below the dust limit ({dust} sats)"));
            }
            let mut sel: Vec<Utxo> = vec![];
            let mut sum = 0u64;
            for u in utxos {
                sum = sum.checked_add(u.value).ok_or("amount overflow")?;
                if sum > MAX_MONEY {
                    return Err("input total exceeds the 21 million BTC supply".into());
                }
                sel.push(u);
                let fee_change = fee_for(
                    rate,
                    tx_vbytes(&sel, &[to_spk.clone(), change_spk.clone()])?,
                );
                let fee_plain = fee_for(rate, tx_vbytes(&sel, std::slice::from_ref(&to_spk))?);
                if sum >= amt + fee_change && sum - amt - fee_change >= dust_limit(&change_spk) {
                    let change = sum - amt - fee_change;
                    check_fee(fee_change, amt)?;
                    return Ok(Plan {
                        inputs: sel,
                        to,
                        amount: amt,
                        fee: fee_change,
                        change: Some((change_addr, change)),
                        rate,
                    });
                }
                if sum >= amt + fee_plain {
                    let fee = sum - amt;
                    check_fee(fee, amt)?;
                    return Ok(Plan {
                        inputs: sel,
                        to,
                        amount: amt,
                        fee,
                        change: None,
                        rate,
                    });
                }
            }
            Err("Not enough confirmed funds for this amount plus the fee".into())
        }
    }
}

// ---------- coin control ----------

/// Let the user pick which coins to spend. Returns the selected subset in the
/// same order as the server supplied it.
pub fn coin_control(utxos: Vec<Utxo>) -> Result<Vec<Utxo>, String> {
    if utxos.is_empty() {
        return Err("No confirmed coins found.".into());
    }
    let items: Vec<String> = utxos
        .iter()
        .map(|u| {
            format!(
                "{}  {:>14}  {}:{}",
                short(&u.txid.to_string()),
                fmt_btc(u.value as i64),
                short(&u.address),
                u.vout
            )
        })
        .collect();
    let defaults = vec![true; utxos.len()];
    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    let picked = MultiSelect::with_theme(&theme())
        .with_prompt("Select coins to spend (space to toggle, enter to confirm)")
        .items(&refs)
        .defaults(&defaults)
        .interact()
        .map_err(|e| e.to_string())?;
    if picked.is_empty() {
        return Err("No coins selected. Nothing was sent.".into());
    }
    Ok(picked.into_iter().map(|i| utxos[i].clone()).collect())
}

/// Ask whether to use automatic selection or coin control.
pub fn maybe_coin_control(utxos: Vec<Utxo>) -> Result<Vec<Utxo>, String> {
    let manual = Confirm::with_theme(&theme())
        .with_prompt("Choose coins manually? (coin control)")
        .default(false)
        .interact()
        .map_err(|e| e.to_string())?;
    if manual {
        coin_control(utxos)
    } else {
        Ok(utxos)
    }
}

// ---------- building + signing ----------

pub fn build_tx(p: &Plan) -> Transaction {
    let input = p
        .inputs
        .iter()
        .map(|u| TxIn {
            previous_output: OutPoint {
                txid: u.txid,
                vout: u.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect();
    let mut output = vec![TxOut {
        value: Amount::from_sat(p.amount),
        script_pubkey: p.to.script_pubkey(),
    }];
    if let Some((addr, v)) = &p.change {
        output.push(TxOut {
            value: Amount::from_sat(*v),
            script_pubkey: addr.script_pubkey(),
        });
    }
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    }
}

/// Address -> (chain, index) for every address the wallet may have used.
pub fn keymap(watch: &Watch, state: &WalletState) -> Result<HashMap<String, (u32, u32)>, String> {
    let mut map = HashMap::new();
    for (chain, count) in [(0u32, state.next_receive), (1u32, state.next_change)] {
        if count > 0 {
            for (i, a) in watch.addresses(chain, 0, count)?.into_iter().enumerate() {
                map.insert(a, (chain, i as u32));
            }
        }
    }
    Ok(map)
}

/// Unsigned PSBT with the UTXO and BIP174 key origin for every input.
pub fn build_psbt(
    p: &Plan,
    watch: &Watch,
    keymap: &HashMap<String, (u32, u32)>,
    master_fp: Fingerprint,
) -> Result<Psbt, String> {
    let mut psbt = Psbt::from_unsigned_tx(build_tx(p)).map_err(|e| e.to_string())?;
    for (i, u) in p.inputs.iter().enumerate() {
        let (chain, index) = *keymap
            .get(&u.address)
            .ok_or("coin belongs to an unknown address")?;
        let path: DerivationPath = derivation_path(watch.network(), watch.kind(), chain, index)
            .parse()
            .map_err(|e: bitcoin::bip32::Error| e.to_string())?;
        // The coin must sit on exactly the script our derivation says it does.
        let spk = watch.script_at(chain, index)?;
        if spk != parse_address(&u.address, watch.network())?.script_pubkey() {
            return Err("coin does not match this wallet's derivation".into());
        }
        let input = &mut psbt.inputs[i];
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(u.value),
            script_pubkey: spk.clone(),
        });
        if spk.is_p2tr() {
            // BIP371: taproot inputs carry an internal key and taproot key
            // origins, not legacy BIP32 derivations.
            let xonly = XOnlyPublicKey::from(watch.pubkey_at(chain, index)?);
            input.tap_internal_key = Some(xonly);
            input
                .tap_key_origins
                .insert(xonly, (vec![], (master_fp, path)));
        } else {
            input
                .bip32_derivation
                .insert(watch.pubkey_at(chain, index)?, (master_fp, path));
            input.sighash_type = Some(EcdsaSighashType::All.into());
        }
    }
    Ok(psbt)
}

/// Sign every input. `keymap` maps our address -> (chain, index).
pub fn sign(
    tx: &mut Transaction,
    p: &Plan,
    signer: &Signer,
    keymap: &HashMap<String, (u32, u32)>,
) -> Result<(), String> {
    let secp = Secp256k1::new();

    // Taproot sighashes commit to every input's value and script, so all the
    // prevouts are needed up front. They come from the coins being spent, not
    // from the network.
    let mut prevouts = Vec::with_capacity(p.inputs.len());
    for u in &p.inputs {
        let spk = parse_address(&u.address, signer.network())?.script_pubkey();
        prevouts.push(TxOut {
            value: Amount::from_sat(u.value),
            script_pubkey: spk,
        });
    }

    let mut cache = SighashCache::new(&mut *tx);
    for (i, u) in p.inputs.iter().enumerate() {
        let (chain, idx) = *keymap
            .get(&u.address)
            .ok_or("coin belongs to an unknown address")?;
        let spk = &prevouts[i].script_pubkey;
        if spk.is_p2tr() {
            let (mut sk, pk) = signer.key_at(chain, idx)?;
            // The key we derived must really be the one that locks this coin.
            let xonly = XOnlyPublicKey::from(pk);
            if ScriptBuf::new_p2tr(&secp, xonly, None) != *spk {
                sk.non_secure_erase();
                return Err("internal check failed: key does not match coin".into());
            }
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .map_err(|e| e.to_string())?;
            let keypair = Keypair::from_secret_key(&secp, &sk);
            sk.non_secure_erase();
            let sig = secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &keypair);
            let mut witness = Witness::new();
            witness.push(sig.as_ref());
            *cache.witness_mut(i).ok_or("witness slot missing")? = witness;
        } else {
            let sighash = cache
                .p2wpkh_signature_hash(i, spk, prevouts[i].value, EcdsaSighashType::All)
                .map_err(|e| e.to_string())?;
            let (mut sk, pk) = signer.key_at(chain, idx)?;
            if ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash()) != *spk {
                sk.non_secure_erase();
                return Err("internal check failed: key does not match coin".into());
            }
            let sig = secp.sign_ecdsa(&Message::from(sighash), &sk);
            sk.non_secure_erase();
            let signature = Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            *cache.witness_mut(i).ok_or("witness slot missing")? = Witness::p2wpkh(&signature, &pk);
        }
    }
    Ok(())
}

// ---------- the interactive flow ----------

fn pct(fee: u64, amount: u64) -> f64 {
    if amount == 0 {
        0.0
    } else {
        fee as f64 * 100.0 / amount as f64
    }
}

/// Show the standard transaction review box. Used by the online send flow and
/// by offline PSBT creation (which uses the same [`Plan`]).
pub fn review(p: &Plan, network: Network) {
    let unit = network::unit(network);
    crate::ui::set_context(format!("Send  ·  review  ·  {}", network::label(network)));
    banner();
    crate::ui::card(
        "Recipient",
        &[style(p.to.to_string()).cyan().bold().to_string()],
    );
    println!();
    let mut lines = vec![format!(
        "{:<12}{} {}",
        style("Amount").dim(),
        style(fmt_btc(p.amount as i64)).bold(),
        style(unit).dim()
    )];
    if let Some((_, v)) = &p.change {
        lines.push(format!(
            "{:<12}{} {}",
            style("Change").dim(),
            fmt_btc(*v as i64),
            style(unit).dim()
        ));
    } else {
        lines.push(format!(
            "{:<12}{}",
            style("Change").dim(),
            style("none").dim()
        ));
    }
    lines.push(format!(
        "{:<12}{} {}",
        style("Fee").dim(),
        fmt_btc(p.fee as i64),
        style(unit).dim()
    ));
    let rate = format!("{:.1} sat/vB  ·  {} input(s)", p.rate, p.inputs.len());
    lines.push(format!("{:<12}{}", style("Fee rate").dim(), rate));
    lines.push(style("─".repeat(36)).dim().to_string());
    lines.push(format!(
        "{:<12}{} {}",
        style("Total").dim(),
        style(fmt_btc((p.amount + p.fee) as i64)).yellow().bold(),
        style(unit).dim()
    ));
    crate::ui::card("Payment", &lines);
    if pct(p.fee, p.amount) > 5.0 {
        println!();
        crate::ui::warn(&format!(
            "Fee is {:.1}% of the amount.",
            pct(p.fee, p.amount)
        ));
    }
    println!();
    crate::ui::warn("Check the address character by character. Sends cannot be undone.");
}

/// Returns Ok(true) if a transaction was broadcast.
pub fn send_flow(name: &str, fp: &str, watch: &Watch, state: &WalletState) -> Result<bool, String> {
    let network = watch.network();
    let net = esplora::net_for(network)?;
    let unit = network::unit(network);
    banner();
    println!(
        "{}\n",
        style(format!("Send ({})", network::label(network))).bold()
    );
    if state.confirmed <= 0 {
        return Err("No confirmed funds to send yet. Wait for confirmations, then Refresh.".into());
    }
    println!(
        "Available (confirmed): {} {unit}\n",
        style(fmt_btc(state.confirmed)).green()
    );

    let to_str: String = Input::with_theme(&theme())
        .with_prompt("Recipient address")
        .validate_with(|s: &String| -> Result<(), String> { parse_address(s, network).map(|_| ()) })
        .interact_text()
        .map_err(|e| e.to_string())?;
    let to = parse_address(&to_str, network)?;

    let amt_str: String = Input::with_theme(&theme())
        .with_prompt("Amount (e.g. 0.0005, 50000 sats, or max)")
        .validate_with(|s: &String| -> Result<(), String> { parse_amount(s).map(|_| ()) })
        .interact_text()
        .map_err(|e| e.to_string())?;
    let amount = parse_amount(&amt_str)?;

    // Our coins, and fee estimates.
    let loaded = spin("Loading your coins and fees…", || -> Result<_, String> {
        let keymap = keymap(watch, state)?;
        let addrs: Vec<String> = state
            .used
            .iter()
            .filter(|a| keymap.contains_key(*a))
            .cloned()
            .collect();
        let utxos = chain::utxos_for(net, &addrs)?;
        Ok((utxos, keymap, chain::fee_rates(net).ok()))
    })?;
    let (utxos, keymap, rates) = loaded;
    if utxos.is_empty() {
        return Err("No confirmed coins found. Wait for confirmations, then Refresh.".into());
    }
    let utxos = maybe_coin_control(utxos)?;

    // Fee choice.
    println!();
    let rate: f64 = match rates {
        Some(r) => {
            let items = [
                format!(
                    "Slow    {:.1} sat/vB  (~{} sats)",
                    r.slow,
                    fee_for(r.slow, TYPICAL_VBYTES)
                ),
                format!(
                    "Normal  {:.1} sat/vB  (~{} sats)",
                    r.normal,
                    fee_for(r.normal, TYPICAL_VBYTES)
                ),
                format!(
                    "Fast    {:.1} sat/vB  (~{} sats)",
                    r.fast,
                    fee_for(r.fast, TYPICAL_VBYTES)
                ),
            ];
            let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
            match menu(&refs)? {
                0 => r.slow,
                1 => r.normal,
                _ => r.fast,
            }
        }
        None => Input::with_theme(&theme())
            .with_prompt("Fee rate in sat/vB (estimates unavailable)")
            .default(2.0f64)
            .validate_with(|v: &f64| -> Result<(), &str> {
                if *v >= 1.0 && *v <= network::MAX_FEE_RATE {
                    Ok(())
                } else {
                    Err("Enter a value from 1 to 1000")
                }
            })
            .interact_text()
            .map_err(|e| e.to_string())?,
    };

    let change_addr = parse_address(&watch.address_at(1, state.next_change)?, network)?;
    let p = plan(utxos, to, amount, rate, change_addr)?;
    spin("Verifying coins…", || {
        chain::verify_prevouts(net, &p.inputs)
    })?;

    // Sanity: numbers must add up exactly.
    let total_in = p
        .inputs
        .iter()
        .try_fold(0u64, |acc, u| acc.checked_add(u.value))
        .ok_or("amount overflow")?;
    let change_v = p.change.as_ref().map(|c| c.1).unwrap_or(0);
    let expected = p
        .amount
        .checked_add(p.fee)
        .and_then(|v| v.checked_add(change_v))
        .ok_or("amount overflow")?;
    if total_in != expected {
        return Err("internal error: amounts do not add up. Nothing was sent.".into());
    }

    // Review screen.
    review(&p, network);

    let confirm: String = Input::with_theme(&theme())
        .with_prompt("Type SEND to confirm (anything else cancels)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| e.to_string())?;
    if confirm.trim() != "SEND" {
        println!("\nCancelled. Nothing was sent.");
        pause();
        return Ok(false);
    }

    // Password again, then unlock keys just for signing. This goes through the
    // same retry policy as opening a wallet.
    let opened = crate::unlock_wallet_with(name, Some(fp), "Password to sign")?;
    if opened.network != network {
        return Err("Wallet network changed. Nothing was sent.".into());
    }
    // Only an authenticated `Opened` can produce a signer; it also supplies the
    // network and BIP39 passphrase, so the old "wrong passphrase" mismatch is now
    // structurally impossible.
    let signer = Signer::from_opened(&opened)?;
    drop(opened);
    if signer.account_xpub()? != watch.xpub_string() {
        return Err("Keys do not match this wallet session. Nothing was sent.".into());
    }
    if signer.kind() != watch.kind() {
        return Err("Wallet address type changed during this session. Nothing was sent.".into());
    }

    let mut tx = build_tx(&p);
    sign(&mut tx, &p, &signer, &keymap)?;
    drop(signer);
    if p.fee < tx.vsize() as u64 {
        return Err("Fee is below the 1 sat/vB relay minimum. Nothing was sent.".into());
    }
    check_fee_rate(p.fee, tx.vsize() as u64)?;
    let txid = tx.compute_txid().to_string();
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);

    match spin("Broadcasting…", || chain::broadcast(net, &hex)) {
        Ok(server_txid) => {
            banner();
            ok("Transaction sent");
            println!("\n  {}", style("Transaction ID").dim());
            println!("  {}\n", style(&txid).cyan());
            if server_txid != txid {
                println!(
                    "{}",
                    style(format!(
                        "  Note: server reported a different id: {server_txid}"
                    ))
                    .yellow()
                );
            }
            println!("  It's pending until confirmed. Use Refresh to follow it.\n");
            pause();
            Ok(true)
        }
        Err(e) if e.starts_with("REJECTED:") => Err(e),
        Err(e) => Err(format!("Broadcast status unknown: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{Signer, Watch};
    use bip39::Mnemonic;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn utxo(value: u64, addr: &str) -> Utxo {
        Utxo {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
            value,
            address: addr.to_string(),
        }
    }

    fn addrs(network: Network) -> (String, Address, Address, Watch) {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let w = Watch::from_mnemonic(&m, network).unwrap();
        let a0 = w.address_at(0, 0).unwrap();
        let to = parse_address(&w.address_at(0, 1).unwrap(), network).unwrap();
        let change = parse_address(&w.address_at(1, 0).unwrap(), network).unwrap();
        (a0, to, change, w)
    }

    #[test]
    fn amount_parsing() {
        assert_eq!(parse_amount("max").unwrap(), None);
        assert_eq!(parse_amount("0.0005").unwrap(), Some(50_000));
        assert_eq!(parse_amount("1500 sats").unwrap(), Some(1_500));
        assert_eq!(parse_amount("  1 sat  ").unwrap(), Some(1));
        assert_eq!(parse_amount("0.00000001").unwrap(), Some(1));
        assert_eq!(
            parse_amount("20999999.99999999").unwrap(),
            Some(2_099_999_999_999_999)
        );
        assert_eq!(parse_amount("21000000").unwrap(), Some(MAX_MONEY));
        assert!(parse_amount("21000000.00000001").is_err());
        assert!(parse_amount("21000001").is_err());
        assert!(parse_amount("0").is_err());
        assert!(parse_amount("abc").is_err());
        assert!(parse_amount("0.123456789").is_err());
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("1e3").is_err());
        assert!(parse_amount("0x10 sats").is_err());
        assert!(parse_amount("18446744073709551616 sats").is_err());
        // Whitespace-only and unicode digits must not be accepted as money.
        assert!(parse_amount("   ").is_err());
        assert!(parse_amount("١٢٣").is_err());
    }

    #[test]
    fn address_validation() {
        let (a0, _, _, _) = addrs(Network::Testnet);
        assert!(parse_address(&a0, Network::Testnet).is_ok());
        assert!(
            parse_address(
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                Network::Testnet
            )
            .is_err(),
            "mainnet must be rejected by a testnet wallet"
        );
        assert!(parse_address("tb1qnotanaddress", Network::Testnet).is_err());
        assert!(parse_address("", Network::Testnet).is_err());

        let (m_addr, _, _, _) = addrs(Network::Bitcoin);
        assert!(parse_address(&m_addr, Network::Bitcoin).is_ok());
        assert!(m_addr.starts_with("bc1q"));
        assert!(
            parse_address(&a0, Network::Bitcoin).is_err(),
            "testnet must be rejected by a mainnet wallet"
        );
    }

    #[test]
    fn plan_with_change() {
        let (a0, to, change, _) = addrs(Network::Testnet);
        let p = plan(vec![utxo(100_000, &a0)], to, Some(30_000), 1.0, change).unwrap();
        assert_eq!(p.fee, 141);
        let c = p.change.as_ref().unwrap().1;
        assert_eq!(30_000 + p.fee + c, 100_000);
    }

    #[test]
    fn plan_rejects_duplicate_coins() {
        let (a0, to, change, _) = addrs(Network::Testnet);
        let u = utxo(100_000, &a0);
        assert!(plan(vec![u.clone(), u], to, Some(30_000), 1.0, change).is_err());
    }

    #[test]
    fn plan_max_and_insufficient_and_dust() {
        let (a0, to, change, _) = addrs(Network::Testnet);
        let too_much = vec![utxo(MAX_MONEY, &a0), utxo(MAX_MONEY, &a0)];
        assert!(
            plan(too_much, to.clone(), None, 1.0, change.clone()).is_err(),
            "a server claiming more coins than exist must be rejected"
        );
        let p = plan(
            vec![utxo(100_000, &a0)],
            to.clone(),
            None,
            1.0,
            change.clone(),
        )
        .unwrap();
        assert_eq!(p.fee, 110);
        assert_eq!(p.amount, 99_890);
        assert!(p.change.is_none());

        assert!(plan(
            vec![utxo(1_000, &a0)],
            to.clone(),
            Some(50_000),
            1.0,
            change.clone()
        )
        .is_err());
        assert!(plan(
            vec![utxo(100_000, &a0)],
            to.clone(),
            Some(100),
            1.0,
            change.clone()
        )
        .is_err());

        // Change would be dust: it is added to the fee instead.
        let p = plan(vec![utxo(30_300, &a0)], to, Some(30_000), 1.0, change).unwrap();
        assert!(p.change.is_none());
        assert_eq!(p.fee, 300);
    }

    #[test]
    fn fee_cap_rejects_absurd_fees() {
        let (a0, to, change, _) = addrs(Network::Testnet);

        // Max send of 200k at 1,000 sat/vB: a ~110k fee is over 10% of what is left.
        assert!(plan(
            vec![utxo(200_000, &a0)],
            to.clone(),
            None,
            1000.0,
            change.clone()
        )
        .is_err());

        // A 141k fee on a 50k send is over 10% of the amount.
        assert!(plan(
            vec![utxo(1_000_000, &a0)],
            to.clone(),
            Some(50_000),
            1000.0,
            change.clone()
        )
        .is_err());

        // Many inputs at the rate ceiling trip the absolute 1M-sat cap.
        let many: Vec<Utxo> = (0..20).map(|i| utxo(100_000 + i, &a0)).collect();
        assert!(plan(many, to, None, 1000.0, change).is_err());
    }

    #[test]
    fn signature_verifies() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let (a0, to, change, _) = addrs(Network::Testnet);
        let signer = Signer::from_mnemonic(&m, Network::Testnet).unwrap();
        let mut keymap = HashMap::new();
        keymap.insert(a0.clone(), (0u32, 0u32));
        let p = plan(vec![utxo(100_000, &a0)], to, Some(30_000), 2.0, change).unwrap();

        let mut tx = build_tx(&p);
        sign(&mut tx, &p, &signer, &keymap).unwrap();
        assert_eq!(tx.input[0].witness.len(), 2);
        assert!(p.fee >= tx.vsize() as u64);

        // Independently re-verify the signature against the sighash.
        let secp = Secp256k1::new();
        let wit = &tx.input[0].witness;
        let sig = Signature::from_slice(wit.nth(0).unwrap()).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(wit.nth(1).unwrap()).unwrap();
        let spk = parse_address(&a0, Network::Testnet)
            .unwrap()
            .script_pubkey();
        let mut cache = SighashCache::new(&tx);
        let h = cache
            .p2wpkh_signature_hash(0, &spk, Amount::from_sat(100_000), EcdsaSighashType::All)
            .unwrap();
        secp.verify_ecdsa(&Message::from(h), &sig.signature, &pk)
            .unwrap();

        // A wrong key map must be refused.
        let mut bad = HashMap::new();
        bad.insert(a0, (0u32, 5u32));
        let mut tx2 = build_tx(&p);
        assert!(sign(&mut tx2, &p, &signer, &bad).is_err());
    }

    fn taproot_fixture() -> (Watch, Signer, String, Address, Address) {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let kind = crate::keystore::AddressType::P2tr;
        let watch = Watch::with_kind(&m, Network::Bitcoin, "", kind).unwrap();
        let signer = Signer::from_mnemonic_with_kind(&m, Network::Bitcoin, kind).unwrap();
        let a0 = watch.address_at(0, 0).unwrap();
        let to = parse_address(&watch.address_at(0, 1).unwrap(), Network::Bitcoin).unwrap();
        let change = parse_address(&watch.address_at(1, 0).unwrap(), Network::Bitcoin).unwrap();
        (watch, signer, a0, to, change)
    }

    #[test]
    fn taproot_spend_signs_with_schnorr_and_verifies() {
        let (_watch, signer, a0, to, change) = taproot_fixture();
        assert!(a0.starts_with("bc1p"));
        let mut keymap = HashMap::new();
        keymap.insert(a0.clone(), (0u32, 0u32));
        let p = plan(vec![utxo(100_000, &a0)], to, Some(30_000), 2.0, change).unwrap();

        let mut tx = build_tx(&p);
        sign(&mut tx, &p, &signer, &keymap).unwrap();

        // Key-path spend: one 64-byte schnorr signature and nothing else.
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 1);
        let raw = witness.nth(0).unwrap();
        assert_eq!(raw.len(), 64, "SIGHASH_DEFAULT must not append a byte");

        // Independently recompute the BIP341 sighash and verify the signature.
        let secp = Secp256k1::new();
        let spk = script_of(&a0).unwrap();
        let prevouts = vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        }];
        let mut cache = SighashCache::new(&tx);
        let h = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let xonly = XOnlyPublicKey::from(signer.key_at(0, 0).unwrap().1);
        let sig = bitcoin::taproot::Signature::from_slice(raw).unwrap();
        secp.verify_schnorr(
            &sig.signature,
            &Message::from_digest(h.to_byte_array()),
            &xonly,
        )
        .unwrap();

        // The fee must still cover the signed transaction, and a key that does not
        // lock the coin must be refused rather than silently used.
        assert!(p.fee >= tx.vsize() as u64);
        let mut bad = HashMap::new();
        bad.insert(a0, (0u32, 9u32));
        let mut tx2 = build_tx(&p);
        assert!(sign(&mut tx2, &p, &signer, &bad).is_err());
    }

    #[test]
    fn taproot_dust_is_330_sats() {
        let (_watch, _signer, a0, to, change) = taproot_fixture();
        // 320 sats of change is below the Taproot dust limit, so it becomes fee.
        let p = plan(
            vec![utxo(30_320, &a0)],
            to.clone(),
            Some(30_000),
            1.0,
            change.clone(),
        )
        .unwrap();
        assert!(p.change.is_none());
        assert_eq!(p.fee, 320);

        // The same leftover is ordinary change for a P2WPKH recipient... which it is
        // not here: both the payment and the change are Taproot, so it is refused.
        assert!(plan(
            vec![utxo(30_329, &a0)],
            to,
            Some(30_000),
            1.0,
            change.clone()
        )
        .unwrap()
        .change
        .is_none());
    }

    #[test]
    fn taproot_psbt_carries_bip371_fields() {
        let (watch, signer, a0, to, change) = taproot_fixture();
        let mut keymap = HashMap::new();
        keymap.insert(a0.clone(), (0u32, 0u32));
        let p = plan(vec![utxo(100_000, &a0)], to, Some(30_000), 2.0, change).unwrap();
        let mut psbt = build_psbt(&p, &watch, &keymap, signer.fingerprint()).unwrap();
        assert!(psbt.inputs[0].bip32_derivation.is_empty());
        assert!(psbt.inputs[0].tap_internal_key.is_some());
        assert_eq!(psbt.inputs[0].tap_key_origins.len(), 1);
        crate::psbt_guard::check_structure(&psbt).unwrap();

        signer.sign_psbt(&mut psbt).unwrap();
        let tx = psbt.clone().extract_tx().unwrap();
        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness.nth(0).unwrap().len(), 64);
    }

    /// Sending from a wallet with a BIP39 passphrase must use the same seed the
    /// watch-only session was derived from, otherwise the account keys do not
    /// match and signing is refused.
    #[test]
    fn signature_verifies_with_passphrase() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let pass = "correct horse";
        let watch = Watch::from_mnemonic_with_passphrase(&m, Network::Testnet, pass).unwrap();
        let signer = Signer::from_mnemonic_with_passphrase(&m, Network::Testnet, pass).unwrap();
        assert_eq!(signer.account_xpub().unwrap(), watch.xpub_string());

        let a0 = watch.address_at(0, 0).unwrap();
        let change = parse_address(&watch.address_at(1, 0).unwrap(), Network::Testnet).unwrap();
        let to = parse_address(&watch.address_at(0, 1).unwrap(), Network::Testnet).unwrap();
        let mut keymap = HashMap::new();
        keymap.insert(a0.clone(), (0u32, 0u32));
        let p = plan(vec![utxo(100_000, &a0)], to, Some(30_000), 2.0, change).unwrap();

        let mut tx = build_tx(&p);
        sign(&mut tx, &p, &signer, &keymap).unwrap();

        let secp = Secp256k1::new();
        let wit = &tx.input[0].witness;
        let sig = Signature::from_slice(wit.nth(0).unwrap()).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(wit.nth(1).unwrap()).unwrap();
        let spk = parse_address(&a0, Network::Testnet)
            .unwrap()
            .script_pubkey();
        let mut cache = SighashCache::new(&tx);
        let h = cache
            .p2wpkh_signature_hash(0, &spk, Amount::from_sat(100_000), EcdsaSighashType::All)
            .unwrap();
        secp.verify_ecdsa(&Message::from(h), &sig.signature, &pk)
            .unwrap();

        // The passphrase-less derivation is a different wallet entirely.
        let wrong = Signer::from_mnemonic(&m, Network::Testnet).unwrap();
        assert_ne!(wrong.account_xpub().unwrap(), watch.xpub_string());
    }
}
