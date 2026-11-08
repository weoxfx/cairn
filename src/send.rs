//! Send flow: validate address -> amount -> fee -> review -> type SEND -> password -> sign -> broadcast.
//! Native SegWit (P2WPKH) inputs only. Deterministic (RFC6979) ECDSA signing via libsecp256k1.

use crate::esplora::{self, Utxo, WalletState};
use crate::network;
use crate::ui::{banner, boxed, fmt_btc, menu, ok, pause, spin, theme};
use crate::wallet::{derivation_path, Signer, Watch};
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::ecdsa::Signature;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Denomination, EcdsaSighashType, Network, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use console::style;
use dialoguer::Input;
use std::collections::HashMap;

const DUST: u64 = 294; // P2WPKH dust threshold in sats
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

// ---------- planning ----------

fn vsize(inputs: usize, outputs: usize) -> u64 {
    (11 + 68 * inputs + 31 * outputs) as u64
}

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

/// Largest-first coin selection. Change below dust goes to the fee (shown on the review screen).
pub fn plan(
    mut utxos: Vec<Utxo>,
    to: Address,
    amount: Option<u64>,
    rate: f64,
    change_addr: Address,
) -> Result<Plan, String> {
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
            let fee = fee_for(rate, vsize(utxos.len(), 1));
            if utxos.is_empty() || total < fee + DUST {
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
            if amt < DUST {
                return Err(format!("Amount is below the dust limit ({DUST} sats)"));
            }
            let mut sel: Vec<Utxo> = vec![];
            let mut sum = 0u64;
            for u in utxos {
                sum = sum.checked_add(u.value).ok_or("amount overflow")?;
                if sum > MAX_MONEY {
                    return Err("input total exceeds the 21 million BTC supply".into());
                }
                sel.push(u);
                let fee_change = fee_for(rate, vsize(sel.len(), 2));
                let fee_plain = fee_for(rate, vsize(sel.len(), 1));
                if sum >= amt + fee_change && sum - amt - fee_change >= DUST {
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
        let path: DerivationPath = derivation_path(watch.network(), chain, index)
            .parse()
            .map_err(|e: bitcoin::bip32::Error| e.to_string())?;
        let input = &mut psbt.inputs[i];
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(u.value),
            script_pubkey: parse_address(&u.address, watch.network())?.script_pubkey(),
        });
        input
            .bip32_derivation
            .insert(watch.pubkey_at(chain, index)?, (master_fp, path));
        input.sighash_type = Some(EcdsaSighashType::All.into());
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
    let mut cache = SighashCache::new(&mut *tx);
    for (i, u) in p.inputs.iter().enumerate() {
        let (chain, idx) = keymap
            .get(&u.address)
            .ok_or("coin belongs to an unknown address")?;
        let (sig, pk) = {
            let spk = parse_address(&u.address, signer.network())?.script_pubkey();
            let sighash = cache
                .p2wpkh_signature_hash(i, &spk, Amount::from_sat(u.value), EcdsaSighashType::All)
                .map_err(|e| e.to_string())?;
            let (mut sk, pk) = signer.key_at(*chain, *idx)?;
            // The key we derived must really be the one that locks this coin.
            let expected = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
            if expected != spk {
                sk.non_secure_erase();
                return Err("internal check failed: key does not match coin".into());
            }
            let sig = secp.sign_ecdsa(&Message::from(sighash), &sk);
            sk.non_secure_erase();
            (sig, pk)
        };
        let signature = Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::All,
        };
        *cache.witness_mut(i).ok_or("witness slot missing")? = Witness::p2wpkh(&signature, &pk);
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
    banner();
    println!("{}\n", style("Review transaction").bold());
    println!("  {}", style("To").dim());
    println!("  {}\n", style(p.to.to_string()).cyan().bold());
    let mut lines = vec![
        format!(
            "{:<8}{} {unit}",
            "Amount",
            style(fmt_btc(p.amount as i64)).bold()
        ),
        format!("{:<8}{} {unit}", "Fee", fmt_btc(p.fee as i64)),
        format!("{:<8}{:.1} sat/vB, {} coin(s)", "", p.rate, p.inputs.len()),
    ];
    if let Some((_, v)) = &p.change {
        lines.push(format!(
            "{:<8}{} {unit} (back to you)",
            "Change",
            fmt_btc(*v as i64)
        ));
    } else {
        lines.push(format!("{:<8}none", "Change"));
    }
    lines.push(format!(
        "{:<8}{} {unit}",
        "Total",
        style(fmt_btc((p.amount + p.fee) as i64)).yellow().bold()
    ));
    boxed(&lines);
    if pct(p.fee, p.amount) > 5.0 {
        println!(
            "{}",
            style(format!(
                "\n  ⚠ Fee is {:.1}% of the amount.",
                pct(p.fee, p.amount)
            ))
            .yellow()
            .bold()
        );
    }
    println!(
        "\n{}",
        style("  Check the address character by character. Sends cannot be undone.").dim()
    );
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
        let utxos = esplora::utxos_for(net, &addrs)?;
        Ok((utxos, keymap, esplora::fee_rates(net).ok()))
    })?;
    let (utxos, keymap, rates) = loaded;
    if utxos.is_empty() {
        return Err("No confirmed coins found. Wait for confirmations, then Refresh.".into());
    }

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
        esplora::verify_prevouts(net, &p.inputs)
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
    let signer = Signer::from_mnemonic(&opened.mnemonic, network)?;
    drop(opened);
    if signer.account_xpub()? != watch.xpub_string() {
        return Err("Keys do not match this wallet session. Nothing was sent.".into());
    }

    let mut tx = build_tx(&p);
    sign(&mut tx, &p, &signer, &keymap)?;
    drop(signer);
    if p.fee < tx.vsize() as u64 {
        return Err("Fee is below the 1 sat/vB relay minimum. Nothing was sent.".into());
    }
    let txid = tx.compute_txid().to_string();
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);

    match spin("Broadcasting…", || esplora::broadcast(net, &hex)) {
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
        Err(e) => Err(format!("Not sent: {e}")),
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
}
