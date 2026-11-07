//! Offline signer: build -> verify -> sign -> broadcast a BIP174 PSBT, over
//! files or QR frames.
//!
//! `--create-psbt` and `--broadcast` run on the online (watch-only) machine.
//! `--offline` never touches the network: it verifies the PSBT, shows what is
//! being spent, asks for `SEND`, then signs with keys derived from the seed.

use crate::esplora;
use crate::qr;
use crate::send;
use crate::ui::{banner, boxed, fmt_btc, menu, ok, pause, spin};
use crate::wallet::{coin_type, Signer, Watch};
use crate::NETWORK;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, CompressedPublicKey, ScriptBuf};
use console::style;
use dialoguer::Input;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const TYPICAL_VBYTES: u64 = 141; // 1 input + 2 outputs, for fee previews

fn fee_for(rate: f64, vbytes: u64) -> u64 {
    (rate * vbytes as f64).ceil() as u64
}

// ---------- online: create the unsigned PSBT ----------

pub fn create_psbt(wallet: Option<String>, out: Option<String>) -> Result<(), String> {
    banner();
    println!("{}\n", style("Create PSBT (online, watch-only)").bold());
    let name = crate::choose_wallet(wallet.as_deref())?;
    let (mnemonic, fp) = crate::unlock_wallet(&name)?;
    let watch = Watch::from_mnemonic(&mnemonic, NETWORK)?;
    drop(mnemonic);

    let state = spin("Syncing with network…", || {
        esplora::sync(&watch, esplora::FULL_GAP, None)
    })?;
    if state.confirmed <= 0 {
        return Err(
            "No confirmed funds to send yet. Wait for confirmations, then try again.".into(),
        );
    }
    println!(
        "Available (confirmed): {} tBTC\n",
        style(fmt_btc(state.confirmed)).green()
    );

    let to = prompt_recipient()?;
    let amount = prompt_amount()?;

    let keymap = send::keymap(&watch, &state)?;
    let addrs: Vec<String> = state
        .used
        .iter()
        .filter(|a| keymap.contains_key(*a))
        .cloned()
        .collect();
    let (utxos, rates) = spin("Loading your coins and fees…", || {
        Ok::<_, String>((esplora::utxos_for(&addrs)?, esplora::fee_rates().ok()))
    })?;
    if utxos.is_empty() {
        return Err("No confirmed coins found. Wait for confirmations, then Refresh.".into());
    }

    let rate = prompt_rate(rates)?;
    let change_addr = send::parse_address(&watch.address_at(1, state.next_change)?)?;
    let plan = send::plan(utxos, to, amount, rate, change_addr)?;

    // Same invariant as the online send flow: the numbers must add up exactly.
    let total_in: u64 = plan.inputs.iter().map(|u| u.value).sum();
    let change_v = plan.change.as_ref().map(|c| c.1).unwrap_or(0);
    if total_in != plan.amount + plan.fee + change_v {
        return Err("internal error: amounts do not add up. Nothing was created.".into());
    }

    send::review(&plan);
    if !confirm(
        "Type CREATE to save the unsigned transaction (anything else cancels)",
        "CREATE",
    )? {
        println!("\nCancelled. Nothing was created.");
        pause();
        return Ok(());
    }

    let master_fp: Fingerprint = fp
        .parse()
        .map_err(|_| "invalid wallet fingerprint".to_string())?;
    let psbt = send::build_psbt(&plan, &watch, &keymap, master_fp)?;
    let path = out.unwrap_or_else(|| format!("{name}-unsigned.psbt"));
    write_psbt(&path, &psbt)?;

    banner();
    ok("Unsigned PSBT created");
    println!("\n  File: {}", style(&path).cyan());
    println!("  TxID: {}", style(psbt.unsigned_tx.compute_txid()).dim());
    println!("\n  Copy it to the offline machine and run:");
    println!("  {}", style(format!("cairn --offline {path}")).bold());
    println!("\n  Or show it as QR for the offline machine:");
    println!("  {}", style(format!("cairn --qr-show {path}")).bold());
    println!(
        "\n{}",
        style("  The offline machine never needs the network.").dim()
    );
    pause();
    Ok(())
}

// ---------- offline: verify and sign ----------

pub fn sign_psbt(input: String, out: Option<String>) -> Result<(), String> {
    banner();
    println!("{}\n", style("Sign PSBT (offline)").bold());
    let mut psbt = read_psbt(&input)?;

    let name = crate::choose_wallet(None)?;
    let (mnemonic, _fp) = crate::unlock_wallet(&name)?;
    let watch = Watch::from_mnemonic(&mnemonic, NETWORK)?;
    let signer = Signer::from_mnemonic(&mnemonic, NETWORK)?;
    drop(mnemonic);

    let verified = verify_psbt(&psbt, &watch, &signer)?;
    show_psbt_review(&verified);
    if !confirm("Type SEND to sign (anything else cancels)", "SEND")? {
        println!("\nCancelled. Nothing was signed.");
        pause();
        return Ok(());
    }

    signer.sign_psbt(&mut psbt)?;
    let tx = psbt
        .clone()
        .extract_tx()
        .map_err(|e| format!("could not finalize transaction: {e}"))?;
    let out_path = out.unwrap_or_else(|| signed_path(&input));
    write_psbt(&out_path, &psbt)?;

    banner();
    ok("PSBT signed and finalized");
    println!("\n  File: {}", style(&out_path).cyan());
    println!("  TxID: {}", style(tx.compute_txid()).dim());
    println!("\n  Carry it back to the online machine and run:");
    println!(
        "  {}",
        style(format!("cairn --broadcast {input} {out_path}")).bold()
    );
    println!("\n  Or carry it back as QR:");
    println!("  {}", style(format!("cairn --qr-show {out_path}")).bold());
    pause();
    Ok(())
}

// ---------- QR transport ----------

pub fn show_qr(path: String) -> Result<(), String> {
    banner();
    println!("{}\n", style("Show PSBT as QR").bold());
    let psbt = read_psbt(&path)?;
    let frames = qr::show(&psbt.serialize())?;
    let _: String = Input::with_theme(&crate::ui::theme())
        .with_prompt("Press Enter when every frame has been captured")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();

    println!("  {}", style(format!("{frames} QR frame(s)")).bold());
    println!("  Scan every frame on the other machine, then rebuild the file:");
    println!(
        "  {}",
        style("cairn --qr-scan --out FILE.psbt <IMAGE>...").bold()
    );
    println!(
        "\n{}",
        style("  QR frames contain the PSBT, never your seed words.").dim()
    );
    Ok(())
}

pub fn scan_qr(images: Vec<String>, out: Option<String>) -> Result<(), String> {
    banner();
    println!("{}\n", style("Read PSBT from QR photos").bold());
    let payloads = spin("Reading QR codes…", || qr::scan_images(&images))?;
    let data = qr::reassemble(&payloads)?;
    let psbt = Psbt::deserialize(&data).map_err(|e| format!("QR data is not a valid PSBT: {e}"))?;
    let path = out.unwrap_or_else(|| "scanned.psbt".into());
    write_psbt(&path, &psbt)?;

    banner();
    ok("PSBT rebuilt from QR");
    println!("\n  File: {}", style(&path).cyan());
    println!("  TxID: {}", style(psbt.unsigned_tx.compute_txid()).dim());
    println!("\n  Next:");
    println!("  {}", style(format!("cairn --offline {path}")).bold());
    println!(
        "  {}",
        style(format!("cairn --broadcast unsigned.psbt {path}")).dim()
    );
    pause();
    Ok(())
}

struct Verified {
    inputs: usize,
    total_in: u64,
    fee: u64,
    change: u64,
    external: Vec<(String, u64)>,
    vsize_est: u64,
}

/// Check that a PSBT really spends our coins, pays who it says and has a sane fee.
///
/// The value of each coin comes from the PSBT itself: an offline machine cannot
/// independently look up UTXOs. Everything else (ownership of the inputs, the
/// script each key locks, the outputs and the arithmetic) is checked here.
fn verify_psbt(psbt: &Psbt, watch: &Watch, signer: &Signer) -> Result<Verified, String> {
    let tx = &psbt.unsigned_tx;
    if psbt.inputs.len() != tx.input.len() || psbt.outputs.len() != tx.output.len() {
        return Err("malformed PSBT: input/output counts do not match the transaction".into());
    }

    let master_fp = signer.fingerprint();
    let mut total_in = 0u64;
    for (i, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
            return Err(format!("input {i} is not unsigned"));
        }
        if !input.partial_sigs.is_empty()
            || input.final_script_witness.is_some()
            || input.final_script_sig.is_some()
        {
            return Err("this PSBT is already signed".into());
        }
        if !matches!(input.ecdsa_hash_ty(), Ok(bitcoin::EcdsaSighashType::All)) {
            return Err(format!("input {i} does not use SIGHASH_ALL"));
        }
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {i} has no witness UTXO"))?;
        if !utxo.script_pubkey.is_p2wpkh() {
            return Err(format!("input {i} is not a native SegWit P2WPKH output"));
        }
        if input.bip32_derivation.len() != 1 {
            return Err(format!("input {i} must have exactly one BIP32 key origin"));
        }
        let (pubkey, (fp, path)) = input.bip32_derivation.iter().next().unwrap();
        if *fp != master_fp {
            return Err("PSBT belongs to a different wallet (fingerprint mismatch)".into());
        }
        let (chain, index) = parse_path(path)
            .ok_or_else(|| format!("input {i} has an unexpected derivation path"))?;
        let expected_script = ScriptBuf::new_p2wpkh(&CompressedPublicKey(*pubkey).wpubkey_hash());
        if expected_script != utxo.script_pubkey {
            return Err(format!("input {i}: key does not match the coin's script"));
        }
        let (_, derived_pubkey) = signer.key_at(chain, index)?;
        if derived_pubkey != *pubkey {
            return Err(format!("input {i}: key does not match this wallet"));
        }
        total_in = total_in
            .checked_add(utxo.value.to_sat())
            .ok_or("amount overflow")?;
    }

    let ours = our_scripts(watch)?;
    let mut total_out = 0u64;
    let mut change = 0u64;
    let mut external = vec![];
    for output in &tx.output {
        let sats = output.value.to_sat();
        total_out = total_out.checked_add(sats).ok_or("amount overflow")?;
        let addr = Address::from_script(&output.script_pubkey, NETWORK)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| format!("script:{}", output.script_pubkey));
        if ours.contains(&output.script_pubkey) {
            change = change.checked_add(sats).ok_or("amount overflow")?;
        } else {
            external.push((addr, sats));
        }
    }

    let fee = total_in
        .checked_sub(total_out)
        .ok_or("PSBT spends more than its inputs")?;
    // Conservative lower bound on relay fee; the real vsize is checked after signing.
    let vsize_est = 11 + 68 * psbt.inputs.len() as u64 + 31 * tx.output.len() as u64;
    if fee < vsize_est {
        return Err(format!(
            "fee of {fee} sats is below the 1 sat/vB relay minimum (about {vsize_est} needed)"
        ));
    }

    Ok(Verified {
        inputs: psbt.inputs.len(),
        total_in,
        fee,
        change,
        external,
        vsize_est,
    })
}

fn show_psbt_review(v: &Verified) {
    banner();
    println!("{}\n", style("Review PSBT").bold());
    if v.external.is_empty() {
        println!(
            "{}",
            style("  No external outputs: the whole amount returns to this wallet.").yellow()
        );
    } else {
        for (addr, sats) in &v.external {
            println!("  {:<8}{} tBTC", "To", style(fmt_btc(*sats as i64)).bold());
            println!("  {}\n", style(addr).cyan().bold());
        }
    }
    let spending = v.total_in.saturating_sub(v.change);
    let lines = vec![
        format!("{:<8}{} tBTC", "Inputs", fmt_btc(v.total_in as i64)),
        format!("{:<8}{} tBTC", "Fee", fmt_btc(v.fee as i64)),
        format!(
            "{:<8}{} tBTC (back to you)",
            "Change",
            fmt_btc(v.change as i64)
        ),
        format!(
            "{:<8}{} tBTC",
            "Spending",
            style(fmt_btc(spending as i64)).yellow().bold()
        ),
        format!(
            "{:<8}{} input(s), ~{:.1} sat/vB",
            "",
            v.inputs,
            v.fee as f64 / v.vsize_est as f64
        ),
    ];
    boxed(&lines);
    println!(
        "\n{}",
        style(
            "  Input values come from the PSBT; compare them with what the online wallet showed."
        )
        .dim()
    );
    println!(
        "{}",
        style("  Check the destination address character by character.").dim()
    );
}

// ---------- online: broadcast the signed PSBT ----------

pub fn broadcast(unsigned_path: String, signed_path: String) -> Result<(), String> {
    banner();
    println!("{}\n", style("Broadcast signed PSBT (online)").bold());
    let unsigned = read_psbt(&unsigned_path)?;
    let signed = read_psbt(&signed_path)?;
    ensure_same_unsigned(&unsigned, &signed)?;
    if signed
        .inputs
        .iter()
        .any(|i| i.final_script_witness.is_none() && i.final_script_sig.is_none())
    {
        return Err("signed PSBT is missing finalized inputs".into());
    }

    let fee = signed
        .fee()
        .map_err(|e| format!("cannot compute fee: {e}"))?
        .to_sat();
    let tx = signed
        .clone()
        .extract_tx()
        .map_err(|e| format!("invalid signed transaction: {e}"))?;
    if tx.compute_txid() != unsigned.unsigned_tx.compute_txid() {
        return Err("signed transaction does not match the unsigned transaction".into());
    }

    banner();
    println!("{}\n", style("Review signed transaction").bold());
    for output in &tx.output {
        let addr = Address::from_script(&output.script_pubkey, NETWORK)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| format!("script:{}", output.script_pubkey));
        println!(
            "  {:<8}{} tBTC",
            "To",
            style(fmt_btc(output.value.to_sat() as i64)).bold()
        );
        println!("  {}\n", style(addr).cyan().bold());
    }
    boxed(&[
        format!("{:<8}{} tBTC", "Fee", fmt_btc(fee as i64)),
        format!("{:<8}{}", "TxID", tx.compute_txid()),
    ]);
    if !confirm("Type SEND to broadcast (anything else cancels)", "SEND")? {
        println!("\nCancelled. Nothing was sent.");
        pause();
        return Ok(());
    }

    let hex = bitcoin::consensus::encode::serialize_hex(&tx);
    match spin("Broadcasting…", || esplora::broadcast(&hex)) {
        Ok(server_txid) => {
            banner();
            ok("Transaction sent");
            println!("\n  {}", style("Transaction ID").dim());
            println!("  {}\n", style(tx.compute_txid()).cyan());
            if server_txid != tx.compute_txid().to_string() {
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
            Ok(())
        }
        Err(e) => Err(format!("Not sent: {e}")),
    }
}

/// The offline machine must not be able to change what the online machine planned.
fn ensure_same_unsigned(unsigned: &Psbt, signed: &Psbt) -> Result<(), String> {
    if unsigned.unsigned_tx != signed.unsigned_tx {
        return Err("signed PSBT does not match the unsigned PSBT. Nothing was sent.".into());
    }
    if unsigned.inputs.len() != signed.inputs.len() {
        return Err("signed PSBT has a different number of inputs. Nothing was sent.".into());
    }
    for (i, (u, s)) in unsigned.inputs.iter().zip(&signed.inputs).enumerate() {
        if u.witness_utxo != s.witness_utxo
            || u.non_witness_utxo != s.non_witness_utxo
            || u.bip32_derivation != s.bip32_derivation
            || u.sighash_type != s.sighash_type
        {
            return Err(format!("signed PSBT changed input {i}. Nothing was sent."));
        }
    }
    Ok(())
}

// ---------- helpers ----------

/// `m/84'/coin'/0'/chain/index` -> (chain, index), rejecting anything else.
fn parse_path(path: &DerivationPath) -> Option<(u32, u32)> {
    let parts: Vec<&ChildNumber> = path.into_iter().collect();
    match parts.as_slice() {
        [ChildNumber::Hardened { index: 84 }, ChildNumber::Hardened { index: coin }, ChildNumber::Hardened { index: 0 }, ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }]
            if *coin == coin_type(NETWORK) && *chain <= 1 =>
        {
            Some((*chain, *index))
        }
        _ => None,
    }
}

fn our_scripts(watch: &Watch) -> Result<HashSet<ScriptBuf>, String> {
    let mut set = HashSet::new();
    // Address scans stop around MAX_INDEX, so look a little past it for change.
    let count = esplora::MAX_INDEX + 16;
    for chain in 0..2 {
        for addr in watch.addresses(chain, 0, count)? {
            set.insert(send::parse_address(&addr)?.script_pubkey());
        }
    }
    Ok(set)
}

fn prompt_recipient() -> Result<Address, String> {
    let s: String = Input::with_theme(&crate::ui::theme())
        .with_prompt("Recipient address")
        .validate_with(|s: &String| -> Result<(), String> { send::parse_address(s).map(|_| ()) })
        .interact_text()
        .map_err(|e| e.to_string())?;
    send::parse_address(&s)
}

fn prompt_amount() -> Result<Option<u64>, String> {
    let s: String = Input::with_theme(&crate::ui::theme())
        .with_prompt("Amount (e.g. 0.0005, 50000 sats, or max)")
        .validate_with(|s: &String| -> Result<(), String> { send::parse_amount(s).map(|_| ()) })
        .interact_text()
        .map_err(|e| e.to_string())?;
    send::parse_amount(&s)
}

fn prompt_rate(rates: Option<esplora::Rates>) -> Result<f64, String> {
    match rates {
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
                0 => Ok(r.slow),
                1 => Ok(r.normal),
                _ => Ok(r.fast),
            }
        }
        None => Input::with_theme(&crate::ui::theme())
            .with_prompt("Fee rate in sat/vB (estimates unavailable)")
            .default(2.0f64)
            .validate_with(|v: &f64| -> Result<(), &str> {
                if *v >= 1.0 && *v <= 1000.0 {
                    Ok(())
                } else {
                    Err("Enter a value from 1 to 1000")
                }
            })
            .interact_text()
            .map_err(|e| e.to_string()),
    }
}

fn confirm(prompt: &str, word: &str) -> Result<bool, String> {
    let answer: String = Input::with_theme(&crate::ui::theme())
        .with_prompt(prompt)
        .allow_empty(true)
        .interact_text()
        .map_err(|e| e.to_string())?;
    Ok(answer.trim() == word)
}

fn read_psbt(path: &str) -> Result<Psbt, String> {
    let data = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if let Ok(psbt) = Psbt::deserialize(&data) {
        return Ok(psbt);
    }
    let text = std::str::from_utf8(&data).map_err(|_| format!("{path} is not a PSBT"))?;
    let bytes = hex::decode(text.trim())
        .map_err(|_| format!("{path} is not a PSBT (binary or hex expected)"))?;
    Psbt::deserialize(&bytes).map_err(|e| format!("invalid PSBT in {path}: {e}"))
}

fn write_psbt(path: &str, psbt: &Psbt) -> Result<(), String> {
    fs::write(path, psbt.serialize()).map_err(|e| format!("cannot write {path}: {e}"))
}

fn signed_path(input: &str) -> String {
    let p = Path::new(input);
    let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("signed");
    p.with_file_name(format!("{name}-signed.psbt"))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esplora::{Utxo, WalletState};
    use crate::send::{build_psbt, keymap, plan};
    use bip39::Mnemonic;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, Txid};

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn fixture() -> (Psbt, Watch, Signer) {
        let m = Mnemonic::parse(ABANDON).unwrap();
        let watch = Watch::from_mnemonic(&m, NETWORK).unwrap();
        let signer = Signer::from_mnemonic(&m, NETWORK).unwrap();
        let a0 = watch.address_at(0, 0).unwrap();
        let other = Mnemonic::from_entropy(&[9u8; 32]).unwrap();
        let other_watch = Watch::from_mnemonic(&other, NETWORK).unwrap();
        let to = send::parse_address(&other_watch.address_at(0, 0).unwrap()).unwrap();
        let change = send::parse_address(&watch.address_at(1, 0).unwrap()).unwrap();
        let utxo = Utxo {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
            value: 100_000,
            address: a0.clone(),
        };
        let p = plan(vec![utxo], to, Some(30_000), 2.0, change).unwrap();
        let state = WalletState {
            used: vec![a0],
            next_receive: 1,
            next_change: 1,
            ..Default::default()
        };
        let km = keymap(&watch, &state).unwrap();
        let psbt = build_psbt(&p, &watch, &km, signer.fingerprint()).unwrap();
        (psbt, watch, signer)
    }

    #[test]
    fn verifies_and_signs_our_psbt() {
        let (psbt, watch, signer) = fixture();
        let v = verify_psbt(&psbt, &watch, &signer).unwrap();
        assert_eq!(v.external.len(), 1);
        assert_eq!(v.external[0].1, 30_000);
        assert_eq!(v.change, 100_000 - 30_000 - v.fee);

        let mut signed = psbt;
        signer.sign_psbt(&mut signed).unwrap();
        assert!(signed.inputs[0].final_script_witness.is_some());
        let tx = signed.extract_tx().unwrap();
        assert_eq!(tx.input[0].witness.len(), 2);
    }

    #[test]
    fn rejects_wrong_wallet_and_low_fee() {
        let (psbt, watch, _signer) = fixture();
        let other = Mnemonic::from_entropy(&[9u8; 32]).unwrap();
        let other_signer = Signer::from_mnemonic(&other, NETWORK).unwrap();
        assert!(verify_psbt(&psbt, &watch, &other_signer).is_err());

        let (mut low, watch2, signer2) = fixture();
        let fee = verify_psbt(&low, &watch2, &signer2).unwrap().fee;
        let first = low.unsigned_tx.output[0].value.to_sat() + fee;
        low.unsigned_tx.output[0].value = Amount::from_sat(first);
        assert!(verify_psbt(&low, &watch2, &signer2).is_err());
    }

    #[test]
    fn rejects_non_all_sighash() {
        let (mut psbt, watch, signer) = fixture();
        psbt.inputs[0].sighash_type = Some(bitcoin::EcdsaSighashType::None.into());
        assert!(verify_psbt(&psbt, &watch, &signer).is_err());
    }

    #[test]
    fn rejects_altered_signed_copy() {
        let (unsigned, _watch, signer) = fixture();
        let mut signed = unsigned.clone();
        signer.sign_psbt(&mut signed).unwrap();
        ensure_same_unsigned(&unsigned, &signed).unwrap();

        signed.unsigned_tx.output[0].value =
            Amount::from_sat(signed.unsigned_tx.output[0].value.to_sat() + 1);
        assert!(ensure_same_unsigned(&unsigned, &signed).is_err());
    }

    #[test]
    fn psbt_file_roundtrip_binary_and_hex() {
        let (psbt, _watch, _signer) = fixture();
        let dir = std::env::temp_dir().join(format!("cairn-psbt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let bin = dir.join("a.psbt");
        write_psbt(bin.to_str().unwrap(), &psbt).unwrap();
        assert_eq!(
            read_psbt(bin.to_str().unwrap()).unwrap().unsigned_tx,
            psbt.unsigned_tx
        );

        let hex_path = dir.join("a.hex");
        fs::write(&hex_path, psbt.serialize_hex()).unwrap();
        assert_eq!(
            read_psbt(hex_path.to_str().unwrap()).unwrap().unsigned_tx,
            psbt.unsigned_tx
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn derivation_paths_are_strict() {
        let good: DerivationPath = "m/84'/1'/0'/0/7".parse().unwrap();
        assert_eq!(parse_path(&good), Some((0, 7)));
        let mainnet: DerivationPath = "m/84'/0'/0'/0/7".parse().unwrap();
        assert_eq!(parse_path(&mainnet), None);
        let wrong_purpose: DerivationPath = "m/44'/1'/0'/0/7".parse().unwrap();
        assert_eq!(parse_path(&wrong_purpose), None);
    }
}
