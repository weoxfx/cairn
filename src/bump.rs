//! Replace-by-fee (RBF) fee bumping for one of our own unconfirmed sends.
//!
//! The replacement keeps the original inputs and the original payment output
//! and takes the higher fee out of our change. Everything is re-derived from the
//! fetched transaction and re-checked against the wallet's own key map, so a
//! server cannot steer the bump at someone else's coins or a different
//! recipient. The same fee ceiling and rate ceiling as a normal send apply.

use crate::esplora::{self, WalletState};
use crate::network;
use crate::send::{self, Plan};
use crate::ui::{self, banner, fmt_btc, menu_titled, pause, short, spin, theme};
use crate::wallet::{Signer, Watch};
use bitcoin::Address;
use console::style;
use dialoguer::Input;

/// P2WPKH dust threshold, the same value the send flow uses.
const DUST: u64 = 294;
/// Signatures vary by a byte, so the change output may need adjusting after
/// signing to still hit the requested fee.
const MAX_ADJUST: usize = 4;
/// Nodes want the replacement to pay a strictly higher rate, not just a higher
/// absolute fee.
const MIN_RATE_INCREASE: f64 = 0.5;

#[derive(Debug)]
pub(crate) struct Bump {
    /// Fee for the replacement transaction.
    pub fee: u64,
    /// New value of our change output.
    pub change: u64,
    /// Requested fee rate.
    pub rate: f64,
    /// Extra fee paid compared with the original transaction.
    pub delta: u64,
}

/// Pure bump arithmetic, kept separate so it can be tested without a network.
pub(crate) fn plan_bump(
    old_fee: u64,
    old_vsize: u64,
    change: u64,
    target_rate: f64,
) -> Result<Bump, String> {
    if old_vsize == 0 {
        return Err("cannot bump a transaction with no size".into());
    }
    if !target_rate.is_finite() || target_rate <= 0.0 {
        return Err("Enter a positive fee rate".into());
    }
    if target_rate > network::MAX_FEE_RATE {
        return Err(format!(
            "fee rate is above the {:.0} sat/vB ceiling",
            network::MAX_FEE_RATE
        ));
    }
    let old_rate = old_fee as f64 / old_vsize as f64;
    if target_rate < old_rate + MIN_RATE_INCREASE {
        return Err(format!(
            "A replacement must pay a higher rate: use at least {:.1} sat/vB",
            old_rate + MIN_RATE_INCREASE
        ));
    }
    let fee = (target_rate * old_vsize as f64).ceil() as u64;
    if fee <= old_fee {
        return Err("The replacement fee must be higher than the original".into());
    }
    let delta = fee - old_fee;
    if change < delta + DUST {
        return Err(format!(
            "Not enough change: paying {} sats more would leave less than the {} sat dust limit",
            delta, DUST
        ));
    }
    Ok(Bump {
        fee,
        change: change - delta,
        rate: target_rate,
        delta,
    })
}

fn total_out(outputs: &[bitcoin::TxOut]) -> Result<u64, String> {
    outputs
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value.to_sat()))
        .ok_or_else(|| "output total overflows".to_string())
}

/// Returns Ok(true) when a replacement was broadcast.
pub fn bump_flow(name: &str, fp: &str, watch: &Watch, state: &WalletState) -> Result<bool, String> {
    let network = watch.network();
    let net = esplora::net_for(network)?;
    let unit = network::unit(network);
    banner();
    println!(
        "{}\n",
        style(format!("Bump fee ({})", network::label(network))).bold()
    );

    let keymap = send::keymap(watch, state)?;
    let history = spin("Looking for pending transactions…", || {
        esplora::transactions(net, state)
    })?;
    let pending: Vec<&esplora::TxSummary> = history
        .iter()
        .filter(|t| t.height.is_none() && t.net < 0)
        .collect();
    if pending.is_empty() {
        return Err(
            "No unconfirmed outgoing transaction to bump. Refresh first if you just sent one."
                .into(),
        );
    }

    let labels: Vec<String> = pending
        .iter()
        .map(|t| format!("{}…  −{} {}", short(&t.txid), fmt_btc(-t.net), unit))
        .collect();
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let pick = if pending.len() == 1 {
        ui::info(&format!("One pending payment: {}", labels[0]));
        0
    } else {
        menu_titled("Which payment should be bumped?", &refs)?
    };
    let target = pending[pick];

    let prev = spin("Loading the transaction…", || {
        esplora::full_tx(net, &target.txid)
    })?;
    if prev.confirmed {
        return Err("That transaction is already confirmed and cannot be replaced.".into());
    }
    if prev.txid.to_string() != target.txid {
        return Err("Server returned a different transaction than requested".into());
    }

    // Classify outputs. We need exactly one payment and at most one change.
    let mut payment: Option<(Address, u64)> = None;
    let mut change: Option<(Address, u64)> = None;
    for o in &prev.outputs {
        let Some(addr_str) = &o.address else {
            return Err(
                "The transaction has a non-standard output; refusing to replace it.".into(),
            );
        };
        let addr = send::parse_address(addr_str, network)?;
        if keymap.contains_key(addr_str) {
            if change.is_some() {
                return Err(
                    "The transaction has more than one change output; replace it manually.".into(),
                );
            }
            change = Some((addr, o.value));
        } else {
            if payment.is_some() {
                return Err(
                    "Only payments with a single recipient can be bumped from this screen.".into(),
                );
            }
            payment = Some((addr, o.value));
        }
    }
    let (to, amount) = payment.ok_or("That transaction has no payment output")?;
    let (change_addr, change_value) = change.ok_or(
        "That transaction has no change output, so there is nothing to pay the higher fee from.",
    )?;

    // Every input must belong to this wallet, or we cannot re-sign it.
    for u in &prev.inputs {
        if !keymap.contains_key(&u.address) {
            return Err(
                "That transaction spends coins outside this wallet; it cannot be replaced here."
                    .into(),
            );
        }
    }

    let total_in = prev
        .inputs
        .iter()
        .try_fold(0u64, |a, u| a.checked_add(u.value))
        .ok_or("input total overflows")?;
    let old_fee = total_in
        .checked_sub(
            prev.outputs
                .iter()
                .try_fold(0u64, |a, o| a.checked_add(o.value))
                .ok_or("output total overflows")?,
        )
        .ok_or("server data does not add up")?;
    let old_rate = old_fee as f64 / prev.vsize as f64;

    println!();
    ui::kv(
        "Payment",
        &format!("{} {} to {}", fmt_btc(amount as i64), unit, to),
    );
    ui::kv(
        "Current fee",
        &format!(
            "{} {}  ({:.1} sat/vB, {} vB)",
            fmt_btc(old_fee as i64),
            unit,
            old_rate,
            prev.vsize
        ),
    );
    ui::kv(
        "Change",
        &format!("{} {}", fmt_btc(change_value as i64), unit),
    );
    println!();

    let default_rate = (old_rate + 2.0).min(network::MAX_FEE_RATE);
    let rate_str: String = Input::with_theme(&theme())
        .with_prompt("New fee rate (sat/vB)")
        .default(format!("{default_rate:.1}"))
        .interact_text()
        .map_err(|e| e.to_string())?;
    let target_rate: f64 = rate_str
        .trim()
        .parse()
        .map_err(|_| "Enter a fee rate in sat/vB".to_string())?;
    let bump = plan_bump(old_fee, prev.vsize, change_value, target_rate)?;

    let plan = |change_now: u64, fee: u64| Plan {
        inputs: prev.inputs.clone(),
        to: to.clone(),
        amount,
        fee,
        change: Some((change_addr.clone(), change_now)),
        rate: bump.rate,
    };
    send::review(&plan(bump.change, bump.fee), network);
    println!();
    ui::kv(
        "Extra fee",
        &format!(
            "+{} {}  ({old_rate:.1} → {:.1} sat/vB)",
            fmt_btc(bump.delta as i64),
            unit,
            bump.rate
        ),
    );
    println!();
    ui::warn("The payment is unchanged; the extra fee comes out of your change.");

    let confirm: String = Input::with_theme(&theme())
        .with_prompt("Type SEND to broadcast the replacement")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| e.to_string())?;
    if confirm.trim() != "SEND" {
        println!("\nCancelled. Nothing was replaced.");
        pause();
        return Ok(false);
    }

    let opened = crate::unlock_wallet_with(name, Some(fp), "Password to sign")?;
    if opened.network != network {
        return Err("Wallet network changed. Nothing was replaced.".into());
    }
    let signer = Signer::from_opened(&opened)?;
    drop(opened);
    if signer.account_xpub()? != watch.xpub_string() {
        return Err("Keys do not match this wallet session. Nothing was replaced.".into());
    }

    // Sign, then confirm the realised fee really is at least the target. Every
    // signature byte can shift the size by a vB, so the change is adjusted.
    let mut change_now = bump.change;
    let mut signed: Option<bitcoin::Transaction> = None;
    for _ in 0..MAX_ADJUST {
        if change_now < DUST {
            return Err("Not enough change left to reach that fee rate".into());
        }
        let p = plan(change_now, bump.fee);
        let mut tx = send::build_tx(&p);
        send::sign(&mut tx, &p, &signer, &keymap)?;
        let fee = total_in
            .checked_sub(total_out(&tx.output)?)
            .ok_or("replacement does not add up")?;
        if fee >= bump.fee {
            send::check_fee(fee, amount)?;
            send::check_fee_rate(fee, tx.vsize() as u64)?;
            if fee <= old_fee {
                return Err("The replacement fee is not higher than the original".into());
            }
            let new_rate = fee as f64 / tx.vsize() as f64;
            if new_rate < old_rate + MIN_RATE_INCREASE {
                return Err(
                    "The replacement fee rate is too close to the original; nodes may reject it"
                        .into(),
                );
            }
            signed = Some(tx);
            break;
        }
        let gap = bump.fee - fee;
        if change_now < gap + DUST {
            return Err("Not enough change to reach that fee rate".into());
        }
        change_now -= gap;
    }
    let tx = signed.ok_or("Could not settle on a fee; nothing was replaced")?;
    drop(signer);

    let txid = tx.compute_txid().to_string();
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);
    match spin("Broadcasting the replacement…", || {
        esplora::broadcast(net, &hex)
    }) {
        Ok(server_txid) => {
            banner();
            ui::ok("Replacement broadcast");
            println!("\n  {}\n", style(&txid).cyan());
            if server_txid != txid {
                ui::warn(&format!("Server reported a different id: {server_txid}"));
            }
            println!("  It replaces the earlier transaction once a miner takes it.\n");
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

    #[test]
    fn requested_rate_is_met_and_paid_from_change() {
        // 200 vB at 5 sat/vB = 1,000 sats, change 10,000.
        let b = plan_bump(1_000, 200, 10_000, 10.0).unwrap();
        assert_eq!(b.fee, 2_000);
        assert_eq!(b.delta, 1_000);
        assert_eq!(b.change, 9_000);
    }

    #[test]
    fn rate_must_increase() {
        let err = plan_bump(1_000, 200, 10_000, 5.0).unwrap_err();
        assert!(err.contains("higher rate"), "{err}");
        assert!(plan_bump(1_000, 200, 10_000, 5.4).is_err());
        assert!(plan_bump(1_000, 200, 10_000, 5.6).is_ok());
    }

    #[test]
    fn change_must_cover_the_extra_fee_and_dust() {
        // Only 1,000 sats of change: a 1,000 sat increase leaves nothing for dust.
        let err = plan_bump(1_000, 200, 1_000, 10.0).unwrap_err();
        assert!(err.contains("dust"), "{err}");
        assert!(plan_bump(1_000, 200, 1_294, 10.0).is_ok());
        assert!(plan_bump(1_000, 200, 1_293, 10.0).is_err());
    }

    #[test]
    fn ceiling_and_nonsense_are_rejected() {
        assert!(plan_bump(1_000, 200, 1_000_000, network::MAX_FEE_RATE + 1.0).is_err());
        assert!(plan_bump(1_000, 200, 10_000, 0.0).is_err());
        assert!(plan_bump(1_000, 200, 10_000, f64::NAN).is_err());
        assert!(plan_bump(1_000, 0, 10_000, 10.0).is_err());
    }

    #[test]
    fn huge_values_do_not_overflow() {
        // A 1 BTC fee on a very large transaction with change near the supply
        // cap: the arithmetic must stay exact.
        let b = plan_bump(100_000_000, 400_000, network::MAX_MONEY_SATS, 300.0).unwrap();
        assert_eq!(b.fee, 120_000_000);
        assert_eq!(b.delta, 20_000_000);
        assert_eq!(b.change, network::MAX_MONEY_SATS - 20_000_000);
    }
}
