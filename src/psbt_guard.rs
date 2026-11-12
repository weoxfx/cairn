//! Wallet-independent PSBT structure checks.
//!
//! This module is shared by the offline verifier and the fuzz target. It checks
//! parsing-adjacent invariants and the sat arithmetic without needing keys, so
//! the same code can be exercised on arbitrary bytes.

use crate::network;
use bitcoin::psbt::Psbt;
use bitcoin::EcdsaSighashType;
use std::collections::HashSet;

/// A review screen must stay reviewable. Real transactions are far smaller;
/// this also bounds the work done on an untrusted PSBT.
pub const MAX_PSBT_INPUTS: usize = 500;
pub const MAX_PSBT_OUTPUTS: usize = 500;

/// Check structure, signedness, previous-transaction consistency and amounts.
/// Returns `(total_in, total_out)` in sats. Ownership, scripts and keys are
/// checked by the caller.
pub fn check_structure(psbt: &Psbt) -> Result<(u64, u64), String> {
    let tx = &psbt.unsigned_tx;
    if psbt.inputs.len() != tx.input.len() || psbt.outputs.len() != tx.output.len() {
        return Err("malformed PSBT: input/output counts do not match the transaction".into());
    }
    if tx.input.len() > MAX_PSBT_INPUTS {
        return Err(format!(
            "PSBT has too many inputs ({}; limit {MAX_PSBT_INPUTS})",
            tx.input.len()
        ));
    }
    if tx.output.len() > MAX_PSBT_OUTPUTS {
        return Err(format!(
            "PSBT has too many outputs ({}; limit {MAX_PSBT_OUTPUTS})",
            tx.output.len()
        ));
    }

    let mut total_in = 0u64;
    let mut outpoints = HashSet::new();
    for (i, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        if !outpoints.insert(txin.previous_output) {
            return Err(format!("input {i} repeats an outpoint"));
        }
        if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
            return Err(format!("input {i} is not unsigned"));
        }
        if !input.partial_sigs.is_empty()
            || input.final_script_witness.is_some()
            || input.final_script_sig.is_some()
        {
            return Err("this PSBT is already signed".into());
        }
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {i} has no witness UTXO"))?;
        if utxo.script_pubkey.is_p2tr() {
            // BIP371 taproot input: one key-path origin and an internal key.
            if input.tap_key_origins.len() != 1 {
                return Err(format!(
                    "input {i} must have exactly one taproot key origin"
                ));
            }
            if input.tap_internal_key.is_none() {
                return Err(format!("input {i} has no taproot internal key"));
            }
            let (_xonly, (leaves, _)) = input.tap_key_origins.iter().next().unwrap();
            if !leaves.is_empty() {
                return Err(format!(
                    "input {i} spends a taproot script path, which Cairn cannot sign"
                ));
            }
        } else {
            if !matches!(input.ecdsa_hash_ty(), Ok(EcdsaSighashType::All)) {
                return Err(format!("input {i} does not use SIGHASH_ALL"));
            }
            if input.bip32_derivation.len() != 1 {
                return Err(format!("input {i} must have exactly one BIP32 key origin"));
            }
        }
        if utxo.value.to_sat() > network::MAX_MONEY_SATS {
            return Err(format!("input {i} value exceeds the 21 million BTC supply"));
        }
        // If the full previous transaction is supplied, it must describe the
        // same output as the witness UTXO.
        if let Some(prev) = &input.non_witness_utxo {
            if prev.compute_txid() != txin.previous_output.txid {
                return Err(format!(
                    "input {i}: previous transaction does not match the outpoint"
                ));
            }
            let out = prev
                .output
                .get(txin.previous_output.vout as usize)
                .ok_or_else(|| format!("input {i}: previous transaction has no such output"))?;
            if out.value != utxo.value || out.script_pubkey != utxo.script_pubkey {
                return Err(format!(
                    "input {i}: previous transaction disagrees with the witness UTXO"
                ));
            }
        }
        total_in = total_in
            .checked_add(utxo.value.to_sat())
            .ok_or("amount overflow")?;
        if total_in > network::MAX_MONEY_SATS {
            return Err("PSBT input total exceeds the 21 million BTC supply".into());
        }
    }

    let mut total_out = 0u64;
    for output in &tx.output {
        let sats = output.value.to_sat();
        if sats > network::MAX_MONEY_SATS {
            return Err("PSBT output exceeds the 21 million BTC supply".into());
        }
        total_out = total_out.checked_add(sats).ok_or("amount overflow")?;
        if total_out > network::MAX_MONEY_SATS {
            return Err("PSBT output total exceeds the 21 million BTC supply".into());
        }
    }
    if total_out > total_in {
        return Err("PSBT spends more than its inputs".into());
    }
    Ok((total_in, total_out))
}

/// Fuzzing entry point. Enabled only by the `fuzzing` feature.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_psbt(data: &[u8]) {
    if let Ok(psbt) = Psbt::deserialize(data) {
        if check_structure(&psbt).is_ok() {
            let bytes = psbt.serialize();
            let again = Psbt::deserialize(&bytes).expect("serialized PSBT must parse");
            assert_eq!(again.unsigned_tx, psbt.unsigned_tx);
            assert!(check_structure(&again).is_ok());
        }
    }
}
