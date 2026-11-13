#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The RLP reader walks signed transaction files and node replies; lengths
    // and nesting are attacker-controlled.
    cairn::evm::tx::fuzz_rlp(data);
});
