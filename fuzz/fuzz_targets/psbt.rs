#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    cairn::psbt_guard::fuzz_psbt(data);
});
