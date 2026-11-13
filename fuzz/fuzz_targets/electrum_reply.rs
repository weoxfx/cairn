#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A hostile or broken Electrum server controls every field here. Parsing a
    // reply must never panic, however wrong the JSON types are.
    cairn::electrum::fuzz_reply(data);
});
