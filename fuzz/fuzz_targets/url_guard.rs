#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Split into a configured URL and a Location header at the first NUL so
    // both sides of the redirect check are fuzzed.
    match text.split_once('\0') {
        Some((base, location)) => cairn::esplora::fuzz_url(base, location),
        None => cairn::esplora::fuzz_url("https://mempool.space/api", text),
    }
});
