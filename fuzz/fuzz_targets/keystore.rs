#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser accepts untrusted wallet files, so every field must be
    // validated without panicking or allocating unbounded memory.
    cairn::keystore::fuzz_keystore(data);
});
