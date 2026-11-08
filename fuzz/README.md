# Fuzz targets

Coverage-guided fuzzing for the parsers that handle untrusted input. The targets
link the real `cairn` library (see `src/lib.rs`), not a copy.

Requires a nightly toolchain and `cargo-fuzz`:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz list
cargo +nightly fuzz run url_guard -- -max_total_time=300
cargo +nightly fuzz run qr_frames -- -max_total_time=300
cargo +nightly fuzz run psbt -- -max_total_time=300
```

Targets:

- `url_guard` — `url_parts`, `looks_like_url_for`, `host_of` and
  `resolve_redirect`. Asserts resolved URLs stay HTTPS, stay free of control
  characters/whitespace/backslashes, and always parse. This covers the A-01
  parser-differential class.
- `qr_frames` — `reassemble` over arbitrary frame lists, then re-encodes any
  accepted payload and checks the round-trip is byte-identical.
- `psbt` — `Psbt::deserialize` plus `psbt_guard::check_structure`: unsigned
  inputs, SIGHASH_ALL, witness and previous-transaction consistency, amount
  bounds and the input/output arithmetic. Accepted PSBTs must re-serialize and
  parse again.

Crashes land in `fuzz/artifacts/<target>/`. Reproduce with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
```

Still to add: keystore JSON needs a pure adapter before it can be fuzzed through
the library surface; current unit tests cover its bounds.
