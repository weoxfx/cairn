# Contributing to Cairn

Thanks for helping! Security review is the most valuable contribution of all.

## Ground rules

1. **No home-made cryptography.** Use audited libraries (rust-bitcoin, libsecp256k1, RustCrypto).
2. **Minimal dependencies.** Every new crate needs a clear reason, and must pass `cargo audit`.
3. **Secrets never leak.** No logging, printing, clipboard, telemetry or plain-text storage of seeds,
   passwords or keys. Wipe sensitive data when done (`zeroize`).
4. **Network correctness.** Mainnet is the default; testnet stays available at creation and import.
   Never let a wallet talk to another chain's API, and keep the network binding authenticated.
5. **Tests required** for anything touching keys, signing, fees or the keystore. Prefer official
   test vectors (BIP39, BIP32, BIP84, BIP174). Cover both networks where a path is network-aware.

## Build and test

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1
cargo audit
```

Fuzzing (targets are listed in `fuzz/Cargo.toml`; CI runs a short smoke on every PR that
touches the parsers):

```
cargo +nightly-2026-11-01 fuzz run qr_frames -- -max_total_time=60
```

## Pull requests

- Keep them small and focused, and explain the why.
- Describe how you tested (and on which platform, for example Termux or Linux).
- Security-sensitive changes (`keystore.rs`, `wallet.rs`, `send.rs`, `offline.rs`, `qr.rs`,
  `esplora.rs`, `electrum.rs`, `chain.rs`, `multisig.rs`) get extra review.
- Platform-specific code goes through `hardening.rs` helpers rather than `#[cfg]` at each call site,
  so Linux, macOS and Windows stay in step. Behaviour that only exists on one platform is reported
  as *not checked*, never as passing.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your work is licensed under MIT OR Apache-2.0, like the project.

