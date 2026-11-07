# Contributing to Cairn

Thanks for helping! Security review is the most valuable contribution of all.

## Ground rules

1. **No home-made cryptography.** Use audited libraries (rust-bitcoin, libsecp256k1, RustCrypto).
2. **Minimal dependencies.** Every new crate needs a clear reason, and must pass `cargo audit`.
3. **Secrets never leak.** No logging, printing, clipboard, telemetry or plain-text storage of seeds,
   passwords or keys. Wipe sensitive data when done (`zeroize`).
4. **Testnet only** until an independent audit is complete.
5. **Tests required** for anything touching keys, signing, fees or the keystore. Prefer official
   test vectors (BIP39, BIP32, BIP84, BIP174).

## Build and test

```
cargo build
cargo test --release -- --test-threads=1
cargo clippy -- -D warnings
cargo fmt
cargo audit
```

## Pull requests

- Keep them small and focused, and explain the why.
- Describe how you tested (and on which platform, for example Termux or Linux).
- Security-sensitive changes (`keystore.rs`, `wallet.rs`, `send.rs`, `esplora.rs`) get extra review.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your work is licensed under MIT OR Apache-2.0, like the project.

