# Cairn

Open-source Bitcoin CLI wallet with an encrypted keystore and (planned) air-gapped signing.

> **EXPERIMENTAL. TESTNET ONLY. UNAUDITED.** Do not use with real funds until an independent security audit is done.

## Run

```
cargo run
```

Wallets live in `~/.cairn/wallets/` (dir `700`, files `600`).

## Security design (current)

- Seed: 256 bits from the OS RNG, BIP39 24 words, shown once, then a 3-word backup quiz
- Keystore: Argon2id (256 MB, 3 passes) -> ChaCha20-Poly1305, atomic writes
- Secrets zeroized after use; wrong-password delays; generic error messages
- Crypto primitives come from audited crates (rust-bitcoin, RustCrypto). We do not roll our own.

## Roadmap

1. [x] Menu, create/import/open, encrypted keystore
2. [ ] Address derivation (BIP84) + Receive screen
3. [ ] Watch-only mode (xpub), balance, build PSBT
4. [ ] Send flow: address validation, fee choice, review screen, type `SEND` to confirm
5. [ ] `cairn --offline` signer + QR transfer
6. [ ] Optional passphrase, 2-of-3 multisig
7. [ ] Reproducible builds, fuzzing, external audit

## Reporting vulnerabilities

See SECURITY.md (to be added). Please disclose privately first.
