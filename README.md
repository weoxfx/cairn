# Cairn

An open-source Bitcoin wallet for the command line, built around an encrypted keystore, a
watch-only session and careful sending.

> **EXPERIMENTAL. TESTNET ONLY. UNAUDITED.**
> Do not use real funds. Nobody independent has reviewed this code yet. Use at your own risk.

## What it does today

- Create, import and open wallets (BIP39, 24 words, native SegWit / BIP84)
- Encrypted wallet file (Argon2id + ChaCha20-Poly1305)
- Balance, transaction list, receive addresses with QR codes
- Send: address and amount validation, fee choice, full review screen,
  type `SEND` to confirm, password re-entry, then sign and broadcast
- Works on Testnet4, Testnet3 and Signet, with provider failover and request pacing
- Runs on Linux, macOS and Android (Termux)

## Security design

| Area | What Cairn does |
|---|---|
| Seed | 256 bits from the OS random source, shown once on the terminal's alternate screen (no scrollback), then a 3-word backup quiz |
| Storage | Only the encrypted entropy is saved. Argon2id (128 MB, 3 passes) then ChaCha20-Poly1305. Atomic writes, mode 600, symlinks refused, KDF parameters validated on load |
| Memory | After unlock only the public account key (xpub) is kept. The seed is wiped. Spending keys exist only for the moment of signing |
| Sending | Re-asks the password, checks the keys match the wallet and each coin, checks that the amounts add up, uses deterministic (RFC6979) signatures |
| Network | HTTPS, response size caps, rate pacing, failover, testnet-only guard. Server data is treated as untrusted |
| Process | No core dumps, not dumpable by other processes, umask 077, 5-minute idle lock |

Cryptographic primitives come from audited libraries (rust-bitcoin, libsecp256k1, RustCrypto).
Cairn does not implement its own cryptography. See [SECURITY.md](SECURITY.md) for the threat model,
known limits and how to report a vulnerability.

## Install

You need Rust (https://rustup.rs). On Termux: `pkg install rust git`.

```
git clone <repo-url> cairn
cd cairn
cargo build --release
./target/release/cairn
```

Wallets are stored in `~/.cairn/wallets/`. Back up your 24 words on paper. The file is only a
convenience copy that your password unlocks.

## Getting testnet coins

Open a wallet, choose **Receive**, and send free coins from a testnet faucet to that address.
Wait for one confirmation before sending (unconfirmed coins are not spent).

## Settings

- **Network:** Settings in the main menu (Testnet4, Testnet3, Signet)
- **Your own server:** `export CAIRN_API=https://your-server/api` (comma separated for several)

## Development

```
cargo test --release -- --test-threads=1
cargo clippy -- -D warnings
cargo audit
```

Tests include the official BIP39 and BIP84 vectors, keystore tamper tests and a signature
verification test. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- [x] Encrypted keystore, create / import / open
- [x] Receive, balance, history, QR
- [x] Send with review and confirmation
- [x] Provider failover and rate pacing
- [ ] Offline signer with PSBT and QR transfer (`cairn --offline`)
- [ ] Optional passphrase (25th word), 2-of-3 multisig
- [ ] Own-node support (Electrum protocol), Tor
- [ ] Reproducible builds, fuzzing, independent audit

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
There is no warranty of any kind.

