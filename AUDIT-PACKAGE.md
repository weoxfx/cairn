# Cairn external audit package

**Status: not audited.** This document prepares an independent review; it is not one. Nothing here
should be read as a safety claim.

Cairn is an experimental Bitcoin wallet. Testnet is the default and mainnet is opt-in. The project's
goal is to run on mainnet eventually, but only after the exit criteria at the bottom are met.

## Target

- Repository: Cairn (Rust, single binary).
- Baseline commit: `826007a4078af770b6ff0a6a1e16be82e4027840` ("fuzzing"), tree
  `68be2386f3b91a65b6cca996d20d3595d4f0f799`, branch `master`.
- Second-pass fixes A-01..A-03 and the fuzz harness are committed in that tree. The third-pass
  hardening (fee ceiling, prevout checks, best-effort `mlock`, PSBT fuzz target) is in the working
  tree and must be committed before the engagement. **Pin the exact commit and tree hash in the
  engagement letter.**
- Version: `0.2.0`. Toolchain used for review: `rustc 1.98.1`, `cargo 1.98.1`. `Cargo.lock` is
  committed and all checks run with `--locked`.
- Platform reviewed: Linux. The code is Unix-only and claims macOS and Termux compatibility.

## Scope

In scope:

| Area | Files | What to review |
| --- | --- | --- |
| Keystore and KDF | `src/keystore.rs` | File format v1/v2, Argon2id parameters, ChaCha20-Poly1305, AAD binding, salt/nonce/ciphertext limits, error-oracle behaviour, zeroization. |
| Derivation and signing | `src/wallet.rs` | BIP39 entropy handling, BIP32/BIP84 derivation, network/coin-type binding, `Signer` input checks, deterministic ECDSA. |
| Transaction construction | `src/send.rs` | Address/amount parsing, coin selection, dust, fee arithmetic, change, SIGHASH_ALL, script/key match. |
| PSBT and offline flow | `src/offline.rs`, `src/psbt_guard.rs` | PSBT creation, verification, signing, change classification, unsigned/signed comparison, file handling, broadcast; wallet-independent structure and amount checks. |
| QR transport | `src/qr.rs` | Frame parser bounds, checksum, reassembly, image parsing and decompression limits. |
| Network and API | `src/esplora.rs` | URL chain guard, manual redirects, same-host enforcement, TLS-only client, JSON parsing bounds, UTXO/balance/history validation, prevout cross-check, failover. |
| Mainnet gate | `src/network.rs` | Marker/env opt-in, ownership and permission checks, typed confirmations, fail-closed composition. |
| Local hardening | `src/hardening.rs` | rlimits, umask, private directories, atomic/symlink-safe writes. |
| UI and CLI | `src/main.rs`, `src/ui.rs` | Password entry, seed display, secret screen, confirmations, argument parsing, idle lock. |

Out of scope (assumed correct): `bitcoin`, `secp256k1`, `argon2`, `chacha20poly1305`, `ureq`/rustls,
`image`, `rqrr`, `bip39`, `serde_json`, and the OS/TLS/PKI stack. Their versions are pinned in
`Cargo.lock` and checked with `cargo audit`.

## Threat model

In scope:

- A malicious or compromised Esplora provider (it can lie about balances, UTXOs, fees and history, or
  return hostile text/redirects).
- A network attacker who cannot break TLS.
- A malicious PSBT, QR code, image or wallet file supplied to the tool.
- Accidental wrong-chain use (testnet wallet pointed at mainnet, or the reverse).
- A local attacker who can create files in `$HOME` but runs as a different user.

Out of scope:

- Malware running as the same user, root/administrator compromise, or a compromised operating system.
- Physical coercion, screen capture, terminal emulator logging, swap/hibernation.
- Side channels, speculative execution, power/EM analysis.
- Compromise of the cryptographic primitives or of the release toolchain/supply chain.

Primary assets: the BIP39 entropy and password, the derived signing keys, and the integrity of the
transaction the user approves.

## Existing review

`SECURITY-REVIEW.md` records findings S-01..S-13, the second-pass findings A-01..A-03 and the
third-pass hardening H-01..H-04, with status, impact and fixes. Auditors should treat those as claims to verify, not as conclusions.

## Reproduction

```sh
cargo fmt --check --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1
cargo audit
cargo build --locked --release
```

Fuzzing (nightly; also run weekly in CI):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run url_guard -- -max_total_time=300
cargo +nightly fuzz run qr_frames -- -max_total_time=300
cargo +nightly fuzz run psbt -- -max_total_time=300
```

There are no network-dependent tests in the suite. The manual testnet flow uses a faucet and a
throwaway wallet: create -> receive -> sync -> send -> offline PSBT sign -> broadcast -> confirm.
The mainnet gate can be exercised with a temporary `HOME` and `--enable-mainnet` / `--disable-mainnet`;
`CAIRN_ENABLE_MAINNET=I_UNDERSTAND_UNAUDITED_MAINNET` opens the gate for one process.

The `fuzz/` package covers the URL/redirect guard, the QR frame parser and PSBT deserialization plus
`psbt_guard::check_structure` (shared with the offline verifier). Keystore JSON still needs a pure
adapter before it can be fuzzed; it is covered by unit tests for now.

## Questions for the audit

1. Can a tampered wallet file relabel the network, weaken the KDF, or make the tool spend mainnet coins
   without the opt-in? Is the v2 AAD unambiguous?
2. Can any path derive or use a spending key without the expected fingerprint, network-specific BIP84
   path and script match?
3. Does the offline verifier prove that every input belongs to the wallet and that the only non-change
   output is the one reviewed? Can a malicious PSBT shift value into fee or change?
4. Is the manual redirect implementation equivalent to the HTTP client's URL semantics for every input
   that can reach it (encoding, userinfo, ports, IPv6, backslashes, control characters)?
5. Are all server-controlled values (balances, UTXOs, txids, fees, text) bounded and validated before
   they affect display, selection or signing?
6. Can a planted file, FIFO, symlink or directory in `$HOME` cause a write outside the intended path,
   a hang, or a permission downgrade?
7. Is the mainnet gate composed safely across every entry point (wallet creation, import, open, send,
   PSBT create/sign/broadcast, QR show/scan, settings, environment and marker)?
8. Are secrets zeroized and kept out of scrollback/core dumps to the extent the platform allows?

## Deliverables and exit criteria

The audit should produce a report with severity, exploitability, affected commit and reproduction,
plus a retest after fixes. Mainnet is not recommended for real funds until:

1. The report is delivered, every High/Medium finding is fixed and retested, and residual findings are
   documented.
2. Fuzzing covers PSBT, QR frames, image lists, Esplora JSON and URL parsing.
3. Live integration tests pass against each supported provider, including error and redirect paths.
4. A mainnet dry run with an amount that can be lost matches an independent wallet/hardware signer
   address-for-address and fee-for-fee.
5. Linux, macOS and Termux behaviour is tested, including terminal seed display.
6. The release is reproducible and signed, `cargo audit` is clean, and an incident/disclosure process
   exists.

Until then: testnet remains the default, mainnet remains opt-in, and the UI must keep saying
"unaudited".
