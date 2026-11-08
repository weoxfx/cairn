# Cairn external audit package

**Status: independent AI-assisted source review completed; no third-party audit.**
This document prepares an independent third-party audit; it is not one, and nothing here should be
read as a safety claim. The independent AI-assisted review at `b620147` found no Critical or High
code vulnerability under the threat model below, but it is not a professional audit and does not
satisfy the exit criteria at the bottom. Its Medium/Low findings are recorded in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md) and remain open unless stated there.

Cairn is an experimental Bitcoin wallet. Testnet is the default; mainnet is chosen when creating or
importing a wallet. The project's goal is to run on mainnet eventually, but only after the exit
criteria at the bottom are met.

## Target

- Repository: Cairn (Rust, single binary).
- Code commit: `b6201478018d06253fa176af74bb62f51852d2f8` ("download updae"), tree
  `f2b391dade309f32ee436ddfd2699d29e5190c14`, branch `master`. This is the current release commit
  and the tree examined by the independent AI-assisted review. `git status` is clean.
- Baseline tag: none. No `v0.2.0` tag has been created yet, so `b620147` is the pin until the release
  is tagged. Do not create an "audit" tag for an AI-assisted review; tag the commit that is actually
  shipped and have the third-party auditor pin that same commit and tree.
- History: `41dd624` was the earlier review baseline. `a645b5f` ("mainnet update") changed mainnet
  selection, removed the per-session gate, and updated the keystore/network tests. `b620147` adds
  `install.sh` and the GitHub release workflow. A review against `41dd624` alone is stale.
- Mainnet change: `a645b5f` deliberately removed `--enable-mainnet`, the marker file, the environment
  token, `network::enabled()`, `require_enabled()`, `require_supported()` and the repeated typed
  `MAINNET` confirmation on open. Mainnet is now selected once when creating or importing a wallet,
  with a default-no confirmation. Opening an existing mainnet wallet, creating a mainnet PSBT,
  signing it offline and broadcasting it do not ask for network confirmation again. The v2 keystore
  AAD still authenticates the network and `net_for` still hard-binds mainnet wallets to the mainnet
  API, but the accident guard is materially weaker. This change is in scope for the audit.
- Prior fixes: second-pass A-01..A-03, the fuzz harness, the third-pass hardening (fee ceiling,
  prevout checks, best-effort `mlock`, PSBT fuzz target) and the prior AI-assisted review fixes are
  committed in the code tree. The `41dd624` fixes (chain-specific URLs, authority-preserving
  redirects, transaction-screen network, seed re-entry, body-size failure, drop ordering) are also
  included in `b620147`.
- Version: `0.2.0`. Toolchain used by the independent reviewer: `rustc 1.99.1`, `cargo 1.99.1`
  (the project pins `1.98.1`). `Cargo.lock` is committed and all checks run with `--locked`.
- Platform reviewed: Linux. The code is Unix-only and claims macOS and Termux compatibility.

## Scope

In scope:

| Area | Files | What to review |
| --- | --- | --- |
| Keystore and KDF | `src/keystore.rs` | File format v1/v2, Argon2id parameters, ChaCha20-Poly1305, AAD binding, salt/nonce/ciphertext limits, error-oracle behaviour, zeroization. |
| Derivation and signing | `src/wallet.rs` | BIP39 entropy handling, BIP32/BIP84 derivation, network/coin-type binding, `Signer` input checks, deterministic ECDSA. |
| Transaction construction | `src/send.rs` | Address/amount parsing, coin selection, dust, fee arithmetic, change, SIGHASH_ALL, script/key match. |
| PSBT and offline flow | `src/offline.rs`, `src/psbt_guard.rs` | PSBT creation, verification, signing, change classification, unsigned/signed comparison, file handling, broadcast, output-count limits and review flooding. |
| QR transport | `src/qr.rs` | Frame parser bounds, checksum, reassembly, image parsing and decompression limits. |
| Network and API | `src/esplora.rs` | URL chain guard, manual redirects, same-host enforcement, TLS-only client, JSON parsing bounds, UTXO/balance/history validation, prevout cross-check, failover, display history bounds. |
| Mainnet selection | `src/network.rs`, `src/main.rs`, `src/esplora.rs`, `src/ui.rs` | Testnet default, creation/import-only confirmation, no per-open gate, chain-aware `net_for`, stale-config migration and fail-closed composition. |
| Local hardening | `src/hardening.rs`, `src/keystore.rs` | rlimits, umask, private directories, atomic/symlink-safe writes, concurrent wallet-creation race. |
| UI and CLI | `src/main.rs`, `src/ui.rs` | Password entry, seed display, secret screen, confirmations, argument parsing, idle lock, terminal text sanitisation. |
| Release and installer | `install.sh`, `.github/workflows/release.yml`, `SECURITY.md` | Checksum verification, artifact provenance, unsigned release status, install paths and update instructions. |

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
- An attacker who can already write the user's wallet directory (same-user access).

Primary assets: the BIP39 entropy and password, the derived signing keys, and the integrity of the
transaction the user approves.

## Existing review

`SECURITY-REVIEW.md` records findings S-01..S-13, the second-pass findings A-01..A-03, the
third-pass hardening H-01..H-04, the prior AI-assisted review triages (AUD-01..AUD-11) and the
independent AI-assisted review at `b620147` (M-01, M-02, L-01..L-05, I-01, I-02). Auditors should
treat those as claims to verify, not as conclusions.

None of those reviews is a third-party audit. The independent review found no Critical or High code
vulnerability, but at review time it left Medium and Low findings open, including the deliberate
mainnet-gate removal and a looser `--broadcast` fee check than the offline verifier. Those are in
scope.

## Reproduction

```sh
cargo fmt --check --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1
cargo audit
cargo build --locked --release
```

The independent review ran the first four commands on `b620147` with rustc/cargo 1.99.1: fmt, clippy
and audit passed, and the test suite reported 47 passed, 0 failed. Re-run them against the exact
commit and record the output in the engagement.

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
Mainnet can be exercised by creating or importing a wallet and choosing Mainnet; it shows the short
experimental/not-third-party-audited notice and asks for a default-no confirmation. Testnet remains
the default. Opening an existing wallet uses its recorded network without another prompt; that
absence of a per-session gate is deliberate and must be assessed as part of the mainnet scope.

The `fuzz/` package covers the URL/redirect guard, the QR frame parser and PSBT deserialization plus
`psbt_guard::check_structure` (shared with the offline verifier). Keystore JSON still needs a pure
adapter before it can be fuzzed; it is covered by unit tests for now.

## Questions for the audit

1. Can a tampered wallet file relabel the network, weaken the KDF, or make the tool spend mainnet
   coins without confirmation? Is the v2 AAD unambiguous? Note that mainnet confirmation now happens
   only at creation/import (M-02); is that remaining confirmation sufficient for an accident guard?
2. Can any path derive or use a spending key without the expected fingerprint, network-specific BIP84
   path and script match?
3. Does the offline verifier prove that every input belongs to the wallet and that the only non-change
   output is the one reviewed? Can a malicious PSBT shift value into fee or change, or flood the review
   with unbounded outputs (L-04)?
4. Is the manual redirect implementation equivalent to the HTTP client's URL semantics for every input
   that can reach it (encoding, userinfo, ports, IPv6, backslashes, control characters)?
5. Are all server-controlled values (balances, UTXOs, txids, fees, text, history amounts and heights)
   bounded and validated before they affect display, selection or signing? History display values are
   currently not bounded (L-02).
6. Can a planted file, FIFO, symlink or directory in `$HOME` cause a write outside the intended path,
   a hang, or a permission downgrade? Can two concurrent creations silently replace a wallet (L-05)?
7. Is mainnet selection and confirmation composed safely across every entry point (wallet creation,
   import, open, send, PSBT create/sign/broadcast, QR show/scan and settings)? The per-session gate is
   gone; verify the AAD/network binding and decide whether the creation/import guard is sufficient.
8. Are secrets zeroized and kept out of scrollback/core dumps to the extent the platform allows?
9. Is the release path honest and verifiable: checksum-verified installer, unsigned artifacts clearly
   labelled, reproducible build claims and no accidental "audited" wording (I-02)?

## Deliverables and exit criteria

The audit should produce a report with severity, exploitability, affected commit and reproduction,
plus a retest after fixes. Mainnet is not recommended for real funds until:

1. A third-party audit report is delivered, every High/Medium finding is fixed and retested, and
   residual findings are documented. The AI-assisted review does not satisfy this criterion.
2. Fuzzing covers PSBT, QR frames, image lists, Esplora JSON and URL parsing.
3. Live integration tests pass against each supported provider, including error and redirect paths.
4. A mainnet dry run with an amount that can be lost matches an independent wallet/hardware signer
   address-for-address and fee-for-fee.
5. Linux, macOS and Termux behaviour is tested, including terminal seed display.
6. The release is reproducible and signed, `cargo audit` is clean, and an incident/disclosure process
   exists.

Until then: testnet remains the default, mainnet remains an explicit creation/import choice, and the
UI must not describe Cairn as third-party audited.
