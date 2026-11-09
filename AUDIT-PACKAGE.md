# Cairn external review package

**Status: source-level security review completed. This document defines the scope for an external
review.**

Cairn is a self-custody Bitcoin wallet. Mainnet is the default for new wallets; testnet is available
when creating or importing a wallet. Source-level reviews are recorded in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md); their findings and residual risks remain in scope here.

## Target

- Repository: Cairn (Rust, single binary).
- Version: `0.8.0`.
- Code baseline: tag the commit that actually ships and give that commit and tree hash to the
  reviewer. The last review covered commit `b6201478018d06253fa176af74bb62f51852d2f8` ("download
  updae"), tree `f2b391dade309f32ee436ddfd2699d29e5190c14`. The 2026-11-09 hardening pass and the
  0.8.0 release changes are in the current tree, so the shipped tag is the correct review target.
- History: `41dd624` was an earlier review baseline. `a645b5f` changed mainnet selection, and
  `b620147` added `install.sh` and the release workflow. Reviewing `41dd624` alone is stale.
- Network model: mainnet is the default at wallet creation/import. Testnet (Testnet4, Testnet3 and
  Signet) is available in the same selector. The keystore AAD authenticates the network, and
  `esplora::net_for` binds each wallet to the matching API. There is no marker file or environment
  token that can move an existing wallet to another chain.
- Toolchain: the project pins `1.98.1`; `Cargo.lock` is committed and release checks run with
  `--locked`.
- Platform reviewed: Linux. The code is Unix-only and also targets macOS and Termux.

## Scope

In scope:

| Area | Files | What to review |
| --- | --- | --- |
| Keystore and KDF | `src/keystore.rs` | File format v1/v2/v3, Argon2id parameters, ChaCha20-Poly1305, AAD binding, salt/nonce/ciphertext limits, error-oracle behaviour, zeroization. |
| Derivation and signing | `src/wallet.rs` | BIP39 entropy handling, BIP32/BIP84 derivation, network/coin-type binding, `Signer` input checks, deterministic ECDSA. |
| Transaction construction | `src/send.rs` | Address/amount parsing, coin selection, dust, fee arithmetic, change, SIGHASH_ALL, script/key match. |
| PSBT and offline flow | `src/offline.rs`, `src/psbt_guard.rs` | PSBT creation, verification, signing, change classification, unsigned/signed comparison, file handling, broadcast, output-count limits and review flooding. |
| QR transport | `src/qr.rs` | Frame parser bounds, checksum, reassembly, image parsing and decompression limits. |
| Network and API | `src/esplora.rs` | URL chain guard, manual redirects, same-host enforcement, TLS-only client, JSON parsing bounds, UTXO/balance/history validation, prevout cross-check, failover, display history bounds. |
| Network selection | `src/network.rs`, `src/main.rs`, `src/esplora.rs`, `src/ui.rs` | Mainnet default, testnet selection at creation/import, per-wallet network binding, chain-aware `net_for`, stale-config handling and fail-closed composition. |
| Local hardening | `src/hardening.rs`, `src/keystore.rs` | rlimits, umask, private directories, atomic/symlink-safe writes, concurrent wallet-creation race. |
| UI and CLI | `src/main.rs`, `src/ui.rs` | Password entry, seed display, secret screen, transaction review, argument parsing, idle lock, terminal text sanitisation. |
| Release and installer | `install.sh`, `.github/workflows/release.yml`, `SECURITY.md` | Checksum verification, artifact provenance, signed-release support, install paths and update instructions. |

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

`SECURITY-REVIEW.md` records findings S-01..S-13, second-pass findings A-01..A-03, third-pass
hardening H-01..H-04, earlier review triages (AUD-01..AUD-11) and the review at
`b620147` (M-01, M-02, L-01..L-05, I-01, I-02). Reviewers should treat those as claims to verify,
not as conclusions.

The review found no Critical or High code vulnerability. The 2026-11-09 hardening pass
addressed the Medium/Low items: fee-rate ceiling, bounded history values and heights, allowlist text
sanitisation, PSBT structure caps, no-replace wallet creation, and ignoring the stale `Mainnet`
config. The 0.8.0 release makes mainnet the default and removes the per-session confirmation; the
per-wallet network binding and normal transaction review remain the relevant controls.

## Reproduction

```sh
cargo fmt --check --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1
cargo audit
cargo deny check
cargo build --locked --release
```

Record the output against the exact commit in the engagement.

Fuzzing (nightly; also run weekly in CI):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run url_guard -- -max_total_time=300
cargo +nightly fuzz run qr_frames -- -max_total_time=300
cargo +nightly fuzz run psbt -- -max_total_time=300
cargo +nightly fuzz run keystore -- -max_total_time=300
```

There are no network-dependent tests in the suite. The manual testnet flow uses a faucet and a
throwaway wallet: create -> receive -> sync -> send -> offline PSBT sign -> broadcast -> confirm.
Mainnet can be exercised by creating or importing a wallet and keeping the default network.

The `fuzz/` package covers the URL/redirect guard, the QR frame parser, PSBT deserialization plus
`psbt_guard::check_structure` (shared with the offline verifier), and a keystore adapter for
wallet-file JSON, KDF bounds, hex lengths and AAD construction (without running Argon2).

## Questions for the review

1. Can a tampered wallet file relabel the network, weaken the KDF, or make the tool spend mainnet
   coins against the wrong chain? Is the v3 AAD unambiguous?
2. Can any path derive or use a spending key without the expected fingerprint, network-specific BIP84
   path and script match?
3. Does the offline verifier prove that every input belongs to the wallet and that the only non-change
   output is the one reviewed? Can a malicious PSBT shift value into fee or change? PSBTs are capped
   at 500 inputs and 500 outputs; verify the cap is enforced before review.
4. Is the manual redirect implementation equivalent to the HTTP client's URL semantics for every input
   that can reach it (encoding, userinfo, ports, IPv6, backslashes, control characters)?
5. Are all server-controlled values (balances, UTXOs, txids, fees, text, history amounts and heights)
   bounded and validated before they affect display, selection or signing?
6. Can a planted file, FIFO, symlink or directory in `$HOME` cause a write outside the intended path,
   a hang, or a permission downgrade? Wallet creation uses no-replace semantics; verify.
7. Is network selection composed safely across every entry point (wallet creation, import, open, send,
   PSBT create/sign/broadcast, QR show/scan and settings)?
8. Are secrets zeroized and kept out of scrollback/core dumps to the extent the platform allows?
9. Is the release path verifiable: checksum-verified installer, signed manifest support, reproducible
   build claims and consistent release-status wording?

## Deliverables and exit criteria

The external review should produce a report with severity, exploitability, affected commit and
reproduction, plus a retest after fixes. The project should meet these criteria before treating an
external review as complete:

1. The report is delivered, every High/Medium finding is fixed and retested, and residual findings
   are documented.
2. Fuzzing covers PSBT, QR frames, image lists, Esplora JSON, URL parsing and keystore parsing.
3. Live integration tests pass against each supported provider, including error and redirect paths.
4. A mainnet dry run with a small amount matches an independent wallet or hardware signer
   address-for-address and fee-for-fee.
5. Linux, macOS and Termux behaviour is tested, including terminal seed display.
6. The release is reproducible and signed, `cargo audit` and `cargo deny check` are clean, and an
   incident/disclosure process exists.

Mainnet is the default for new wallets. Testnet remains available for development and testing.
