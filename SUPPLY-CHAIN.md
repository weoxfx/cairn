# Supply-chain policy

Cairn is a wallet, so its build inputs are part of its security boundary. This page
describes what is enforced today and what is still planned. None of it is a safety
guarantee on its own.

## Dependency graph

- `Cargo.lock` is committed. Every CI build uses `cargo build --locked` /
  `cargo test --locked`, so a lockfile change is visible in the diff.
- The dependency set is intentionally small. New crates need a clear reason in the
  pull request and must pass `cargo audit` and `cargo deny check`.
- `cargo audit` runs on every push and pull request and fails on vulnerabilities,
  unmaintained crates and unsound advisories (`--deny warnings`).
- `cargo deny check` runs in CI with [`deny.toml`](deny.toml):
  - **Licenses:** allowlist only (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`,
    `Zlib`, `0BSD`, `CC0-1.0`, `CDLA-Permissive-2.0`, `Unicode-3.0`, `Unlicense`,
    `MITNFA`, and `Apache-2.0 WITH LLVM-exception`). A new license fails CI.
  - **Sources:** only crates.io is allowed. Git and unknown registries are denied.
  - **Bans:** wildcard version requirements are denied; duplicate versions are
    reported as warnings.

Run it locally:

```sh
cargo install cargo-deny --locked
cargo deny check
```

## GitHub Actions

Every action in `.github/workflows/` is pinned by full commit SHA, not a mutable
tag. The Rust toolchain is pinned to `1.98.1` for CI and releases and `nightly` only
for the weekly fuzz job. The release workflow uses the same toolchain and flags as
the reproducibility job.

## Fuzzing

`fuzz/` contains coverage-guided libFuzzer targets linked to the real parsers:

| Target | Surface |
|---|---|
| `url_guard` | API URL and redirect parsing |
| `qr_frames` | QR frame reassembly and round-trip |
| `psbt` | PSBT deserialization and `psbt_guard` checks |
| `keystore` | Wallet-file JSON, KDF bounds, hex lengths and AAD construction |

The weekly Fuzz workflow runs each target for 120 seconds. The keystore adapter does
not run Argon2 (that would be too slow); it checks everything up to the expensive
KDF step.

## Reproducible builds

See [REPRODUCIBLE.md](REPRODUCIBLE.md). CI builds the release binary twice with
pinned flags and fails on a hash mismatch. Cross-machine reproduction is still the
user's check to perform.

## Signed releases

See [RELEASE-SIGNING.md](RELEASE-SIGNING.md). When `MINISIGN_SECRET_KEY` is set, the
release workflow signs `SHA256SUMS`; `install.sh` verifies it when
`CAIRN_MINISIGN_PUBKEY` is set and warns honestly when it is not.

## cargo-vet (planned)

[`cargo-vet`](https://mozilla.github.io/cargo-vet/) records which dependencies have
been reviewed by whom. It is a stronger social guarantee than a license allowlist,
but it needs an initial audit set and maintainer time. The adoption path is:

```sh
cargo install cargo-vet --locked
cargo vet init
cargo vet
```

Do not add a `cargo vet` CI gate until the audit set is populated; an empty set
would fail every build and encourage people to bypass it. Until then, `cargo audit`
and `cargo deny` are the enforced gates.

## Reporting a supply-chain issue

If you find a malicious crate, a compromised action, a signature mismatch or a
reproducibility failure, report it privately as described in
[SECURITY.md](SECURITY.md). Do not open a public issue with exploit details first.
