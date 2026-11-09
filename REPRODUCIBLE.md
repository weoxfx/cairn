# Reproducible builds

Cairn aims to make every release binary rebuildable from the tagged source with the
same toolchain and flags. This is a process goal, not a claim that any particular
download has already been independently rebuilt. Verify it yourself before trusting
a release.

## Pinned inputs

| Input | Pin |
|---|---|
| Rust toolchain | `1.98.1` (`.github/workflows/ci.yml`, `release.yml`) |
| Dependency graph | `Cargo.lock`, built with `--locked` |
| Build profile | `Cargo.toml` release profile (`lto = "fat"`, `codegen-units = 1`, `incremental = false`, `strip = true`) |
| Path mapping | `--remap-path-prefix=<workspace>=/cairn`, `--remap-path-prefix=$HOME/.cargo=/cargo` |
| Timestamp | `SOURCE_DATE_EPOCH=0` in CI |

GitHub Actions are pinned by commit SHA in all workflows.

## Rebuild locally

```sh
git clone https://github.com/weoxfx/cairn
cd cairn
git checkout <release-tag>
rustup toolchain install 1.98.1 --profile minimal
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/cairn --remap-path-prefix=$HOME/.cargo=/cargo"
cargo build --locked --release
sha256sum target/release/cairn
```

Compare that hash with the `cairn` binary inside the release archive. For the Linux
musl target add `--target x86_64-unknown-linux-musl` and
`RUSTFLAGS="... -C target-feature=+crt-static"`.

## What CI checks

The `reproducible` job in `.github/workflows/ci.yml` builds the release binary twice
in separate target directories with the flags above and fails if the two SHA-256
hashes differ. That catches non-determinism introduced by the build (timestamps,
unordered output, path leakage) on the pinned runner.

## What this does not prove

- Two builds on the same runner are not a cross-machine reproduction. Different
  CPUs, kernels, linkers or C libraries can still change the output. A third party
  should rebuild on independent hardware and compare hashes.
- `strip = true` removes most debug information, but panic strings and static data
  can still contain build paths. The remap flags reduce, but do not remove, that
  surface.
- The macOS binaries are not notarized or code-signed by Apple. Gatekeeper may warn.
- Reproducibility does not make the code correct. It only lets you check that a
  binary matches source you can read.

## Reporting a mismatch

If your rebuild does not match a published archive, do not run the archive. Open a
private security report as described in [SECURITY.md](SECURITY.md) with the tag, the
target triple, `rustc -Vv`, `uname -a`, the expected hash and the hash you got.
