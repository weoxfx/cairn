# Cairn

An open-source Bitcoin wallet for the command line, built around an encrypted keystore, a
watch-only session and careful sending.

## What it does today

- Create, import and open wallets (BIP39, 24 words, native SegWit / BIP84)
- Encrypted wallet file (Argon2id + ChaCha20-Poly1305, authenticated metadata)
- Balance, transaction list, receive addresses with QR codes
- Send: address and amount validation, fee choice, full review screen,
  type `SEND` to confirm, password re-entry, then sign and broadcast
- Offline signing (file or QR transport): build an unsigned PSBT online, sign it on a
  machine with no network, then broadcast it after the online side verifies it
- Works on Testnet4, Testnet3 and Signet, with provider failover and request pacing
- Mainnet can be chosen when creating or importing a wallet; testnet remains the default
- Runs on Linux, macOS and Android (Termux)

## Mainnet

Cairn is built and tested testnet-first, and testnet remains the default. Mainnet is chosen when
creating or importing a wallet, without any extra setup. That choice shows a short
not-third-party-audited notice and asks for confirmation. Opening an existing wallet uses its
recorded network without another prompt.

Mainnet has completed an independent AI-assisted source review but has **not** had a third-party
audit, and must not be treated as safe for real savings. New wallets record their network, and the
API layer refuses a testnet wallet pointed at a mainnet server (and the reverse). Use testnet, or a
hardware/reviewed wallet, for anything you cannot afford to lose.

## Security design

| Area | What Cairn does |
|---|---|
| Seed | 256 bits from the OS random source, shown once on the terminal's alternate screen (no scrollback), then a 3-word backup quiz. Import asks for the hidden phrase twice |
| Storage | Only the encrypted entropy is saved. Argon2id (128 MB, 3 passes) then ChaCha20-Poly1305. The v2 AAD authenticates network, fingerprint, KDF parameters, salt and nonce. Atomic writes that never follow a symlink, mode 600, `.cairn` kept at 700, symlinked wallet dirs refused, KDF bounds enforced on load. v1 testnet wallets still open |
| Memory | After unlock only the public account key (xpub) is kept. The decrypted mnemonic and signing keys are held in `mlock`ed allocations when the OS allows it, and erased on drop. Spending keys exist only for the moment of signing |
| Sending | Re-asks the password, checks the keys match the wallet and each coin, re-fetches each spent coin's creating transaction to compare value/address, checks that the amounts add up, enforces a fee ceiling (10% of the amount, 10k-sat floor, 1M-sat hard cap), uses deterministic (RFC6979) signatures |
| Offline | `--offline` never opens a socket. It checks that every input belongs to the wallet, has the expected network-specific BIP84 path and script, that change is ours and that the fee clears the relay minimum. PSBT files must be regular files (no FIFOs or symlinks) and signed output is written atomically at mode 600. The online side refuses a signed PSBT that changed any input or output. QR frames are checksummed and then go through the same checks; they are public data, not encrypted |
| Network | HTTPS-only with certificate checks; redirects are same-origin (host and port) and re-checked, broadcasts refuse them. Response size caps fail closed, with rate pacing, failover and a chain-specific URL guard; userinfo and IPv6 authorities are rejected. Server data is treated as untrusted; UTXO/input/output and balance amounts are bounded, txids are validated, and control characters plus a specific list of invisible Unicode format characters are stripped. History net amounts and heights are display-only and not bounded (L-02); the sanitiser list is not exhaustive (L-03) |
| Mainnet | Chosen when creating or importing a wallet; testnet remains the default. The choice shows a short not-third-party-audited notice and a default-no confirmation. Opening an existing wallet does not ask again. This is an accident guard, not a third-party audit |
| Process | No core dumps, umask 077, 5-minute idle lock; non-dumpable on Linux/Android |

Cryptographic primitives come from audited libraries (rust-bitcoin, libsecp256k1, RustCrypto).
Cairn does not implement its own cryptography. See [SECURITY.md](SECURITY.md) for the threat model,
known limits and how to report a vulnerability. Internal and independent AI-assisted reviews are
documented in [SECURITY-REVIEW.md](SECURITY-REVIEW.md); neither is a substitute for a third-party
audit.

## Install

### One-line install

No GitHub release has been published yet, so the current one-line install uses a source build. It
requires Rust and the platform build tools; if a release is published later, the same command uses
a prebuilt binary on supported platforms.

Linux x86_64, macOS, or Termux/Android:

```sh
curl -fsSL https://raw.githubusercontent.com/weoxfx/cairn/master/install.sh | sh
```

On Termux, install Rust first:

```sh
pkg install rust
curl -fsSL https://raw.githubusercontent.com/weoxfx/cairn/master/install.sh | sh -s -- --from-source
```

The installer downloads a release when one exists, verifies its SHA-256 checksum, and puts `cairn`
in `~/.local/bin` (Termux: `$PREFIX/bin`; override with `CAIRN_INSTALL_DIR`). Without a release it
builds from source with `cargo`; if Cargo is missing it prints the exact command for your platform.
It does not use `sudo`. Download and inspect `install.sh` first if you prefer.

After it finishes, run:

```sh
cairn
```

If your shell says `cairn: command not found`, add `~/.local/bin` to `PATH` once:

```sh
# Linux
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
. ~/.profile

# macOS (zsh)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
. ~/.zshrc
```

`apt install cairn` is not available because Cairn does not publish a signed Debian/Ubuntu APT
repository. The installer is the no-root equivalent.

### Download a prebuilt binary

Once a release is published, no Rust toolchain is needed. Download the archive for your platform
from the [latest release](https://github.com/weoxfx/cairn/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86_64 | `cairn-v*-x86_64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `cairn-v*-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `cairn-v*-x86_64-apple-darwin.tar.gz` |

Each archive contains the `cairn` binary, `README.md`, `SECURITY.md` and both licenses. Download the
matching `.sha256` file and verify it before running:

```sh
sha256sum -c cairn-v*-x86_64-unknown-linux-musl.tar.gz.sha256
tar -xzf cairn-v*-x86_64-unknown-linux-musl.tar.gz
cd cairn-v*-x86_64-unknown-linux-musl
./cairn
```

On macOS use `shasum -a 256 -c ...` instead of `sha256sum -c`. The macOS binaries are unsigned; if
Gatekeeper blocks one, use Finder's right-click **Open** or clear the quarantine attribute. Put the
binary on your `PATH` with:

```sh
install -m 755 cairn ~/.local/bin/cairn
```

Prebuilt Android/Termux and ARM Linux binaries are not published yet; the installer falls back to
the source build, or use the source build below.

### Build from source

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

## Offline signing (PSBT)

PSBTs can travel as files (binary; hex text is also accepted) or as QR frames.

1. **Online — build:** `cairn --create-psbt [WALLET] --out unsigned.psbt`
   Syncs, asks for the recipient, amount and fee, shows the usual review, then asks you to type
   `CREATE`. The unsigned BIP174 PSBT is written to the file.
2. **Offline — sign:** copy the file over and run `cairn --offline unsigned.psbt --out signed.psbt`
   on a machine with no network. It checks that the inputs belong to the wallet, that each key
   origin is `m/84'/coin'/0'/chain/index` for the wallet's network (coin `0` mainnet, `1` testnet),
   that the coin scripts match, that change is yours and that the fee is at least 1 sat/vB. It then
   shows what is leaving the wallet and asks for `SEND`.
3. **Online — broadcast:** copy the signed file back and run
   `cairn --broadcast unsigned.psbt signed.psbt`. Cairn verifies the signed PSBT has exactly the same
   inputs and outputs as the unsigned one, shows the final details and asks for `SEND`.

The offline machine cannot look up how much each coin really holds, so input values come from the
PSBT file. Compare the total and fee shown there with what the online machine displayed before you
sign. Never sign a PSBT you did not expect.

### QR transport

Instead of copying files, the PSBT can travel as QR frames:

```
cairn --qr-show unsigned.psbt
cairn --qr-scan --out unsigned.psbt frame1.png frame2.png ...
```

`--qr-show` displays one QR for a small PSBT, or cycles through numbered frames for a larger one.
The QR size follows your terminal: a taller window needs fewer frames, and Cairn asks you to enlarge
it if a frame would not fit. Photograph or screenshot every frame (PNG or JPEG), then pass all images
to `--qr-scan` on the other machine. It accepts frames in any order, ignores duplicates and rejects
missing or mixed frames using a short SHA-256 checksum. Sign offline, show the signed PSBT as QR, and
scan it back the same way.

A typical PSBT is two to five frames on a tall terminal, and more on a short one. Rerun `--qr-show`
if you miss a frame. QR contents are public data (addresses, amounts, public keys), not your seed.
The usual PSBT review still happens after scanning.

## Settings

- **Network:** Settings in the main menu for Testnet4, Testnet3 and Signet. A wallet's mainnet or
  testnet identity is fixed when it is created or imported.
- **Your own server:** `export CAIRN_API=https://your-server/testnet/api` (comma separated for several; use a hostname or IPv4 literal, not an IPv6 literal)

## Development

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1
cargo audit
```

Tests include the official BIP39 and BIP84 vectors, keystore tamper/network-relabel tests, signature
verification, the offline PSBT verify/sign/roundtrip path and QR frame render/scan tests.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Releasing

Push a version tag to publish downloadable binaries:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The release workflow builds a static Linux x86_64 binary and macOS binaries for Apple Silicon and
Intel, attaches SHA-256 checksums and creates a GitHub Release.

## Roadmap

- [x] Encrypted keystore, create / import / open
- [x] Receive, balance, history, QR
- [x] Send with review and confirmation
- [x] Provider failover and rate pacing
- [x] Offline signer with PSBT and QR transfer (PSBT files and QR images; live camera optional)
- [x] Experimental mainnet support (independently source-reviewed; no third-party audit)
- [ ] Optional passphrase (25th word), 2-of-3 multisig
- [ ] Own-node support (Electrum protocol), Tor
- [x] Fuzzing harness for URL/redirect, QR frames and PSBT (keystore pending)
- [x] Independent AI-assisted source review (not a third-party audit)
- [ ] Reproducible builds and third-party audit (required before recommending mainnet)

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
There is no warranty of any kind.

