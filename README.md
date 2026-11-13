# Cairn

An open-source, self-custody Bitcoin wallet for the command line, built around an encrypted
keystore, a watch-only session and careful sending.

## What it does today

- Create, import and open wallets (BIP39, 24 words, native SegWit / BIP84)
- Optional BIP39 passphrase (25th word), asked before the wallet is created or opened
- Encrypted wallet file (Argon2id + ChaCha20-Poly1305, authenticated metadata)
- Optional generated password: six words from the OS random source (66 bits), shown once on the
  alternate screen, so a strong password is one keystroke away instead of a habit
- Balance, transaction list, receive addresses with QR codes
- Send: address and amount validation, fee choice, coin control, full review screen,
  type `SEND` to confirm, password re-entry, then sign and broadcast
- Offline signing (file or QR transport): build an unsigned PSBT online, sign it on a
  machine with no network, then broadcast it after the online side verifies it
- Works on Testnet4, Testnet3 and Signet, with provider failover and request pacing
- Own Esplora server and SOCKS5/Tor support (`CAIRN_API`, `CAIRN_PROXY`, `CAIRN_TOR=1`)
- Watch-only descriptor export, numeric SeedQR display, and BIP329 transaction labels
- Machine-readable `--json` output for version, descriptors and labels
- Mainnet by default; Testnet4, Testnet3 and Signet are available when creating or importing a wallet
- Runs on Linux x86_64/ARM64, macOS and Android (Termux)

## Mainnet

Mainnet is selected by default when creating or importing a wallet. Testnet (Testnet4, Testnet3 and
Signet) is available in the same network selector for development and testing.

New wallets record their network, and the API layer refuses a testnet wallet pointed at a mainnet
server (and the reverse). Cairn has undergone source-level security review; the findings and
residual risks are recorded in [SECURITY-REVIEW.md](SECURITY-REVIEW.md). As with any self-custody
wallet, verify addresses and transaction details before approving a send, and keep your recovery
phrase offline.

## Security design

| Area | What Cairn does |
|---|---|
| Seed | 256 bits from the OS random source, shown once on the terminal's alternate screen (no scrollback), then a 3-word backup quiz. Import asks for the hidden phrase twice |
| Storage | Only the encrypted entropy is saved. Argon2id (128 MB, 3 passes) then ChaCha20-Poly1305. The v2 AAD authenticates network, fingerprint, KDF parameters, salt and nonce; v3 additionally authenticates whether a BIP39 passphrase is required. The passphrase itself is never stored. Atomic no-replace writes that never follow a symlink, mode 600, `.cairn` kept at 700, symlinked wallet dirs refused, KDF bounds enforced on load. v1/v2 wallets still open |
| Memory | After unlock only the public account key (xpub) is kept. The decrypted mnemonic and signing keys are held in `mlock`ed allocations when the OS allows it, and erased on drop. Spending keys exist only for the moment of signing |
| Sending | Re-asks the password, checks the keys match the wallet and each coin, re-fetches each spent coin's creating transaction to compare value/address, checks that the amounts add up, offers coin control, enforces a fee ceiling (10% of the amount, 10k-sat floor, 1M-sat hard cap) and a 1,000 sat/vB absolute rate ceiling, uses deterministic (RFC6979) signatures |
| Offline | `--offline` never opens a socket. It checks that every input belongs to the wallet, has the expected network-specific BIP84 path and script, that change is ours, that the fee clears the relay minimum and the rate ceiling, and caps PSBTs at 500 inputs / 500 outputs. PSBT files must be regular files (no FIFOs or symlinks) and signed output is written atomically at mode 600. The online side refuses a signed PSBT that changed any input or output. QR frames are checksummed and then go through the same checks; they are public data, not encrypted |
| Network | HTTPS-only with certificate checks; redirects are same-origin (host and port) and re-checked, broadcasts refuse them. Optional SOCKS5/Tor proxy (`CAIRN_PROXY` or `CAIRN_TOR=1`), with DNS resolved by the proxy. Response size caps fail closed, with rate pacing, failover and a chain-specific URL guard; userinfo and IPv6 authorities are rejected. Server data is treated as untrusted; UTXO/input/output/balance/history amounts and block heights are bounded, txids are validated, and server text is reduced to printable ASCII by an allowlist before display |
| Mainnet | The default for new wallets; testnet is available at creation/import. The wallet's network is stored and authenticated, and the API layer refuses cross-chain endpoints |
| EVM | Same encrypted seed, a separate derivation: `m/44'/60'/0'/0/index`, so one wallet holds Bitcoin and an EVM account. EIP-55 checksums are verified on mixed-case input, the zero address is refused, token calldata is cross-checked against the reviewed recipient, signatures are EIP-1559 only, and the fee is capped at 2,000 gwei unless `--force-fee` is given. Every RPC endpoint is probed with `eth_chainId` and refused if it reports another chain. Offline signing reads a JSON file and makes no network request; broadcast re-checks the transaction and the node's returned hash |
| Process | No core dumps, umask 077, 5-minute idle lock; non-dumpable on Linux/Android |

Cryptographic primitives come from audited libraries (rust-bitcoin, libsecp256k1, RustCrypto).
Cairn does not implement its own cryptography. See [SECURITY.md](SECURITY.md) for the threat model,
known limits and how to report a vulnerability. Source-level security review is documented in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md).

## Install

### One-line install

No GitHub release has been published yet, so the current one-line install uses a source build. It
requires Rust and the platform build tools; if a release is published later, the same command uses
a prebuilt binary on supported platforms.

Linux x86_64/ARM64, macOS, or Termux/Android:

```sh
curl -fsSL https://raw.githubusercontent.com/weoxfx/cairn/master/install.sh | sh
```

On Termux, install Rust first:

```sh
pkg install rust
curl -fsSL https://raw.githubusercontent.com/weoxfx/cairn/master/install.sh | sh -s -- --from-source
```

The installer downloads a release when one exists, verifies its SHA-256 checksum, and puts `cairn`
in `~/.local/bin` (Termux: `$PREFIX/bin`; override with `CAIRN_INSTALL_DIR`). When
`CAIRN_MINISIGN_PUBKEY` is set it also verifies the signed `SHA256SUMS` manifest before trusting the
archive; without a key it prints a warning that the checksum is unsigned. Without a release it builds
from source with `cargo`; if Cargo is missing it prints the exact command for your platform. It does
not use `sudo`. Download and inspect `install.sh` first if you prefer. See
[RELEASE-SIGNING.md](RELEASE-SIGNING.md) for key setup and manual verification.

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
| Linux ARM64 | `cairn-v*-aarch64-unknown-linux-gnu.tar.gz` |
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

When the release is signed, prefer verifying the signed manifest instead of trusting a checksum
downloaded from the same place as the archive:

```sh
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P "$CAIRN_MINISIGN_PUBKEY"
sha256sum -c <(grep '  cairn-v.*x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS)
```

On macOS use `shasum -a 256 -c ...` instead of `sha256sum -c`. The macOS binaries are unsigned; if
Gatekeeper blocks one, use Finder's right-click **Open** or clear the quarantine attribute. Put the
binary on your `PATH` with:

```sh
install -m 755 cairn ~/.local/bin/cairn
```

Prebuilt Android/Termux binaries are not published; the installer falls back to the source build, or
use the source build below.

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
- **Tor / proxy:** `export CAIRN_TOR=1` uses the local Tor SOCKS port (`127.0.0.1:9050`), or
  `export CAIRN_PROXY=socks5://host:port`. Proxy credentials are redacted in the UI. An invalid
  proxy setting fails closed instead of silently falling back to a direct connection.
- **Descriptors:** `cairn --descriptor [WALLET]` prints the BIP84 receive/change watch-only
  descriptors; add `--json` for machine-readable output. The Info screen also shows them.
- **SeedQR:** `cairn --seedqr [WALLET]` shows a numeric SeedQR after typing `SHOW`. It reveals the
  seed, so use it offline and clear the screen afterwards.
- **Labels:** `cairn --label <TXID> "<label>"` stores a BIP329 `tx` record in
  `~/.cairn/labels.jsonl`; labels appear in the transaction list.

## Network backends

The wallet speaks to one chain through either backend, and both are bound to the wallet's network:

- **Esplora** (default) — HTTPS, with the provider URL guard, redirect rules and response caps.
- **Electrum** — `CAIRN_BACKEND=electrum`, or set `CAIRN_ELECTRUM=host:50002`. The server's
  `genesis_hash` is compared with the wallet's own chain before anything else happens, so a server
  for another network is refused rather than trusted.

```bash
CAIRN_ELECTRUM=electrum.blockstream.info:50002 cairn            # dashboard over Electrum
CAIRN_ELECTRUM=tcp://127.0.0.1:50001 cairn --json --version     # local node, plaintext
```

Balance, history, coins, fee estimates, broadcast and the pre-sign transaction check all go through
whichever backend is selected. Fee bumping stays on Esplora: it needs the previous transaction's
outputs in the shape that backend reports.

## Taproot (BIP86)

A wallet is created (or imported) with one address type, and every address it hands out uses it:

- **Native SegWit (BIP84)**, `m/84'/coin'/0'`, `bc1q…` — the default, accepted everywhere.
- **Taproot (BIP86)**, `m/86'/coin'/0'`, `bc1p…` — key-path only, with cheaper spends.

The choice is stored in the wallet file header and authenticated with the ciphertext, so neither
an attacker nor a corrupted disk can switch a wallet to the other purpose without decryption
failing. Spending a Taproot coin is a single-schnorr-signature key-path spend (BIP341/342,
`SIGHASH_DEFAULT`); the send, fee-bump and offline PSBT flows all handle both script types, and
fee estimates are per input/output type rather than a single average.

## Multisig vaults (2-of-3)

`cairn multisig` builds n-of-m P2WSH vaults whose cosigner keys are spread across machines or
hardware wallets. Creating a vault stores only public data (the cosigner xpubs and their origins)
at `~/.cairn/multisig/<name>.json`, and prints a `wsh(sortedmulti(…))` descriptor you can import
elsewhere. Keys are sorted (BIP67), so the address does not depend on the order the xpubs were
entered in.

Spending is a file hand-off, so no machine ever needs more than one key:

```bash
cairn multisig create --name savings --threshold 2 --cosigner "phone:tpub…" --cosigner "safe:tpub…"
cairn multisig psbt   --name savings --to bc1q… --amount 0.01 --rate 2
cairn multisig sign   --name savings --psbt savings-unsigned.psbt   # on cosigner A
cairn multisig sign   --name savings --psbt savings-unsigned.psbt   # on cosigner B
cairn multisig combine a-signed.psbt b-signed.psbt --out signed.psbt
cairn multisig finalize --psbt signed.psbt --broadcast
```

Each signer refuses a PSBT whose witness script is not the vault's script for the path it lists,
whose key origins are not cosigners of that vault, or whose key does not lock the coin. `finalize`
re-parses the witness script, checks that the UTXO really pays it, requires the threshold of
signatures and verifies every one of them before building the witness. Change is sent to the
vault's change chain, at the index given by `--change-index` (default 0).

## Bumping a pending payment

If a send is stuck because fees rose, the dashboard's **Bump fee** entry replaces it (RBF) instead
of sending again: same inputs, same recipient, same amount, and the additional fee comes out of
your change. The replacement must pay at least 0.5 sat/vB more and a strictly higher absolute fee,
it is refused when the change cannot cover the difference without going below dust, and the normal
fee and rate ceilings still apply. Transactions with no change output, with more than one recipient,
or with inputs from outside the wallet are refused rather than guessed at.

## EVM wallets

One seed, two chains. An existing Cairn wallet derives its EVM account at
`m/44'/60'/0'/0/index`, so there is no second seed phrase and no second keystore. The EVM code
lives beside the Bitcoin code rather than inside it: nothing in the EVM path can build or sign a
PSBT, and nothing in the Bitcoin path can reach an EVM endpoint.

```sh
cairn evm                                          # interactive EVM dashboard
cairn evm chains                                   # supported chains and IDs
cairn evm use base                                 # save a default chain
cairn evm address --qr                             # receive address + QR
cairn evm balance                                  # native balance, token names, USD values
cairn evm token add 0xA0b8...eB48                  # track an ERC-20 (name, symbol, decimals read on-chain)
cairn evm send --to 0x.. --amount 0.05             # build, review, confirm, broadcast
cairn evm send --to 0x.. --amount 25 --token 0xA0b8...eB48
```

Running `cairn evm` with no arguments opens the same kind of dashboard as the Bitcoin side — balance
card, token table, menu, five-minute idle lock — rather than a different-looking command surface.

Supported: Ethereum, Base, Arbitrum One, OP Mainnet, Polygon and Sepolia. Add a chain by adding an
entry to `CHAINS` in `src/evm/chains.rs`; the registry is checked by tests for duplicate IDs and
non-TLS endpoints.

**Offline signing** works the same way as the PSBT flow, with a JSON document instead of a PSBT:

```sh
cairn evm send --to 0x.. --amount 0.05 --build unsigned.ethtx.json   # online: fills nonce, gas, fees
cairn evm sign unsigned.ethtx.json --out signed.ethtx.json           # offline: no network at all
cairn evm broadcast signed.ethtx.json                                # online: sends the raw bytes
```

The unsigned file carries every value that will be signed, and both `sign` and `broadcast`
re-validate it from scratch. `sign` refuses a transaction whose `from` is not the unlocked wallet's
address at that index, and `broadcast` refuses a signed file whose hash does not match its bytes or
the hash the node echoes back.

**Settings:**

- `CAIRN_EVM_CHAIN` or `cairn evm use <chain>` sets the default chain.
- `CAIRN_EVM_RPC=https://your-node` overrides the built-in endpoints. It is still chain-id checked.
- `CAIRN_PROXY` / `CAIRN_TOR=1` apply to EVM RPC traffic as well.
- `CAIRN_NO_PRICE=1` disables the USD estimate, which is fetched from CoinGecko and used for display
  only. `CAIRN_PRICE_API` points it at a different endpoint.

**Not implemented (honest limits):** the EVM side does native transfers and ERC-20 `transfer` calls
only — no swaps, no arbitrary contract calls, no approvals, and no transaction history (that needs
an indexer or an API key). It has not been through the source-level review the Bitcoin path has.

## Security check

`cairn security check [WALLET] [--json]` reports what this build can actually verify for one
wallet: file encryption and format version, file permissions, KDF parameters, ciphertext integrity
(it asks for your password and re-derives the fingerprint), network/Tor configuration, recovery
metadata, and this process's memory protections. It also looks at the machine rather than the
wallet: whether the session is a local terminal or an SSH/pipe session, whether anything is
tracing the process (`TracerPid`, e.g. a debugger that could read the password), loader-injection
variables (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `DYLD_*`) and a system-wide
`/etc/ld.so.preload` hook, PATH entries other users can write to, listening TCP sockets and whether
any of them accept connections from other machines, and the attached USB devices with their
keyboard/HID and storage interfaces.

The malware line scans for real when the machine has an engine to scan with: if ClamAV's
`clamscan` (or `clamdscan`) is installed, Cairn runs it over the running binary and the wallet
directory and reports a signature match as a failing check. Cairn itself ships no signatures or
heuristics — that would be a promise it cannot keep — so without ClamAV the line is `SKIP` with the
reason and an install hint, never `PASS`. A keylogger or an injected library is covered by the
loader, tracer and session lines instead of by signatures. It is also availableIn an interactive terminal the report fills in line by line as each check finishes, with a spinner
over the slow parts (sockets, USB enumeration, the signature scan); `--json` and piped output stay
plain. It is also available from the wallet dashboard. Features Cairn does not have — hardware signers,
multisig, backup verification, final signed-transaction re-display, a third-party audit — are
listed as `SKIP` with the reason, never as `PASS`. A failing check exits non-zero. The report is
not an audit and does not certify a wallet as secure; passing checks only mean nothing in the
inspected set was wrong.

## JSON output

`--json` currently covers `--version`, `--descriptor`, `--label`, `security check` and every
`cairn evm` subcommand. It is intended for scripts and integration tests, not for interactive use.
Errors still go to stderr as text, and `cairn evm` requires an explicit wallet name with `--json`
so the output can never be mixed with an interactive picker.

## Development

```
cargo fmt --check --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1
cargo audit
cargo deny check
```

Tests include the official BIP39 and BIP84 vectors, keystore tamper/network-relabel/passphrase tests,
signature verification, the offline PSBT verify/sign/roundtrip path, PSBT structure caps, fee-rate
ceilings, descriptor/passphrase derivation and QR frame render/scan tests. Fuzz targets live in
`fuzz/` (`url_guard`, `qr_frames`, `psbt`, `keystore`). See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).

## Releasing

Push a version tag to publish downloadable binaries:

```sh
git tag v1.0.0
git push origin v1.0.0
```

The release workflow builds a static Linux x86_64 binary, a Linux ARM64 binary and macOS binaries for
Apple Silicon and Intel, attaches SHA-256 checksums and creates a GitHub Release. When the
`MINISIGN_SECRET_KEY` repository secret is configured it also publishes a signed `SHA256SUMS`
manifest. See [RELEASE-SIGNING.md](RELEASE-SIGNING.md) and [REPRODUCIBLE.md](REPRODUCIBLE.md).

## Roadmap

- [x] Encrypted keystore, create / import / open
- [x] Receive, balance, history, QR
- [x] Send with review and confirmation
- [x] Provider failover and rate pacing
- [x] Offline signer with PSBT and QR transfer (PSBT files and QR images; live camera optional)
- [x] Mainnet support with per-wallet network binding
- [x] Optional BIP39 passphrase (25th word)
- [x] Own Esplora server, SOCKS5/Tor proxy
- [x] Watch-only descriptor export, numeric SeedQR, BIP329 labels, `--json`
- [x] Coin control and fee-rate ceiling
- [x] Fuzzing harness for URL/redirect, QR frames, PSBT and keystore
- [x] Pinned GitHub Actions, cargo-deny, reproducible-build CI check, optional signed releases
- [x] Source-level security review and remediation
- [x] EVM accounts from the same seed (Ethereum, Base, Arbitrum, OP, Polygon, Sepolia)
- [x] ERC-20 balances with token names and USD values, EIP-1559 offline signing and broadcast
- [x] Interactive EVM dashboard in the same shell as the Bitcoin wallet
- [x] RBF fee bumping for unconfirmed sends, from the dashboard
- [ ] 2-of-3 multisig, Electrum protocol, Taproot/BIP86
- [ ] Windows support and packaged installers

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
There is no warranty of any kind.

