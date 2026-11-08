# Cairn

An open-source Bitcoin wallet for the command line, built around an encrypted keystore, a
watch-only session and careful sending.

> **EXPERIMENTAL. UNAUDITED. TESTNET BY DEFAULT.**
> Mainnet is available from the network menu after a one-time confirmation. It is still
> experimental and nobody independent has reviewed this code; do not use real funds you cannot
> afford to lose.

## What it does today

- Create, import and open wallets (BIP39, 24 words, native SegWit / BIP84)
- Encrypted wallet file (Argon2id + ChaCha20-Poly1305, authenticated metadata)
- Balance, transaction list, receive addresses with QR codes
- Send: address and amount validation, fee choice, full review screen,
  type `SEND` to confirm, password re-entry, then sign and broadcast
- Offline signing (file or QR transport): build an unsigned PSBT online, sign it on a
  machine with no network, then broadcast it after the online side verifies it
- Works on Testnet4, Testnet3 and Signet, with provider failover and request pacing
- Mainnet can be selected from the network menu; testnet remains the default
- Runs on Linux, macOS and Android (Termux)

## Mainnet

Cairn is built and tested testnet-first, and testnet remains the default. Mainnet is chosen when
creating or importing a wallet, without any extra setup. That choice shows a short
experimental/unaudited notice and asks for confirmation. Opening an existing wallet uses its
recorded network without another prompt.

Mainnet is **not audited** and must not be treated as safe for real savings. New wallets record
their network, and the API layer refuses a testnet wallet pointed at a mainnet server (and the
reverse). Use testnet, or a hardware/reviewed wallet, for anything you cannot afford to lose.

## Security design

| Area | What Cairn does |
|---|---|
| Seed | 256 bits from the OS random source, shown once on the terminal's alternate screen (no scrollback), then a 3-word backup quiz. Import asks for the hidden phrase twice |
| Storage | Only the encrypted entropy is saved. Argon2id (128 MB, 3 passes) then ChaCha20-Poly1305. The v2 AAD authenticates network, fingerprint, KDF parameters, salt and nonce. Atomic writes that never follow a symlink, mode 600, `.cairn` kept at 700, symlinked wallet dirs refused, KDF bounds enforced on load. v1 testnet wallets still open |
| Memory | After unlock only the public account key (xpub) is kept. The decrypted mnemonic and signing keys are held in `mlock`ed allocations when the OS allows it, and erased on drop. Spending keys exist only for the moment of signing |
| Sending | Re-asks the password, checks the keys match the wallet and each coin, re-fetches each spent coin's creating transaction to compare value/address, checks that the amounts add up, enforces a fee ceiling (10% of the amount, 10k-sat floor, 1M-sat hard cap), uses deterministic (RFC6979) signatures |
| Offline | `--offline` never opens a socket. It checks that every input belongs to the wallet, has the expected network-specific BIP84 path and script, that change is ours and that the fee clears the relay minimum. PSBT files must be regular files (no FIFOs or symlinks) and signed output is written atomically at mode 600. The online side refuses a signed PSBT that changed any input or output. QR frames are checksummed and then go through the same checks; they are public data, not encrypted |
| Network | HTTPS-only with certificate checks; redirects are same-origin (host and port) and re-checked, broadcasts refuse them. Response size caps fail closed, with rate pacing, failover and a chain-specific URL guard; userinfo and IPv6 authorities are rejected. Server data is treated as untrusted; amounts and balances bounded, txids validated, control characters and invisible Unicode format characters stripped |
| Mainnet | Available from the network menu; testnet remains the default. Selecting it shows a short experimental/unaudited notice and a default-no confirmation. This is an accident guard, not an audit |
| Process | No core dumps, umask 077, 5-minute idle lock; non-dumpable on Linux/Android |

Cryptographic primitives come from audited libraries (rust-bitcoin, libsecp256k1, RustCrypto).
Cairn does not implement its own cryptography. See [SECURITY.md](SECURITY.md) for the threat model,
known limits and how to report a vulnerability. An internal review is documented in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md); it is not a substitute for an independent audit.

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

## Roadmap

- [x] Encrypted keystore, create / import / open
- [x] Receive, balance, history, QR
- [x] Send with review and confirmation
- [x] Provider failover and rate pacing
- [x] Offline signer with PSBT and QR transfer (PSBT files and QR images; live camera optional)
- [x] Experimental, unaudited mainnet support
- [ ] Optional passphrase (25th word), 2-of-3 multisig
- [ ] Own-node support (Electrum protocol), Tor
- [x] Fuzzing harness for URL/redirect, QR frames and PSBT (keystore pending)
- [ ] Reproducible builds and independent audit (required before recommending mainnet)

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
There is no warranty of any kind.

