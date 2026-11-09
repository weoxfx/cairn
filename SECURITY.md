# Security policy

**Status: source-level security review completed. Mainnet is the default for new wallets; testnet
is available for development and testing.**

## Network selection

Mainnet is the default when creating or importing a wallet. Testnet (Testnet4, Testnet3 and Signet)
can be selected instead. A wallet's network is recorded in the keystore, authenticated by the v2/v3
AAD and bound to the matching API; cross-chain endpoints are refused.

## Review status

Source-level reviews were completed on 2026-11-08 and 2026-11-09. The
review of commit `b620147` found no Critical or High code vulnerability under its documented threat
model, and the 2026-11-09 pass remediated the earlier Medium/Low findings. The findings, fixes and
residual risks are recorded in [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

## Reporting a vulnerability

Please report privately and do not open a public issue or post exploit details first.

- Use GitHub's **"Report a vulnerability"** button (Security tab, private advisory), or
- contact the maintainers privately if an address is listed on the repository profile.

Include what you found, how to reproduce it and the impact. We aim to acknowledge reports within
a few days and to credit reporters who want it. Good-faith research is welcome.

## What is protected

- **Seed generation:** 256 bits from the OS random source, BIP39, shown once on the alternate
  screen and then cleared.
- **Seed import:** the hidden phrase must be entered twice; a mismatch saves nothing.
- **Wallet file:** Argon2id (128 MB, 3 passes) then ChaCha20-Poly1305, mode 600 in a 700 folder,
  atomic no-replace writes that never follow a symlink. Symlinks and oversized files are refused;
  `~/.cairn` and its wallet directory must be real directories and are kept at mode 700. KDF
  parameters are validated against tight bounds (19 MiB–256 MiB, 2–10 passes, 1–4 lanes) so a
  tampered file cannot weaken the key derivation or exhaust memory. Version 2 authenticates the
  network, fingerprint, KDF parameters, salt and nonce in the AAD, so relabelling a mainnet wallet
  as testnet (or downgrading its KDF) fails decryption. Version 3 additionally authenticates whether
  a BIP39 passphrase is required; the passphrase itself is never stored. Version 1 and 2 wallets
  remain readable.
- **BIP39 passphrase:** an optional 25th-word passphrase is mixed into BIP39 seed derivation before
  BIP32/BIP84. It is asked for at creation/import and at unlock, never written to disk, and losing it
  makes the wallet unrecoverable. Wallet fingerprints and addresses therefore differ from the
  no-passphrase wallet even with the same 24 words.
- **Session:** after unlock only the public account key is kept. The decrypted mnemonic and the
  signer's key allocation are held in `mlock`ed heap allocations when the OS allows it, and erased
  on drop. Temporary private keys derived while building the watch-only view are erased. The
  network code never has access to anything that can spend. The watch-only dashboard re-locks after
  5 minutes idle.
- **Sending:** password re-entry, keys must match the wallet session and each coin's script, amounts
  are checked to add up and capped at 21 million BTC. Duplicate coins are rejected, and selected
  coins are re-checked against the transaction that created them (value and address must match)
  before review. Coin control lets the user choose which UTXOs are spent. A fee ceiling rejects
  more than 10% of the recipient amount (with a 10,000-sat floor for ordinary small sends) or more
  than 1,000,000 sats absolute, and a 1,000 sat/vB rate ceiling rejects hidden-fee estimates. Explicit
  `SEND` confirmation and deterministic signatures. Server-provided txids are validated before
  display.
- **Offline signing:** `--offline` performs no network I/O. It rejects an already-signed PSBT,
  checks every input belongs to the loaded wallet with an `m/84'/coin'/0'/chain/index` key origin
  for the wallet's network and a matching P2WPKH script, rejects duplicate inputs and non-zero
  locktimes, classifies change against the wallet's addresses, rejects amounts above the money
  supply, caps the PSBT at 500 inputs and 500 outputs, enforces a minimum fee, the fee ceiling and
  the 1,000 sat/vB rate ceiling, and requires `SEND`.
  PSBT files are capped at 5 MB, must be regular files and are opened with `O_NOFOLLOW` (no FIFOs or
  symlinks); signed output is written atomically with mode 600. The online `--broadcast` step
  rejects a signed PSBT whose unsigned transaction or input metadata differs from the unsigned file
  it was given.
- **QR transport:** `--qr-show` splits a PSBT into versioned frames with a short SHA-256 checksum.
  `--qr-scan` reassembles them in any order, rejects missing, mixed or corrupt frames, caps image
  dimensions and decoding memory, and the resulting PSBT goes through the same offline verification
  before anything is signed.
- **Network:** HTTPS-only certificate-verified requests. Redirects are followed manually and only
  to the same origin (host and port), with HTTPS and the chain-specific guard re-checked; broadcasts
  refuse redirects entirely. API authorities must be hostnames or IPv4 literals; userinfo and IPv6
  literals are rejected to avoid parser differentials. Testnet4, Testnet3 and Signet each require
  their own URL segment, and mainnet rejects any testnet segment. Response size limits fail closed,
  with request pacing, provider failover, and no cross-chain endpoints.
  Responses are treated as untrusted: UTXO/input/output/balance/history amounts and block heights are
  bounded, txids are validated, and server-supplied text is reduced to printable ASCII and spaces
  by an allowlist with a length cap before it reaches the screen. This prevents the common
  wrong-chain accident and response-driven display/redirect attacks, not a malicious server in
  general.
- **Process:** core dumps disabled, umask 077. On Linux and Android the process is also marked
  non-dumpable; other platforms rely on the core-dump limit and OS protections.

## What is NOT protected (known limits)

- Malware, root access or a compromised device. A phone or PC that is online is not an air-gapped
  signer. The offline signer supports files and QR images, but live camera capture and a hardened
  air-gapped workflow are still planned.
- **QR data is public:** screenshots and photos of a PSBT expose its addresses, amounts and public
  keys to anyone who sees them. The frame checksum detects damage or mixed files; it does not prove
  who created the PSBT. Always read the verification screen before signing.
- **Offline PSBT limits:** the offline machine cannot independently look up UTXO values, so the
  amounts it displays come from the PSBT file. Verify the total and fee against what the online
  wallet showed before signing. The offline PSBT checks do not replace reading the review screen.
- **Fee checks differ:** the offline verifier applies the percentage fee ceiling to non-wallet
  outputs; `--broadcast` applies it to all outputs, including change, so it is slightly looser for a
  PSBT signed elsewhere (L-01 residual). Both paths apply the absolute 1,000,000-sat cap and the
  1,000 sat/vB rate ceiling. Review the fee before broadcasting.
- Short-lived copies of secrets that libraries do not wipe (for example the password prompt and some
  key types). Erasing is best-effort. The decrypted mnemonic and signer keys are `mlock`ed when the
  OS allows it, but locking can be refused (for example by `RLIMIT_MEMLOCK`) and is not a guarantee;
  a swapped or hibernated machine can still expose them in that case.
- **API redirects:** the client refuses cross-origin, non-HTTPS and broadcast redirects.
  Same-origin HTTPS redirects are still followed, so a malicious provider can change paths and
  metadata exposure within its own host and port. No key material is sent, and responses remain
  untrusted.
- Privacy against the API server: it sees your IP and the addresses you query. Provider failover
  queries the same set at every configured provider. Use your own server, or `CAIRN_TOR=1` /
  `CAIRN_PROXY=socks5://host:port` to route through Tor or another proxy. Tor hides your IP from the
  provider; the provider still sees the addresses unless you also run your own server.
- Address scanning stops at the configured gap and the 200-address ceiling. Activity beyond that
  window may not appear until a wider scan is implemented.
- Weak passwords, screen capture and shoulder surfing.

## Rules for contributors

- Never implement your own cryptography. Use audited libraries.
- Keep dependencies minimal, pinned (commit `Cargo.lock`) and checked with `cargo audit`.
- Never log, print or store secrets. Never add telemetry.
- Anything touching keys, signing or the keystore needs tests and a careful review.
- Keep network binding strict and make sure every review screen shows the real destination and
  amount before a transaction can be approved.

## Before any release

`cargo fmt --check --all`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked --release -- --test-threads=1`, `cargo audit`, `cargo deny check`, review the
diff of `Cargo.lock`, confirm the reproducible-build job passes, and sign the release. Keep this
threat model and [SECURITY-REVIEW.md](SECURITY-REVIEW.md) current.

