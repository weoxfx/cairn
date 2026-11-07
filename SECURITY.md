# Security policy

**Status: experimental, unaudited, testnet only. Do not use real funds.**

## Reporting a vulnerability

Please report privately and do not open a public issue or post exploit details first.

- Use GitHub's **"Report a vulnerability"** button (Security tab, private advisory), or
- contact the maintainers privately if an address is listed on the repository profile.

Include what you found, how to reproduce it and the impact. We aim to acknowledge reports within
a few days and to credit reporters who want it. Good-faith research is welcome.

## What is protected

- **Seed generation:** 256 bits from the OS random source, BIP39, shown once on the alternate
  screen and then cleared.
- **Wallet file:** Argon2id (128 MB, 3 passes) then ChaCha20-Poly1305, mode 600 in a 700 folder,
  atomic writes. Symlinks and oversized files are refused. KDF parameters are validated so a
  tampered file cannot weaken the key derivation or exhaust memory.
- **Session:** after unlock only the public account key is kept. The seed is wiped. The network
  code never has access to anything that can spend. The session re-locks after 5 minutes idle.
- **Sending:** password re-entry, keys must match the wallet session and each coin's script, amounts
  are checked to add up, minimum fee check, explicit `SEND` confirmation, deterministic signatures.
- **Network:** certificate-verified HTTPS, response size limits, request pacing, provider failover,
  testnet/signet-only URL guard. Server responses are untrusted.
- **Process:** core dumps disabled, process marked non-dumpable, umask 077.

## What is NOT protected (known limits)

- Malware, root access or a compromised device. A phone or PC that is online is not an air-gapped
  signer. The offline signer is on the roadmap.
- Short-lived copies of secrets that libraries do not wipe (for example the password prompt and some
  key types). Erasing is best-effort.
- Privacy against the API server: it sees your IP and the addresses you query. Use your own server
  or Tor (planned).
- Weak passwords, screen capture and shoulder surfing.
- No independent audit has been done.

## Rules for contributors

- Never implement your own cryptography. Use audited libraries.
- Keep dependencies minimal, pinned (commit `Cargo.lock`) and checked with `cargo audit`.
- Never log, print or store secrets. Never add telemetry.
- Anything touching keys, signing or the keystore needs tests and a careful review.

## Before any release

`cargo test --release`, `cargo clippy -- -D warnings`, `cargo audit`, review the diff of
`Cargo.lock`, and sign the release. An independent audit is required before mainnet is supported.

