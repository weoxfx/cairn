# Cairn security notes

**Status: experimental, unaudited, testnet only. Do not use real funds.**

## What is protected
- Seed: OS randomness (256 bits), BIP39. Stored only as Argon2id + ChaCha20-Poly1305 ciphertext.
- Wallet file: mode 600 in a 700 folder, atomic writes, symlinks and oversized files refused,
  KDF parameters validated (a tampered file can't weaken the KDF or exhaust memory).
- After unlock only the public account key is kept; the seed is wiped. Network code never sees it.
- Seed is shown on the terminal's alternate screen (no scrollback) and cleared.
- Process hardening: no core dumps, not dumpable by other processes, umask 077.
- Network: HTTPS (certificate-verified), response size caps, testnet-only URL guard.
  Server data is untrusted and used for display only.
- Session re-locks after 5 minutes idle; Send will require the password again.

## What is NOT protected (known limits)
- Malware or root on the same device (Termux is not an air-gapped signer).
- The password prompt library may keep short-lived copies of typed text in memory.
- The explorer server learns your IP and addresses (use your own node or Tor later).
- Screen recording, shoulder surfing, and a weak password.
- No independent audit yet.

## Report a vulnerability
Open a private security advisory on the repository (to be set up). Please don't post exploits publicly first.

## Checks before any release
`cargo test --release`, `cargo clippy -- -D warnings`, `cargo audit`, `cargo deny check`.

