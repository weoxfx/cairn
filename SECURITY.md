# Security policy

**Status: experimental, unaudited. Testnet is the default. Mainnet is opt-in only and is not
recommended for real funds until an independent audit is complete.**

## Mainnet gate

Mainnet is disabled by default. It becomes reachable only after either:

- `cairn --enable-mainnet` and a typed `ENABLE MAINNET` confirmation, which writes
  `~/.cairn/mainnet-enabled` (mode 600), or
- `CAIRN_ENABLE_MAINNET=I_UNDERSTAND_UNAUDITED_MAINNET` for one session.

Opening or creating a mainnet wallet then repeats the warning and asks for a typed `MAINNET`
confirmation. The marker is a guard against accidents, not evidence of safety. It does not replace
the independent audit that is still required before anyone should rely on Cairn for real money.

## Review status

An internal, source-level security review was completed on 2026-11-08. It is **not an independent
audit** and does not change the pre-release requirement below. The findings, fixes and residual risks
are recorded in [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

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
  tampered file cannot weaken the key derivation or exhaust memory. Version 2 authenticates the
  network, fingerprint, KDF parameters, salt and nonce in the AAD, so relabelling a mainnet wallet
  as testnet (or downgrading its KDF) fails decryption. Version 1 testnet wallets remain readable.
- **Session:** after unlock only the public account key is kept. Temporary private keys
  derived while building the watch-only view are erased. The seed is wiped. The network code
  never has access to anything that can spend. The session re-locks after 5 minutes idle.
- **Sending:** password re-entry, keys must match the wallet session and each coin's script, amounts
  are checked to add up and capped at 21 million BTC, minimum fee check, explicit `SEND`
  confirmation, deterministic signatures. Server-provided txids are validated before display.
- **Offline signing:** `--offline` performs no network I/O. It rejects an already-signed PSBT,
  checks every input belongs to the loaded wallet with an `m/84'/coin'/0'/chain/index` key origin
  for the wallet's network and a matching P2WPKH script, classifies change against the wallet's
  addresses, rejects amounts above the money supply, enforces a minimum fee, and requires `SEND`.
  PSBT files are capped at 5 MB and must be regular files (no FIFOs). The online `--broadcast` step
  rejects a signed PSBT whose unsigned transaction or input metadata differs from the unsigned file
  it was given.
- **QR transport:** `--qr-show` splits a PSBT into versioned frames with a short SHA-256 checksum.
  `--qr-scan` reassembles them in any order, rejects missing, mixed or corrupt frames, caps image
  dimensions and decoding memory, and the resulting PSBT goes through the same offline verification
  before anything is signed.
- **Network:** HTTPS-only certificate-verified requests (HTTP and HTTPS-to-HTTP redirects are
  refused), response size limits, request pacing, provider failover, and a chain-aware URL guard:
  testnet wallets refuse mainnet endpoints, mainnet wallets refuse testnet/signet endpoints.
  Responses are treated as untrusted: amounts are bounded, txids are validated and terminal control
  characters are stripped before server text reaches the screen. This prevents the common
  wrong-chain accident and response-driven display attacks, not a malicious server in general.
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
- Short-lived copies of secrets that libraries do not wipe (for example the password prompt and some
  key types). Erasing is best-effort, and secrets are not `mlock`ed, so a swapped or hibernated
  machine can still expose them.
- **API redirects:** the client refuses HTTP and HTTPS-to-HTTP redirects, but still follows ordinary
  HTTPS redirects to another host. No key material is sent, and responses remain untrusted, but a
  malicious provider can redirect availability and metadata requests.
- Privacy against the API server: it sees your IP and the addresses you query. Use your own server
  or Tor (planned).
- Weak passwords, screen capture and shoulder surfing.
- The mainnet opt-in marker can be deleted or forged by anyone who can write to your home directory.
  It is an accident guard, not an authorization boundary.
- No independent audit has been done. Mainnet support existing in the code is not an audit result and
  must not be read as one.

## Rules for contributors

- Never implement your own cryptography. Use audited libraries.
- Keep dependencies minimal, pinned (commit `Cargo.lock`) and checked with `cargo audit`.
- Never log, print or store secrets. Never add telemetry.
- Anything touching keys, signing or the keystore needs tests and a careful review.
- Never present mainnet as audited or recommended. Keep it opt-in and keep the warnings.

## Before any release

`cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked --release -- --test-threads=1`, `cargo audit`, review the diff of
`Cargo.lock`, and sign the release. An independent audit and remediation are required before mainnet
is recommended or described as safe.

