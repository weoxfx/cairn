# Internal security review — 2026-11-08

**Status: internal source review, NOT an independent audit.**

This document records a source-level review of Cairn performed by the project's own tooling and
maintainer workflow. It is not a third-party audit, not a penetration test, and not evidence that
mainnet use is safe. The recommendation remains: do not use Cairn for real funds you cannot afford
to lose until an independent audit and remediation are complete.

## Scope

Reviewed at commit state immediately before the review's fixes (working tree, version 0.2.0):

- Wallet creation/import, BIP39/BIP32/BIP84 derivation, watch-only separation.
- Encrypted keystore, KDF parameters, authenticated metadata, v1 compatibility, file handling.
- Online send flow, coin selection, fee calculation, address/amount parsing, signing.
- Offline PSBT verify/sign/broadcast path and QR transport.
- Esplora HTTP layer, provider failover, chain-aware URL guard, untrusted response handling.
- Mainnet selection and confirmation, UI network labels, process hardening, docs and CI configuration.

Dependencies were scanned with `cargo audit`. The review relied on manual reading and the existing
test suite; it did not include formal verification, fuzzing, side-channel analysis, live mainnet
testing or third-party code review.

## Verification run

All of the following passed after the fixes in this document:

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release -- --test-threads=1   # 47 passed
cargo audit                                        # 0 vulnerabilities, 155 dependencies
cargo build --locked --release
```

## Summary

No critical or high-severity issue was found that would let a remote API server, PSBT file or QR
image exfiltrate the seed or forge a signature under the documented threat model. The signing and
keystore designs are small and use audited primitives; no home-made cryptography was found.

Several medium/low issues were found around **untrusted numeric input, terminal output, memory
bounds and secret hygiene**. All were fixed in this review. The remaining items are accepted risks
or require an independent audit to assess properly.

## Findings

| ID | Severity | Area | Status |
|---|---|---|---|
| S-01 | Medium | Unbounded server/PSBT amounts | Fixed |
| S-02 | Medium | Terminal escape injection from server text | Fixed |
| S-03 | Medium | Memory amplification from API responses | Fixed |
| S-04 | Low | Unbounded PSBT file read / FIFO hang | Fixed |
| S-05 | Low | QR image decode allocation limits | Fixed |
| S-06 | Low | Secret erasure gaps and long-lived per-input keys | Fixed |
| S-07 | Low | CI workflow would not run on GitHub | Fixed |
| S-08 | Low | Mainnet banner state after cancelling confirmation | Fixed |
| S-09 | Low | KDF upper bound allows local 1 GiB work factor | Fixed (bounded) |
| S-10 | Info | Cross-host / malformed-host HTTPS redirects | Fixed |
| S-11 | Info | Mainnet confirmation is an accident guard, not authorization | Accepted |
| S-12 | Info | No `mlock`; terminal wiping is best effort | Mitigated (best effort) |
| S-13 | Info | Testnet variants share coin type 1 and URL-based identification | Accepted |

### S-01 — Unbounded server/PSBT amounts (fixed)

**Impact:** a malicious or compromised API server, or a crafted PSBT, could supply values above the
21 million BTC supply. This could produce misleading review screens, overflow later casts to `i64`,
or make the wallet construct an obviously invalid transaction. It does not directly steal coins:
BIP143 signatures commit to each spent output's value, so a lie about a value normally makes the
transaction invalid rather than redirecting funds.

**Fix:** added `network::MAX_MONEY_SATS` and enforced it in:

- `esplora::parse_utxo` (server UTXO values) plus checked conversion of `vout` to `u32`.
- `send::plan` (aggregate input total).
- `offline::verify_psbt` (per-input, total input, per-output and total output).
- `offline::broadcast` (documented transaction outputs and witness UTXOs).

Regression tests cover absurd UTXO, input and output values.

### S-02 — Terminal escape injection from server text (fixed)

**Impact:** server-controlled strings were printed more or less directly in two places: the `txid`
field in the transaction list and HTTP error/broadcast response bodies. A malicious API could embed
ANSI/OSC control sequences, potentially spoofing terminal output or abusing terminal features such
as clipboard access. No key material was exposed.

**Fix:** transaction txids are parsed as `bitcoin::Txid` and invalid entries are skipped. Error bodies
and unexpected broadcast responses are passed through `safe_text`, which strips control characters
and invisible Unicode format characters (bidi overrides, zero-width, BOM) and bounds length. A
regression test checks the sanitiser and `parse_utxo` validation.

### S-03 — Memory amplification from API responses (fixed)

**Impact:** `transactions` fetched a page for every used address and retained all parsed pages before
processing, and UTXO fetching could accumulate an unbounded number of entries within the response
body cap. A malicious server could force large memory use on a phone or small machine.

**Fix:** transaction pages are processed in bounded batches; total transaction summaries are capped
at 100,000; UTXOs are capped at 10,000 per address and 20,000 per wallet. Oversized or absurd
responses fail closed with an error instead of being retained.

### S-04 — Unbounded PSBT file read / FIFO hang (fixed)

**Impact:** PSBT files were read with `fs::read`, without a size cap, and opening a FIFO could block
the process indefinitely. This is primarily a local denial-of-service / robustness issue.

**Fix:** PSBTs are capped at 5 MB, opened with `O_NOFOLLOW | O_NONBLOCK` and required to be regular
files. Signed output is written atomically with mode 600. Tests cover oversized files, directories
and symlinks.

### S-05 — QR image decode allocation limits (fixed)

**Impact:** decoding attacker-supplied images could allocate very large buffers before QR detection.

**Fix:** image dimensions are capped at 8000×8000 and decoder allocation at 64 MiB. QR frame
reassembly was already bounded to 256 frames × 200 bytes and validates frame counts, indexes,
checksums and chunk lengths.

### S-06 — Secret erasure gaps (fixed)

**Impact:** several temporary copies of private key material were dropped without a best-effort
erase, and `Signer::sign_psbt` kept every input's derived secret key in a vector until the signing
pass. This is a memory-hygiene issue, not a known extraction path.

**Fix:** `Watch::from_mnemonic` and `keystore::fingerprint` erase temporary `Xpriv` material;
`Signer::key_at` erases the derived child key and keypair; `sign_psbt` validates with a short-lived
key, erases it, then re-derives one key at a time while signing. Online `send::sign` also erases the
per-input key after use. Erasure remains best effort because Rust moves and compiler optimisations can
leave copies.

### S-07 — CI workflow location (fixed)

**Impact:** `ci.yml` was at the repository root, where GitHub Actions does not look, so the intended
format/clippy/test/audit gates would not run.

**Fix:** moved to `.github/workflows/ci.yml`. The workflow pins Rust 1.98.1, uses `--locked`, denies
clippy warnings, runs tests single-threaded and denies `cargo audit` warnings.

### S-08 — Mainnet banner after cancel (fixed)

**Impact:** cancelling the mainnet confirmation could leave the terminal displaying the mainnet
banner while the session was still effectively testnet/default. Cosmetic and potentially
confusing, not an authorisation bypass.

**Fix:** reset the display network to testnet when confirmation is cancelled.

### S-09 — KDF upper bound allows local work-factor DoS (fixed, bounded)

A locally modified wallet file could previously select KDF parameters up to 1 GiB / 20 passes /
parallelism 16, and that work was performed before authentication failed. Accepted parameters are now
capped at 256 MiB / 10 passes / 4 lanes (new wallets use 128 MiB / 3 / 1), and salt, nonce and
ciphertext lengths are checked before any KDF work. A forged file can still force bounded work, but
it can no longer request gigabytes of memory or minutes of CPU. An attacker who can already write the
wallet file can also simply delete or corrupt it.

### S-10 — Cross-origin and malformed-host HTTPS redirects (fixed)

Automatic redirects are now disabled in the HTTP agent and followed manually. A redirect must stay on
the same origin (host and port), remain HTTPS and still pass the chain-specific URL guard; anything
else fails closed. `--broadcast` refuses redirects entirely. The parser preserves the port on
relative redirects, rejects userinfo and IPv6 literals, and compares the full authority. Redirect
resolution and same-origin checks have unit tests. The remaining exposure is same-origin path changes
by the provider, which cannot receive keys or change what a response means.

### S-11 — Mainnet selection is an accident guard (accepted)

Mainnet is chosen when creating or importing a wallet, while testnet remains the default. That
choice shows a short notice that Cairn is experimental and unaudited, then asks for a default-no
confirmation. Opening a wallet uses its recorded network without another prompt. The UI does not
claim safety, and mainnet spends still go through the normal review screens. This prevents accidental
chain selection, not a compromised account. This is documented in `SECURITY.md`.

### S-12 — Memory locking; terminal wiping is best effort (mitigated, best effort)

The decrypted mnemonic and the signer's key allocation are now `mlock`ed when the OS allows it, so
they are less likely to reach swap. Locking can be refused (for example by a low `RLIMIT_MEMLOCK`)
and is not a guarantee; if it fails, swap/hibernation can still capture secrets. The seed display
uses the terminal's alternate screen and clears it afterwards, but terminal emulators, tmux logging
and screen capture may retain it. Users must trust the device and terminal.

### S-13 — Testnet variants share coin type 1 (accepted)

Testnet4, Testnet3 and Signet share BIP84 coin type 1 and the same address prefixes. The API setting
and URL guard select the chain; there is no cryptographic chain identifier in the address. A wrong
testnet choice cannot lose real funds, but it can show the wrong testnet history. Mainnet is separated
by coin type 0 and address prefix.

## Additional hardening (2026-11-08)

Beyond the findings above, the same pass also:

- Made `.cairn`, the wallet directory, the network config and PSBT output symlink-safe: symlinked
  directories are refused, private files are replaced atomically (`O_NOFOLLOW` temp file + rename)
  with mode 600.
- Extended server-text sanitisation to invisible Unicode format characters in addition to control
  characters.
- Bounded per-address API balances to the 21 million BTC supply and represent negative mempool
  deltas without allowing a negative total, so a lying server cannot display an impossible balance.
- Capped a `--qr-scan` invocation at 1024 images.
- Took the HTTP user agent from `CARGO_PKG_VERSION` instead of a hard-coded version that could drift.

## Second-pass review (2026-11-08)

A fresh adversarial pass over the hardening diff found three issues. All three are fixed in this tree:

- **A-01 (Low, fixed) — URL parser differential.** The manual redirect check parsed hosts itself, while the
  HTTP client uses the WHATWG URL parser. In a URL such as `https://evil.example\@mempool.space/api`
  the client treats `\` as a path separator and connects to `evil.example`, while the check saw
  `mempool.space` and allowed the redirect. URLs containing control characters, whitespace or
  backslashes are now rejected before parsing, so the same-host comparison and the actual connection
  agree. Covered by assertions in the URL-guard and redirect tests.
- **A-02 (Info, fixed) — aggregate display balance.** Per-address balances were capped at 21M BTC, but a
  collection of lying responses could still display more. Synced totals are now capped as well.
- **A-03 (Low, fixed) — FIFO config hang.** `~/.cairn/config` was opened with `O_NOFOLLOW` but without
  `O_NONBLOCK`, so a planted FIFO could block startup before the regular-file check. The config is now
  opened non-blocking, like wallet and PSBT files.

Accepted, not changed:

- A same-origin HTTPS redirect can still change the path. It remains on the provider's host and port,
  no keys are sent, and responses stay untrusted, so this is metadata exposure only.
- `--qr-show` / `--qr-scan` display a mainnet label inferred from an untrusted PSBT before the
  interactive confirmation. They never sign or use the network, and signing/broadcasting still go
  through the normal review screens.
- Directory creation and chmod have the usual same-user TOCTOU window. Same-user malware is outside the
  threat model.

## Third-pass hardening (2026-11-08)

- **H-01 (Medium, fixed) — fee ceiling.** `send::plan` now rejects a fee above 10% of the recipient
  amount (with a 10,000-sat floor for ordinary small sends) or above 1,000,000 sats absolute. Server
  estimates and manual entry were already clamped to 1..=1000 sat/vB; this adds the missing hard
  stop and bounds what a malicious estimate can burn. The same ceiling is enforced by the offline
  PSBT verifier and by `--broadcast`.
- **H-02 (Low, fixed) — prevout cross-check.** Before review, the online side re-fetches each
  selected coin's creating transaction and compares the output's value and address with the UTXO
  endpoint. A mismatch, missing output or unconfirmed status fails closed. Verification is capped at
  100 unique transactions. The offline signer cannot do this and still relies on the PSBT's witness
  UTXO, as documented.
- **H-03 (Info, mitigated) — memory locking.** The decrypted mnemonic and the signer's key
  allocation are `mlock`ed best effort. Failure is non-fatal and documented; this reduces but does
  not eliminate swap/hibernation exposure.
- **H-04 (Info, fixed) — PSBT fuzz target.** `psbt_guard::check_structure` holds the
  wallet-independent structural and arithmetic checks used by the offline verifier, and `fuzz/psbt`
  exercises deserialization plus those checks.

## External AI-assisted review triage (2026-11-08)

An external AI reviewer produced `audit.txt` against code commit `5c96ea2`. It had no Rust toolchain,
so it read the source and ran Python PoCs but could not execute this test suite or the fuzzers. This
was an AI-assisted review, not an independent audit. Triage:

- **BLOCK-01 (High, fixed) — IPv6 same-host redirect bypass.** `url_parts` split an authority at the
  first `:`, so `[2001:db8::1]` became `[2001`; two different IPv6 hosts could compare equal. The
  parser now rejects bracketed and unbracketed IPv6 authorities before the same-host check; API URLs
  must be hostnames or IPv4 literals. Regression assertions cover `[2001:db8::1]`, `[::1]` and an
  unbracketed literal.
- **BLOCK-02 (Medium, no code change) — missing tag/history.** The reviewer's snapshot had one commit
  and no tags; the full history is now on `master`. The old `audit-2026-11-08` tag was removed
  because it pointed at a stale package commit, so use a pinned commit hash for any re-review.
- **INF-01 (Info, accepted).** The 10,000-sat floor intentionally allows a normal minimum fee on
  dust-sized sends; a 10,000-sat fee on a 294-sat output is still shown with its sat/vB and a
  percentage warning, and the absolute 1,000,000-sat cap remains. Lowering the floor would reject
  legitimate small sends at relay-feasible rates.
- **INF-02 (Info, fixed).** `psbt_guard::check_structure` and `send::plan` now reject repeated
  outpoints; offline and online selection have regression tests and the PSBT fuzzer exercises the
  shared check.
- **INF-03 (Info, accepted).** Offline verification must trust the PSBT's witness UTXO values; BIP143
  commits to them, so a lie makes the signature invalid. The review screen states this and the online
  side re-fetches prevouts. This remains documented residual risk.
- **INF-04 (Info, fixed).** The offline verifier and `--broadcast` reject a non-zero locktime. Cairn
  builds immediate transactions only; this prevents a PSBT from freezing funds until a future
  height/time.
- **INF-05 (Info, fixed).** A negative mempool delta is legitimate when an address spends a confirmed
  coin. It is no longer clamped to zero; pending totals are allowed to go negative but never below a
  zero confirmed balance.
- **INF-06 (Info, accepted).** A PSBT can influence the cosmetic network banner before the signature
  gate; no key or signing decision uses that label. Accepted as display-only, as before.
- **INF-07 (Info, accepted).** The file is chmod 0600 before authentication. This reduces ciphertext
  exposure while the password prompt is open; a different local user cannot read it and same-user
  malware is out of scope.
- **INF-08 (Info, fixed).** The derived `SecretKey` used only to compare public keys in
  `verify_psbt` is now erased immediately.
- **INF-09 (Info, accepted).** Testnet4, Testnet3 and Signet share coin type 1; the operator selects
  the network and the URL guard separates it from mainnet. Documented limitation.
- **INF-10 (Info, accepted).** The 5-minute lock covers the watch-only dashboard menu; the seed has
  already been dropped, and QR/PSBT screens are separate commands. No spending key is held there.
- **INF-11 (Info, accepted).** Wallet stems are displayed from a 0700 directory and never executed;
  ANSI spoofing requires write access to the user's wallet directory (same-user, out of scope).
- **INF-12 (Info, clean).** The reviewer's RustSec cross-check found no affected locked dependency.

The fixes are committed in `1e87e5d`; later review fixes are committed in `41dd624`. A second
source-only AI-assisted review at `1e87e5d` found no blocking issue and re-confirmed the fixes and
accepted residuals. It also lacked a Rust toolchain and saw no tag or earlier commits in its snapshot.
The full history is on `master`. The old `audit-2026-11-08` tag was removed because it pointed at the
stale `704bee7` package commit; no tag currently represents an audit.

## Latest external AI-assisted review triage (2026-11-08)

A further source-only AI review of `1e87e5d` found no Critical/High code issue and one process
problem. It was not an independent audit, and its snapshot again lacked tags/history. Findings:

- **AUD-01 (Medium, process, partially addressed) — reproducibility.** The review snapshot did not
  identify the tree it examined, and the old package tag was stale. `AUDIT-PACKAGE.md` now pins
  `41dd624` / tree `4a89ef9c6dccdabbd934c83118926027ebc84a5c` and includes the latest fixes. The
  stale tag was removed. A new tag should only be created for the independent-audit package; this
  is not a code vulnerability, but an independent audit is still required.
- **AUD-02 (Low, fixed) — testnet chain confusion.** The guard accepted any testnet name for any
  testnet, so a Testnet4 wallet could follow a same-host redirect to `testnet`/`signet`. Each testnet
  now requires its own segment (`testnet4`; `testnet`/`testnet3`; `signet`), and chain names in the
  query string are ignored.
- **AUD-03 (Low, fixed) — redirect authority loss.** Relative redirects dropped the port, and
  same-host redirects with a different port or userinfo were accepted. Redirects now preserve the
  authority, compare host and port, and reject userinfo. Regression assertions cover both.
- **AUD-04 (Low, fixed) — display-network coupling.** The transaction screen used the cosmetic
  display network instead of `watch.network()`; it now receives the wallet's actual network.
- **AUD-05 (Low, fixed) — silent import typo.** Import parsed one hidden seed entry and printed only
  the fingerprint. It now asks for the hidden phrase twice and saves nothing on a mismatch.
- **AUD-06 (Info, fixed).** Broadcast failures that are not a definitive server rejection are now
  reported as `Broadcast status unknown`, not `Not sent`.
- **AUD-07 (Info, fixed).** A response body over the 2 MB cap now fails closed instead of being
  silently truncated.
- **AUD-08 (Info, accepted).** CI actions use mutable major tags. Pin commit SHAs before a release;
  the runner inputs are not part of the wallet's trust boundary today.
- **AUD-09 (Info, accepted).** Provider failover queries the same address set at each provider, so
  every configured provider learns it. This is a privacy tradeoff of failover; use one trusted
  provider or Tor when that matters.
- **AUD-10 (Info, accepted).** Scanning stops at the configured gap and the 200-address ceiling. A
  wallet with activity beyond that window needs a wider scan; this must be addressed before mainnet.
- **AUD-11 (Info, fixed).** `Opened::drop` now zeroizes the mnemonic before releasing its `mlock`.

The latest fixes are committed in `41dd624`; no audit tag is published. Pin that commit and tree
hash for the next review, and create a new tag only when the independent audit is engaged.

## Fuzzing harness (2026-11-08)

`fuzz/` links the real parser modules through a new library target (`src/lib.rs`, `[lib] test = false`)
and runs coverage-guided libFuzzer targets:

- `url_guard` — URL/redirect parsing. Asserts resolved targets stay HTTPS, contain no control
  characters, whitespace or backslashes, and always parse. Also covers malformed absolute targets
  such as `https://` and `//`, which `resolve_redirect` now rejects instead of returning them.
- `qr_frames` — arbitrary frame lists; accepted payloads are re-encoded and must round-trip
  byte-identically.
- `psbt` — PSBT deserialization plus the shared structure/arithmetic checks; accepted PSBTs must
  re-serialize and parse again.

Short smoke runs completed with no crashes or artifacts: the latest `url_guard` run after the
chain/authority fixes did 121,403 executions, and `psbt` did 67,843, in 10 seconds each. CI repeats
each for 120 seconds weekly. This is a harness addition, not an audit. Keystore JSON still needs a
pure adapter before it can be fuzzed through the library.

## Positive observations

- Sends cap the fee and cross-check every selected prevout online; the offline verifier shares its
  structural checks with the fuzz target.
- The keystore uses Argon2id and ChaCha20-Poly1305 from RustCrypto, with random salt and nonce per
  save. v2 AAD binds network, fingerprint, KDF parameters, salt and nonce; relabelling or parameter
  downgrade fails authentication.
- v1 files are accepted only as testnet, matching their historical scope.
- Wallet files are created atomically with mode 0600, read with `O_NOFOLLOW`, size limits and a
  regular-file check.
- The watch-only session keeps only an account xpub; the seed is dropped after unlock.
- Both signing paths validate each input's fingerprint, network-specific BIP84 path, P2WPKH script
  and `SIGHASH_ALL` before signing. `Signer::sign_psbt` deliberately does not trust the first partial
  signature.
- Offline `--broadcast` compares the signed PSBT's unsigned transaction and input metadata with the
  original unsigned file, and the offline review classifies change against the wallet's scripts.
- Mainnet is explicit: testnet is the default, selection uses a default-no confirmation,
  chain-aware `net_for` binds wallets to the matching API, and the URL guard rejects cross-chain
  endpoints.
- `cargo audit` is clean and the dependency set is small.

## Residual risk and release recommendation

This review does not replace an independent audit. Before mainnet is recommended or described as
safe, the project still needs at least:

1. An independent third-party audit of keystore, derivation, signing, PSBT and network paths, with
   remediation of findings.
2. Fuzzing of PSBT, QR frame, image and JSON parsers.
3. Live integration tests against each supported Esplora provider and testnet, plus a mainnet
   dry-run plan that does not risk funds.
4. Platform testing on Linux, macOS and Termux/Android, including terminal behaviour and process
   hardening differences.
5. A review of `mlock` failure behavior (locking is best effort) and further local-file DoS limits;
   cross-host redirects, the fee ceiling, prevout checks and the KDF upper bound are now addressed.

Until then: keep testnet as the default, keep mainnet explicit and clearly labelled unaudited, and
do not use Cairn for meaningful real funds.
