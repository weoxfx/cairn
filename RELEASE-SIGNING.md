# Release signing

Release archives are checksummed with SHA-256 and the combined `SHA256SUMS` manifest
can be signed with [minisign](https://jedisct1.github.io/minisign/). Signing is
optional and controlled by a repository secret; when no key is configured the
release is still published with checksums, but the installer prints an explicit
warning instead of pretending the download is authenticated.

**A signature is not a safety guarantee.** A valid signature proves that the holder of a key
produced the manifest. It does not prove that the code is correct or safe.

## One-time key setup

Generate a passwordless key on an offline machine:

```sh
minisign -G -W -p cairn.pub -s cairn.key
```

`-W` creates a key with no password so CI can use it unattended. Treat `cairn.key`
as a high-value secret: anyone who has it can sign a release. Store only the secret
key text in the GitHub Actions secret `MINISIGN_SECRET_KEY`; commit or publish only
the public key.

The public key (`cairn.pub`) is a short base64 string. Publish it in the README and
in the release notes, and give it to users out of band when possible. Users pass it
to the installer as `CAIRN_MINISIGN_PUBKEY`.

## Publishing a signed release

The `publish` job in `.github/workflows/release.yml` reads
`secrets.MINISIGN_SECRET_KEY`. When the secret is set it:

1. builds `dist/SHA256SUMS` from the per-archive checksums;
2. signs it as `dist/SHA256SUMS.minisig`;
3. uploads both files with the release.

When the secret is not set the signing step is skipped. Do not describe an unsigned
release as signed.

## Verifying a release

With the project public key:

```sh
export CAIRN_MINISIGN_PUBKEY='RW...'
curl -fsSL https://raw.githubusercontent.com/weoxfx/cairn/master/install.sh | sh
```

The installer downloads `SHA256SUMS` and `SHA256SUMS.minisig`, verifies the signature,
checks that the selected archive is listed in the signed manifest, then verifies the
archive hash. If `CAIRN_MINISIGN_PUBKEY` is unset it falls back to the per-archive
`.sha256` file and prints a warning that the checksum is not signed.

Manual verification:

```sh
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P "$CAIRN_MINISIGN_PUBKEY"
grep '  cairn-v0.2.0-x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS
sha256sum -c <(grep '  cairn-v0.2.0-x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS)
```

## Key rotation and compromise

- Keep the key offline except when rotating the CI secret. Prefer a dedicated
  release-signing key, not a personal SSH or GPG key.
- If the secret may have leaked, remove it from GitHub, publish a notice, generate a
  new key, and re-sign future releases with the new public key. Old signatures
  remain valid for old releases; tell users which key covers which version.
- A compromised CI runner can sign a malicious build before the signature is made.
  Pinned action SHAs, `--locked` builds, branch protection and a short secret
  lifetime reduce, but do not eliminate, that risk. Reproducible builds are the
  defence that lets users detect it.

## Current status

Cairn is experimental. See [SECURITY.md](SECURITY.md) for the review status and known
limits before using it with real funds.
