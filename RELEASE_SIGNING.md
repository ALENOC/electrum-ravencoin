# Release signing

Electrum-Ravencoin release artifacts use a dedicated Ed25519 release-signing key.

The release key is deliberately separate from both the signed ElectrumX server-registry key and the Ravencoin Core safety-policy key. The private release key is stored locally in the same already-gitignored directory used for the registry key, but under a distinct filename:

```text
.server-registry-key/
├── server-registry-ed25519-private.pem
└── release-signing-ed25519-private.pem
```

Never add, force-add, commit, upload, or paste either private key into GitHub, an issue, a pull request, CI logs, or release assets.

## One-time key creation

Run this from the repository root on the trusted release workstation:

```bash
mkdir -m 700 -p .server-registry-key
umask 077

openssl genpkey -algorithm ED25519 \
  -out .server-registry-key/release-signing-ed25519-private.pem

chmod 600 .server-registry-key/release-signing-ed25519-private.pem

python3 contrib/release_signing.py key-info
python3 contrib/release_signing.py export-public
```

`export-public` writes only the public trust root to `RELEASE_SIGNING_PUBKEY.json`. Review that file before committing it. The private PEM must remain local.

Make a protected offline backup of the private release key before the first public release.

## Release flow

The GitHub Actions release workflow builds the source distribution, Linux AppImage, Windows executables, and macOS DMG. A tag build creates a **draft** GitHub release and attaches the artifacts plus `SHA256SUMS`.

The draft must not be published until `SHA256SUMS` has been signed offline.

After downloading the exact `SHA256SUMS` file from the draft release:

```bash
python3 contrib/release_signing.py sign \
  --manifest SHA256SUMS \
  --output SHA256SUMS.ed25519.json
```

Verify locally before upload:

```bash
python3 contrib/release_signing.py verify \
  --manifest SHA256SUMS \
  --signature SHA256SUMS.ed25519.json
```

Upload `SHA256SUMS.ed25519.json` to the same draft release. Only then should the release be published.

## Verification by users

Users need these three files from the same release:

```text
SHA256SUMS
SHA256SUMS.ed25519.json
RELEASE_SIGNING_PUBKEY.json
```

From a trusted checkout of this repository they can run:

```bash
python3 contrib/release_signing.py verify \
  --manifest SHA256SUMS \
  --signature SHA256SUMS.ed25519.json
```

They can then verify an individual artifact with the normal platform SHA-256 tool against `SHA256SUMS`.

## Key rotation

A release-key rotation is a trust-root change. Commit the new `RELEASE_SIGNING_PUBKEY.json` in a reviewed PR before signing any release with the new private key. Never silently replace the public key only in a release asset.
