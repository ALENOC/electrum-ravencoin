# Electrum-Ravencoin 1.3.0rc3

This is a community-maintained release candidate focused on Ravencoin network safety, backend validation, and hardened distribution after the August 2026 Ravencoin consensus incident.

## Changes since 1.3.0rc2

- Fixed release-manifest generation so `SHA256SUMS` never contains a checksum for itself and is verified with `sha256sum -c` before upload.
- Fixed macOS release version capture so generated build files cannot cause an erroneous `-dirty` DMG filename; CI now rejects dirty release DMGs explicitly.
- The release signing public-key metadata is included in the generated SHA256 manifest.
- Added Cipig's public Ravencoin ElectrumX endpoints (`electrum1.cipig.net`, `electrum2.cipig.net`, and `electrum3.cipig.net`) after the RavenTag anchor and before `rvn4lyfe.com`. Cipig has confirmed a Ravencoin Core 4.8.0 backend; these endpoints remain discovery-only until the hardened `server.ravencoin_backend` capability is implemented and independently verified.

## Security and network changes

- Ravencoin mainnet ElectrumX endpoints must satisfy the client backend-safety contract before they can participate in trusted reads or transaction broadcast.
- Ravencoin Core 4.8.0 is the current supported baseline; later releases require explicit safety certification rather than being trusted only because their version number is higher.
- Trusted `operatorGroup` identity is bound to the exact signed TLS endpoint `(hostname, TLS protocol, port)`.
- TLS first contact is fail-closed for unexpected self-signed certificates.
- The signed ElectrumX server registry supports authenticated runtime updates, expiry, anti-rollback state, and same-version/different-content equivocation rejection.
- The Ravencoin Core safety-policy state rejects rollback and same-version/different-content equivocation.
- Wallet-file encryption uses BIE3 with scrypt for password-derived keys, with migration support for older BIE1 wallets after successful unlock.
- SPV read authorization and transaction broadcast are rechecked at the security-sensitive point of use.

## Distribution

This release candidate is intended to ship:

- source distribution (`.tar.gz`)
- Linux x86_64 AppImage
- Windows executables produced by the repository's deterministic Wine build
- macOS x86_64 DMG

The macOS RC artifact is x86_64. Native Apple Silicon packaging can be added after the current deterministic macOS pipeline has been ported and validated for arm64.

OS-level code signing/notarization may not be present on every RC artifact. Integrity is independently covered by the release `SHA256SUMS` manifest and the dedicated offline Ed25519 release signature.

## Important trust note

This client is a lightweight wallet. It does not replace full Ravencoin consensus validation performed by Ravencoin Core. Its security model validates and authorizes ElectrumX backends and SPV evidence within the capabilities of a lightweight client.

## Release-candidate status

`1.3.0rc3` should be tested on real Windows, Linux, and macOS installations before promotion to `1.3.0`.

Recommended smoke tests include wallet creation/opening, legacy wallet-file migration, synchronization, history and balance retrieval, receive, a small-value real RVN send/broadcast, restart, and signed server-registry update behavior.

This is a community-maintained Electrum-Ravencoin release and is not an official release of the Ravencoin Foundation or the original Electrum project.
