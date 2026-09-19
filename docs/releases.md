# Releases

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Building](building.md) · [Core certification](core-certification.md)

The maintained release is **1.3.2**, published on the
[releases page](https://github.com/ALENOC/electrum-ravencoin/releases) with a
source distribution, a Linux x86_64 AppImage, Windows executables and an x86_64
macOS DMG. It must not be confused with upstream Electrum binaries or with a
certified Ravencoin Core release: a wallet release says nothing about which Core
build a server runs.

Every release carries a `SHA256SUMS` manifest and a detached Ed25519 signature
over that manifest, produced offline. A release is only maintained once both
verify. Live deployment validation remains a separate gate from Core release
certification.

Release procedure: the tag must equal `ELECTRUM_VERSION` exactly, the build
workflow produces the artifact set and a draft release, and the draft is
published only after `SHA256SUMS` has been signed offline.
