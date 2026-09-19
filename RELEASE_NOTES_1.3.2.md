# Electrum-Ravencoin 1.3.2

1.3.2 is a maintenance release that fixes hardware wallet detection for Ledger
devices running the official Ravencoin application.

## Hardware wallet support

- Fixed Ledger hardware wallet detection and pairing. Previously, connecting a
  Ledger device with the official Ravencoin app open (version 2.0.6) failed
  with `ValueError: Ledger is not in either the Bitcoin or Bitcoin Testnet app`
  during client construction. The plugin was attempting to initialize the device
  via `ledger_bitcoin.createClient()`, an upstream Bitcoin library that enforces
  an allowlist of Bitcoin application names. Because the exception was unhandled,
  the hardware wallet manager failed to create the client and reported no
  connected device.
- Device construction now routes directly to the legacy `btchip` client
  (`Ledger_Client_Legacy`), which is the native protocol implemented by the
  official Ledger Ravencoin application.

## Distribution

This release ships:

- source distribution (`.tar.gz`)
- Linux x86_64 AppImage
- Windows executables produced by the repository's deterministic Wine build
- macOS x86_64 DMG

The macOS artifact is x86_64. Native Apple Silicon packaging can be added after
the current deterministic macOS pipeline has been ported and validated for
arm64.

OS-level code signing and notarization may not be present on every artifact.
Integrity is independently covered by the release `SHA256SUMS` manifest and the
dedicated offline Ed25519 release signature. Verify both before running a
binary.

## Important trust note

This client is a lightweight wallet. It does not replace full Ravencoin
consensus validation performed by Ravencoin Core. Its security model validates
and authorizes ElectrumX backends and SPV evidence within the capabilities of a
lightweight client.

This is a community-maintained Electrum-Ravencoin release and is not an official
release of the Ravencoin Foundation or the original Electrum project.
