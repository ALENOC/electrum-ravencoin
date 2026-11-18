# Electrum-Ravencoin 1.3.3

1.3.3 is a maintenance release that fixes Ledger hardware wallet compatibility
with the updated official Ledger Ravencoin application (`2.4.10` through
`2.4.15+`) and refreshes the signed ElectrumX discovery registry.

## Hardware wallet support

- Fixed Ledger connection, pairing, and wallet creation with the updated
  official Ledger Ravencoin application (`2.4.10` / `2.4.11` / `2.4.15+`).
  Starting with `app-bitcoin-legacy` 2.4.10, Ledger enabled BIP-32 derivation
  path hardening (`PATH_APP_LOAD_PARAMS = "*/175'"`) and removed the
  `HAVE_APPLICATION_FLAG_DERIVE_MASTER` permission for altcoin apps. As a
  result, the Ledger device rejected root/unscoped key derivation calls
  (`m/0'` and `m`) used during device discovery (`get_soft_device_id()`) and
  initial device setup (`get_master_fingerprint()`), preventing Electrum-Ravencoin
  from connecting to the device.
- `Ledger_Client_Legacy` now queries the 4-byte master key fingerprint via the
  dedicated `INS_GET_MASTER_FINGERPRINT` (`0xE0 0xD0 0x00 0x00 0x00`) APDU
  introduced in `app-bitcoin-legacy` 2.4.11, which does not require master key
  derivation permissions, and falls back to `getWalletPublicKey("")` on older
  Ledger app versions.
- Added an automatic fallback for Ledger hardware-derived wallet file encryption
  (`get_password_for_storage_encryption()`). Because Ledger's Ravencoin app
  manifest currently restricts derivations strictly to `"*/175'"` without
  whitelisting Electrum's standard `m/4541509'/1112098098'` encryption path,
  `Ledger_Client_Legacy` automatically falls back to the coin-type-scoped path
  `m/4541509'/175'/0'` when the device rejects the legacy path.
  *(Note: if you previously encrypted a local wallet file with an older Ledger
  Ravencoin app version `< 2.4.10`, simply create a new wallet file via
  `Create New Wallet -> Standard wallet -> Use a hardware device` to reconnect
  your Ledger; your funds on `m/44'/175'/0'` are unaffected).*
- Added USB/HID model recognition for newer Ledger devices including Ledger
  Stax, Ledger Flex, and Ledger Nano Gen5, and improved user-facing messages
  when the Ledger device is locked or the Ravencoin app is not open.

## Server discovery and transport

- `electrum/servers.json` and signed server registry v5
  (`electrum/servers.signed.json`) now retain only the authenticated
  `electrumx.raventag.com` endpoint.
- Added transparent WebSocket-over-TLS (`wss://<host>:443`) transport fallback
  in `Interface` (`_RSClient` / `_AiohttpWSTransport`) when direct TCP port
  `50002` is proxied behind Cloudflare Tunnel.

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
