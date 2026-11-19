# Electrum-Ravencoin 1.3.4rc1 - Ledger compatibility test release

This experimental release addresses the Nano S Plus report in [issue #20](https://github.com/ALENOC/electrum-ravencoin/issues/20). The reporter's [1.3.3 screenshot](https://x.com/WeitaoB54770/status/2123245382444662813) shows status 6F00 in the Install Wizard after device detection. It does not identify the command that failed.

The legacy Ledger plugin still reads GET_MASTER_FINGERPRINT first. If that command returns 6F00, the plugin tries to compute the same fingerprint from the root public key. When a storage parent read returns 6F00, it requests the public key at the original storage path. When opening an existing wallet, the wizard can try the other 1.3.3 storage key if the standard key is unavailable. The file must authenticate successfully before it opens. If the device blocks the key originally used, the file remains encrypted.

Diagnostics record the failed operation and status word. Automated Ledger tests passed, including opening encrypted wallet files. Compatibility still needs verification on real Ledger hardware.

The downloads include the Windows standalone executable, portable executable and installer (32-bit Wine build), Linux x86_64 AppImage, Intel macOS DMG and source archive. Verify SHA256SUMS and its Ed25519 signature using the project's release public key. The manifest signature is separate from platform code signing.

For testing, back up your wallet file and keep 1.3.3 available. Close Ledger Live, unlock your Ledger, open the Ravencoin app and try opening the wallet. Testing this change requires no recovery phrase, transaction signature or transfer.
