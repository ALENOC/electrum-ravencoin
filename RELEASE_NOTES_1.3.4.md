# Electrum-Ravencoin 1.3.4

This release carries the Ledger changes tested in 1.3.4rc1. A Nano S Plus user reported that Electrum 1.3.3 detected the device and then displayed status 6F00 in the Install Wizard. The command that failed on that device is still unknown. [Issue #20](https://github.com/ALENOC/electrum-ravencoin/issues/20)

The legacy Ledger plugin requests the master fingerprint from the device. If that command returns 6F00, it can compute the same fingerprint from the root public key. When a storage parent read returns 6F00, Electrum requests the leaf public key at the original storage path. For an existing encrypted file, the wizard can try the alternate storage key already supported in 1.3.3. The wallet opens only if the file authenticates successfully. A device that blocks the original key may still be unable to open the file.

Automated tests cover pairing, the Ledger status words and opening encrypted wallets. Confirmation on physical Ledger hardware is still pending. To test, back up the wallet file, close Ledger Live, unlock the device and open the Ravencoin app. Opening the wallet requires no recovery phrase or transaction signature.

Downloads include the Windows standalone executable, portable executable and installer (32-bit), Linux x86_64 AppImage, Intel macOS DMG and source archive. Verify SHA256SUMS and its Ed25519 signature using the official release public key. [Verification instructions](https://github.com/ALENOC/electrum-ravencoin/blob/1.3.4/RELEASE_SIGNING.md)
