# Electrum-Ravencoin 1.3.5

This release fixes wallet creation with a Ledger running the Ravencoin app 2.4.15. In 1.3.4 the Install Wizard showed "Invalid status 6f00" after the device was detected, and no new hardware wallet could be created. [Issue #20](https://github.com/ALENOC/electrum-ravencoin/issues/20)

The Ravencoin app now only derives keys under `*/175'`. When it refuses a path it answers status 6F00. Before creating a hardware wallet, Electrum reads a public key used to encrypt the wallet file. The standard path `m/4541509'/1112098098'` is refused, so Electrum now uses `m/4541509'/175'/0'` for both new and existing files. When opening a file, Electrum tries the standard key first and the coin-scoped key second.

A wallet file encrypted with the standard key before the Ledger app update cannot be opened with the updated app, because the device no longer derives that key. Funds are not affected: the file holds addresses, labels and history, not coins. Create a new wallet file with File > New/Restore > Standard wallet > Use a hardware device, and the RVN on `m/44'/175'/0'` will appear again.

To test, back up the wallet file, close Ledger Live, unlock the device and open the Ravencoin app. Creating or opening the wallet requires no recovery phrase or transaction signature.

Downloads include the Windows standalone executable, portable executable and installer (32-bit), Linux x86_64 AppImage, Intel macOS DMG and source archive. Verify SHA256SUMS and its Ed25519 signature using the official release public key. [Verification instructions](https://github.com/ALENOC/electrum-ravencoin/blob/1.3.5/RELEASE_SIGNING.md)
