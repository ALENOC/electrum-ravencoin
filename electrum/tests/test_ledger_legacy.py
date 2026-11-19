import os
from unittest.mock import MagicMock, patch

from electrum import bip32, ecc
from electrum.base_wizard import BaseWizard, HWD_SETUP_DECRYPT_WALLET
from electrum.crypto import hash_160
from electrum.keystore import Xpub
from electrum.plugin import DeviceMgr, DeviceUnpairableError
from electrum.storage import WalletStorage, StorageEncryptionVersion, get_derivation_used_for_hw_device_encryption
from electrum.plugins.ledger.ledger import (
    BTChipException,
    Ledger_Client_Legacy,
    LedgerPlugin,
    test_pin_unlocked,
)
from electrum.util import InvalidPassword, UserFacingException

from . import ElectrumTestCase


def _compressed_pubkey_and_uncompressed_bytes(secret_byte: int):
    privkey = bytes([secret_byte]) * 32
    pub_compressed = ecc.ECPrivkey(privkey).get_public_key_bytes(compressed=True)
    pub_uncompressed = ecc.ECPrivkey(privkey).get_public_key_bytes(compressed=False)
    return pub_compressed, bytearray(pub_uncompressed)


class _DummyHardenedLedgerDongle:
    """Simulates a Ledger device running Ravencoin app >= 2.4.10 with
    PATH_APP_LOAD_PARAMS = "*/175'" and INS_GET_MASTER_FINGERPRINT (0xD0).
    """

    BTCHIP_CLA = 0xE0

    def __init__(self, *, support_get_master_fp: bool = True):
        self.support_get_master_fp = support_get_master_fp
        self.master_pub_compressed, self.master_pub_uncompressed = (
            _compressed_pubkey_and_uncompressed_bytes(1)
        )
        self.parent_pub_compressed, self.parent_pub_uncompressed = (
            _compressed_pubkey_and_uncompressed_bytes(2)
        )
        self.node_pub_compressed, self.node_pub_uncompressed = (
            _compressed_pubkey_and_uncompressed_bytes(3)
        )
        self.standard_storage_key, self.standard_storage_raw = (
            _compressed_pubkey_and_uncompressed_bytes(4)
        )
        self.master_fp = hash_160(self.master_pub_compressed)[0:4]
        self.requested_paths = []
        self.exchanged_apdus = []
        self.dongle = MagicMock()
        self.dongle.exchange.side_effect = self._exchange

    def _exchange(self, apdu: bytearray):
        self.exchanged_apdus.append(bytes(apdu))
        if len(apdu) >= 2 and apdu[0] == 0xE0 and apdu[1] == 0xD0:
            if not self.support_get_master_fp:
                raise BTChipException("INS not supported", sw=0x6D00)
            return bytearray(self.master_fp)
        raise BTChipException("Unsupported APDU", sw=0x6D00)

    def getFirmwareVersion(self):
        return {
            "version": "2.4.15",
            "specialVersion": 0,
        }

    def getWalletPublicKey(self, path: str, **kwargs):
        self.requested_paths.append(path)
        norm_path = path.replace("h", "'").replace("H", "'")
        if self.support_get_master_fp:
            # Hardened app >= 2.4.10 enforces PATH_APP_LOAD_PARAMS = "*/175'"
            parts = [p for p in norm_path.split("/") if p]
            if len(parts) < 2 or parts[1] != "175'":
                raise BTChipException("Conditions of use not satisfied", sw=0x6985)
        if norm_path == "4541509'/1112098098'":
            return {"publicKey": self.standard_storage_raw, "chainCode": bytes(32)}
        if norm_path == "":
            return {
                "publicKey": self.master_pub_uncompressed,
                "chainCode": bytes([0x11]) * 32,
            }
        if norm_path in ("44'/175'", "4541509'/175'"):
            return {
                "publicKey": self.parent_pub_uncompressed,
                "chainCode": bytes([0x22]) * 32,
            }
        return {
            "publicKey": self.node_pub_uncompressed,
            "chainCode": bytes([0x33]) * 32,
        }


def _make_legacy_client(dongle: _DummyHardenedLedgerDongle) -> Ledger_Client_Legacy:
    client = Ledger_Client_Legacy.__new__(Ledger_Client_Legacy)
    client.plugin = MagicMock()
    client.dongleObject = dongle
    client.signing = False
    client._product_key = (0x2C97, 0x5011)  # Ledger Nano S Plus
    client._soft_device_id = None
    return client


class TestLedgerLegacyHardenedApp(ElectrumTestCase):

    def test_master_fingerprint_uses_apdu_0xd0_without_deriving_master_or_m0h(self):
        dongle = _DummyHardenedLedgerDongle(support_get_master_fp=True)
        client = _make_legacy_client(dongle)

        fp_bytes = client.get_master_fingerprint()
        self.assertEqual(fp_bytes, dongle.master_fp)
        self.assertEqual(
            client.request_root_fingerprint_from_device(), dongle.master_fp.hex()
        )
        self.assertEqual(client.get_soft_device_id(), dongle.master_fp.hex())
        self.assertEqual(dongle.requested_paths, [])
        self.assertTrue(
            any(apdu == b"\xe0\xd0\x00\x00\x00" for apdu in dongle.exchanged_apdus)
        )

    def test_master_fingerprint_falls_back_to_root_pubkey_on_older_app(self):
        dongle = _DummyHardenedLedgerDongle(support_get_master_fp=False)
        client = _make_legacy_client(dongle)

        fp_bytes = client.get_master_fingerprint()
        self.assertEqual(fp_bytes, dongle.master_fp)
        self.assertEqual(dongle.requested_paths, [""])

    def test_get_xpub_for_ravencoin_account_path_succeeds_under_path_hardening(self):
        dongle = _DummyHardenedLedgerDongle(support_get_master_fp=True)
        client = _make_legacy_client(dongle)

        xpub = client.get_xpub("m/44'/175'/0'", "standard")
        node = bip32.BIP32Node.from_xkey(xpub)
        self.assertEqual(node.depth, 3)
        self.assertEqual(
            node.fingerprint, hash_160(dongle.parent_pub_compressed)[0:4]
        )
        norm_paths = [p.replace("h", "'") for p in dongle.requested_paths]
        self.assertEqual(norm_paths, ["44'/175'", "44'/175'/0'"])

    def test_storage_encryption_password_falls_back_when_standard_path_is_blocked(self):
        dongle = _DummyHardenedLedgerDongle(support_get_master_fp=True)
        client = _make_legacy_client(dongle)

        pw = client.get_password_for_storage_encryption()
        self.assertEqual(pw, dongle.node_pub_compressed.hex())
        self.assertEqual(
            client.get_fallback_password_for_storage_encryption(),
            dongle.node_pub_compressed.hex(),
        )
        norm_paths = [p.replace("h", "'") for p in dongle.requested_paths]
        # First attempt at 4541509' fails under "*/175'", then falls back to 4541509'/175'/0'
        self.assertIn("4541509'", norm_paths)
        self.assertIn("4541509'/175'", norm_paths)
        self.assertIn("4541509'/175'/0'", norm_paths)

    def test_pin_unlocked_decorator_translates_btchip_status_words(self):
        class _Dummy:
            @test_pin_unlocked
            def locked_call(self):
                raise BTChipException("Security status not satisfied", sw=0x6982)

            @test_pin_unlocked
            def cla_not_supported_call(self):
                raise BTChipException("CLA not supported", sw=0x6E00)

        dummy = _Dummy()
        with self.assertRaises(UserFacingException) as ctx_locked:
            dummy.locked_call()
        self.assertIn("locked", str(ctx_locked.exception).lower())

        with self.assertRaises(UserFacingException) as ctx_app:
            dummy.cla_not_supported_call()
        self.assertIn("ravencoin app", str(ctx_app.exception).lower())

    def test_fingerprint_status_and_malformed_response(self):
        for sw in (0x6F00, 0x6D00, 0x6A80, 0x6B00, 0x6985):
            with self.subTest(sw=sw):
                dongle = _DummyHardenedLedgerDongle(support_get_master_fp=False)
                dongle.dongle.exchange.side_effect = BTChipException("device detail", sw)
                client = _make_legacy_client(dongle)
                if sw == 0x6985:
                    with self.assertRaises(BTChipException):
                        client.get_soft_device_id()
                    self.assertEqual(dongle.requested_paths, [])
                else:
                    self.assertEqual(client.get_soft_device_id(), dongle.master_fp.hex())
                    self.assertEqual(client.get_soft_device_id(), dongle.master_fp.hex())
                    self.assertEqual(dongle.requested_paths, [""])
        for response in (b"", b"123", b"12345"):
            for library_method in (False, True):
                dongle = _DummyHardenedLedgerDongle()
                if library_method:
                    dongle.getMasterFingerprint = MagicMock(return_value=response)
                else:
                    dongle.dongle.exchange.side_effect = None
                    dongle.dongle.exchange.return_value = response
                with self.assertRaises(UserFacingException):
                    _make_legacy_client(dongle).get_master_fingerprint()
                self.assertEqual(dongle.requested_paths, [])

    def test_root_fallback_failure_preserves_error_and_logs_only_operation_and_sw(self):
        dongle = _DummyHardenedLedgerDongle()
        dongle.dongle.exchange.side_effect = BTChipException("sensitive detail", 0x6F00)
        client = _make_legacy_client(dongle)
        with self.assertLogs("electrum.plugins.ledger.ledger", "INFO") as logs:
            with self.assertRaises(BTChipException) as failure:
                client.get_soft_device_id()
        self.assertEqual(failure.exception.sw, 0x6985)
        self.assertIsNone(client._soft_device_id)
        self.assertEqual(dongle.requested_paths, [""])
        self.assertEqual([r.getMessage() for r in logs.records], [
            "Ledger GET_MASTER_FINGERPRINT failed (sw=0x6f00)",
            "Ledger root public key failed (sw=0x6985)",
        ])

    def test_pairing_requires_original_account_xpub(self):
        client = _make_legacy_client(_DummyHardenedLedgerDongle())
        km = MagicMock()
        path = "m/44'/175'/0'"
        km.get_derivation_prefix.return_value = path
        km.xpub = client.get_xpub(path, "standard")
        dm = MagicMock()
        dm._client_by_id.return_value = client
        args = dict(plugin=client.plugin, handler=MagicMock(), info=MagicMock(), keystore=km)
        self.assertIs(DeviceMgr.force_pair_keystore(dm, **args), client)
        km.xpub = client.get_xpub("m/44'/175'/1'", "standard")
        with self.assertRaises(DeviceUnpairableError):
            DeviceMgr.force_pair_keystore(dm, **args)

    def test_storage_6f00_is_scoped_to_operation_and_existing_wallet(self):
        dongle = _DummyHardenedLedgerDongle(support_get_master_fp=False)
        read_key = dongle.getWalletPublicKey
        client = _make_legacy_client(dongle)
        standard = get_derivation_used_for_hw_device_encryption()
        scoped = client._get_fallback_storage_encryption_derivation()
        # Use the original xpub algorithm to make two distinct BIE2 fixtures.
        keys = [Xpub.get_pubkey_from_xpub(client.get_xpub(path, "standard"), ()).hex()
                for path in (standard, scoped)]
        self.assertNotEqual(*keys)
        blocked = {"4541509'"}

        def read(path):
            if path.replace("h", "'") in blocked:
                raise BTChipException("sensitive detail", 0x6F00)
            return read_key(path)

        with patch.object(dongle, "getWalletPublicKey", side_effect=read):
            self.assertEqual(client.get_password_for_storage_encryption(), keys[0])
            for i, key in enumerate(keys):
                file_path = os.path.join(self.electrum_path, str(i))
                storage = WalletStorage(file_path)
                storage.set_password(key, StorageEncryptionVersion.XPUB_PASSWORD)
                storage.write("original contents")
                raw = storage.raw
                if i:
                    blocked.add("4541509'/1112098098'")
                    with self.assertRaises(BTChipException):
                        client.get_password_for_storage_encryption()
                storage = WalletStorage(file_path)
                wizard = MagicMock()
                plugin = MagicMock(spec=LedgerPlugin)
                plugin.setup_device.return_value = client
                wizard.plugins.get_plugin.return_value = plugin
                BaseWizard.on_device(wizard, "ledger", MagicMock(),
                                     purpose=HWD_SETUP_DECRYPT_WALLET, storage=storage)
                self.assertEqual(storage.read(), "original contents")
                self.assertEqual(WalletStorage(file_path).raw, raw)
            # An inaccessible old standard key cannot be replaced by the scoped key.
            storage = WalletStorage(os.path.join(self.electrum_path, "0"))
            with self.assertRaises(InvalidPassword):
                BaseWizard.on_device(wizard, "ledger", MagicMock(),
                                     purpose=HWD_SETUP_DECRYPT_WALLET, storage=storage)
            self.assertFalse(storage.is_past_initial_decryption())
            blocked.add("4541509'/175'/0'")
            with self.assertRaises(BTChipException):
                client.get_password_for_storage_decryption()

    def test_firmware_and_account_errors_do_not_switch_derivation(self):
        dongle = _DummyHardenedLedgerDongle()
        client = _make_legacy_client(dongle)
        with patch.object(dongle, "getFirmwareVersion", side_effect=BTChipException("detail", 0x6F00)):
            with self.assertRaises(BTChipException):
                client.get_password_for_storage_decryption()
            self.assertEqual(dongle.requested_paths, [])
        for sw in (0x6F00, 0x6D00, 0x6A80, 0x6B00, 0x6985):
            with patch.object(dongle, "getWalletPublicKey", side_effect=BTChipException("detail", sw)) as read:
                with self.assertRaises((BTChipException, UserFacingException)):
                    client.get_xpub("m/44'/175'/0'", "standard")
                self.assertEqual(read.call_count, 1)

    def test_recognize_modern_ledger_models(self):
        self.assertEqual(
            LedgerPlugin._recognize_device((0x2C97, 0x5011)),
            (True, "Ledger Nano S Plus"),
        )
        self.assertEqual(
            LedgerPlugin._recognize_device((0x2C97, 0x7011)),
            (True, "Ledger Flex"),
        )
        self.assertEqual(
            LedgerPlugin._recognize_device((0x2C97, 0x8011)),
            (True, "Ledger Nano Gen5"),
        )
