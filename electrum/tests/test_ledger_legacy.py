from unittest.mock import MagicMock

from electrum import bip32, ecc
from electrum.crypto import hash_160
from electrum.plugins.ledger.ledger import (
    BTChipException,
    Ledger_Client_Legacy,
    LedgerPlugin,
    test_pin_unlocked,
)
from electrum.util import UserFacingException

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
