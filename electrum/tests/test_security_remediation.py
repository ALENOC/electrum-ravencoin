import base64
import os
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, Mock

from electrum import constants
from electrum.address_synchronizer import AddressSynchronizer
from electrum.blockchain import Blockchain, InvalidHeader
from electrum.interface import ErrorGettingSSLCertFromServer, Interface
from electrum.network import Network, WriteAuthorization, WriteAuthorizationState
from electrum.ravencoin_backend import BackendEligibilityState
from electrum.storage import (
    SCRYPT_N, SCRYPT_R, SCRYPT_SALT_LEN,
    StorageEncryptionVersion, WalletStorage,
)
from electrum.util import InvalidPassword


class TestKawpowAlgorithmDowngrade(unittest.TestCase):
    def setUp(self):
        constants.set_mainnet()

    def tearDown(self):
        constants.set_mainnet()

    def test_post_activation_height_cannot_select_legacy_hashing_by_timestamp(self):
        height = constants.net.KawpowActivationHeight + 1
        target = (1 << 256) - 1
        header = {
            "version": 4,
            "prev_block_hash": "11" * 32,
            "merkle_root": "22" * 32,
            "timestamp": constants.net.KawpowActivationTS - 1,
            "bits": Blockchain.target_to_bits(target),
            "nonce": 0,
            "block_height": height,
        }
        with self.assertRaisesRegex(InvalidHeader, "legacy PoW"):
            Blockchain.verify_header(header, header["prev_block_hash"], target)


class TestBackendClaimNaming(unittest.TestCase):
    def test_old_safe_core_name_is_only_a_compatibility_alias(self):
        self.assertIs(
            BackendEligibilityState.SAFE_CORE_VERIFIED,
            BackendEligibilityState.POLICY_CONFORMING_BACKEND_CLAIM,
        )
        self.assertEqual(
            "POLICY_CONFORMING_BACKEND_CLAIM",
            BackendEligibilityState.SAFE_CORE_VERIFIED.name,
        )


class TestTlsFirstContact(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def bare_interface(fingerprint):
        interface = object.__new__(Interface)
        interface.is_server_ca_signed = AsyncMock(return_value=False)
        interface._get_expected_fingerprint = Mock(return_value=fingerprint)
        interface._save_certificate = AsyncMock()
        return interface

    async def test_self_signed_without_pin_is_rejected(self):
        interface = self.bare_interface(None)
        with self.assertRaises(ErrorGettingSSLCertFromServer):
            await interface._try_saving_ssl_cert_for_first_time(Mock())
        interface._save_certificate.assert_not_awaited()

    async def test_explicit_pin_allows_self_signed_first_contact(self):
        interface = self.bare_interface("aa" * 32)
        await interface._try_saving_ssl_cert_for_first_time(Mock())
        interface._save_certificate.assert_awaited_once_with()


class TestWalletStorageScrypt(unittest.TestCase):
    def test_new_user_password_uses_bie3(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wallet")
            storage = WalletStorage(path)
            storage.set_password("correct horse battery staple", StorageEncryptionVersion.USER_PASSWORD)
            storage.write('{"wallet":"test"}')
            envelope = base64.b64decode(open(path, "r", encoding="utf-8").read())
            self.assertEqual(b"BIE3", envelope[:4])
            self.assertEqual(StorageEncryptionVersion.USER_PASSWORD_SCRYPT,
                             storage.get_encryption_version())
            self.assertEqual(SCRYPT_SALT_LEN, len(envelope[4:4 + SCRYPT_SALT_LEN]))
            reopened = WalletStorage(path)
            reopened.decrypt("correct horse battery staple")
            self.assertEqual('{"wallet":"test"}', reopened.read())

    def test_same_password_gets_random_independent_salts(self):
        with tempfile.TemporaryDirectory() as tmp:
            salts = []
            for name in ("a", "b"):
                path = os.path.join(tmp, name)
                storage = WalletStorage(path)
                storage.set_password("same password", StorageEncryptionVersion.USER_PASSWORD)
                storage.write('{"x":1}')
                envelope = base64.b64decode(open(path, "r", encoding="utf-8").read())
                salts.append(envelope[4:4 + SCRYPT_SALT_LEN])
            self.assertNotEqual(salts[0], salts[1])

    def test_wrong_bie3_password_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wallet")
            storage = WalletStorage(path)
            storage.set_password("right", StorageEncryptionVersion.USER_PASSWORD)
            storage.write('{"x":1}')
            reopened = WalletStorage(path)
            with self.assertRaises(InvalidPassword):
                reopened.decrypt("wrong")

    def test_legacy_bie1_migrates_after_successful_unlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wallet")
            legacy = WalletStorage(path)
            legacy._encryption_version = StorageEncryptionVersion.USER_PASSWORD
            key = legacy.get_eckey_from_password("legacy password")
            legacy.pubkey = key.get_public_key_hex()
            legacy.write('{"legacy":true}')
            self.assertEqual(b"BIE1", base64.b64decode(open(path, "r", encoding="utf-8").read())[:4])
            reopened = WalletStorage(path)
            reopened.decrypt("legacy password")
            self.assertEqual('{"legacy":true}', reopened.read())
            self.assertEqual(StorageEncryptionVersion.USER_PASSWORD_SCRYPT,
                             reopened.get_encryption_version())
            self.assertEqual(b"BIE3", base64.b64decode(open(path, "r", encoding="utf-8").read())[:4])

    def test_scrypt_floor(self):
        self.assertGreaterEqual(SCRYPT_N, 1 << 15)
        self.assertGreaterEqual(SCRYPT_R, 8)
        self.assertGreaterEqual(SCRYPT_SALT_LEN, 16)


class TestVerifiedStateQuarantine(unittest.TestCase):
    @staticmethod
    def bare_adb(verified_info=None):
        adb = object.__new__(AddressSynchronizer)
        adb.lock = threading.RLock()
        adb.transaction_lock = threading.RLock()
        adb.threadlocal_cache = threading.local()
        adb._get_balance_cache = {}
        adb._get_asset_balance_cache = {}
        adb._get_assets_in_mempool_cache = {}
        adb.db = Mock()
        adb.db.get_verified_tx = Mock(return_value=verified_info)
        adb.get_local_height = Mock(return_value=200)
        prevout = Mock()
        prevout.txid = bytes.fromhex("11" * 32)
        prevout.to_str = Mock(return_value=("11" * 32) + ":0")
        coin = Mock()
        coin.prevout = prevout
        coin.spent_height = None
        coin.value_sats = Mock(return_value=12345)
        coin.block_height = 100
        coin.is_coinbase_output = Mock(return_value=False)
        coin.asset = None
        adb.get_addr_outputs = Mock(return_value={prevout: coin})
        return adb

    def test_unverified_positive_height_does_not_inflate_balance(self):
        adb = self.bare_adb(None)
        self.assertEqual((0, 0, 0), adb.get_balance({"Rtest"}))

    def test_matching_spv_record_counts_as_confirmed(self):
        info = Mock()
        info.height = 100
        adb = self.bare_adb(info)
        self.assertEqual((12345, 0, 0), adb.get_balance({"Rtest"}))


class TestVerifiedReadAuthorization(unittest.TestCase):
    @staticmethod
    def authorized_window():
        return WriteAuthorization(
            state=WriteAuthorizationState.AUTHORIZED,
            reason="fixture",
            operator_group_count=2,
            window_start=90,
            window_tip=101,
            window_hashes=tuple(f"{i:064x}" for i in range(90, 102)),
        )

    @staticmethod
    def interface():
        iface = Mock()
        iface.is_connected_and_ready = Mock(return_value=True)
        iface.is_safe_ravencoin_mainnet_endpoint = True
        iface.server.host = "read.example"
        iface.blockchain.height = Mock(return_value=101)
        iface.blockchain.get_hash = Mock(side_effect=lambda h: f"{h:064x}")
        return iface

    def test_exact_read_chain_must_match_quorum(self):
        net = object.__new__(Network)
        net.get_write_authorization = Mock(return_value=self.authorized_window())
        iface = self.interface()
        old_servers = constants.net.DEFAULT_SERVERS
        try:
            constants.net.DEFAULT_SERVERS = {"read.example": {"operatorGroup": "READ_OP"}}
            self.assertEqual(
                WriteAuthorizationState.AUTHORIZED,
                net.get_verified_read_authorization(iface, required_height=100).state,
            )
            iface.blockchain.get_hash = Mock(return_value="ff" * 32)
            self.assertEqual(
                WriteAuthorizationState.CHAIN_CONFLICT,
                net.get_verified_read_authorization(iface, required_height=100).state,
            )
        finally:
            constants.net.DEFAULT_SERVERS = old_servers

    def test_height_newer_than_witness_tip_is_not_verified(self):
        net = object.__new__(Network)
        net.get_write_authorization = Mock(return_value=self.authorized_window())
        iface = self.interface()
        old_servers = constants.net.DEFAULT_SERVERS
        try:
            constants.net.DEFAULT_SERVERS = {"read.example": {"operatorGroup": "READ_OP"}}
            self.assertEqual(
                WriteAuthorizationState.STALE_CHAIN_EVIDENCE,
                net.get_verified_read_authorization(iface, required_height=102).state,
            )
        finally:
            constants.net.DEFAULT_SERVERS = old_servers


class TestProductionOperatorDiversity(unittest.TestCase):
    def test_shipped_directory_has_two_operator_groups(self):
        groups = {
            entry.get("operatorGroup")
            for entry in constants.net.DEFAULT_SERVERS.values()
            if isinstance(entry, dict) and entry.get("operatorGroup")
        }
        self.assertIn("rvn4lyfe", groups)
        self.assertIn("ALENOC", groups)
        self.assertGreaterEqual(len(groups), 2)


if __name__ == "__main__":
    unittest.main()
