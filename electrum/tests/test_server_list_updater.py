import copy
import json
import os
import tempfile
import unittest

from electrum import constants
from electrum.server_list_updater import (
    CACHE_FILENAME,
    MAX_REMOTE_BYTES,
    ServerListError,
    apply_remote_server_list,
    build_effective_server_list,
    get_builtin_server_list,
    load_cached_remote_servers,
    parse_remote_server_list,
    sanitize_remote_server_list,
    write_cached_remote_servers,
)


class TestDynamicServerList(unittest.TestCase):

    def setUp(self):
        self.saved_mainnet_servers = copy.deepcopy(
            constants.RavencoinMainnet.DEFAULT_SERVERS
        )
        constants.set_mainnet()

    def tearDown(self):
        constants.RavencoinMainnet.DEFAULT_SERVERS = self.saved_mainnet_servers
        constants.set_mainnet()

    def test_remote_host_cannot_mint_operator_group(self):
        remote = {
            "new-electrum.example": {
                "s": "50002",
                "version": "1.11",
                "operatorGroup": "fake-independent-operator",
            }
        }
        sanitized = sanitize_remote_server_list(remote)
        self.assertIn("new-electrum.example", sanitized)
        self.assertNotIn("operatorGroup", sanitized["new-electrum.example"])

        effective = build_effective_server_list(remote)
        self.assertNotIn("operatorGroup", effective["new-electrum.example"])

    def test_compiled_anchor_cannot_be_replaced_or_removed_remotely(self):
        builtin = get_builtin_server_list()
        self.assertIn("rvn4lyfe.com", builtin)
        self.assertIn("electrumx.raventag.com", builtin)

        remote = {
            "rvn4lyfe.com": {
                "s": "60000",
                "operatorGroup": "attacker",
                "version": "999",
            },
            "new-electrum.example": {"s": "50002"},
        }
        effective = build_effective_server_list(remote)

        self.assertEqual(builtin["rvn4lyfe.com"], effective["rvn4lyfe.com"])
        # Omission from the unsigned remote document cannot delete a compiled
        # trust anchor either.
        self.assertEqual(
            builtin["electrumx.raventag.com"],
            effective["electrumx.raventag.com"],
        )
        self.assertIn("new-electrum.example", effective)

    def test_remote_only_server_is_updateable_and_removable(self):
        first = build_effective_server_list(
            {"new-electrum.example": {"s": "50002", "version": "1.11"}}
        )
        second = build_effective_server_list(
            {"new-electrum.example": {"s": "50003", "version": "1.12"}}
        )
        removed = build_effective_server_list(
            {"another-electrum.example": {"s": "50002"}}
        )

        self.assertEqual("50002", first["new-electrum.example"]["s"])
        self.assertEqual("50003", second["new-electrum.example"]["s"])
        self.assertNotIn("new-electrum.example", removed)

    def test_malformed_remote_entries_fail_closed(self):
        bad_values = [
            [],
            {},
            {"bad.example": "not-an-object"},
            {"bad.example": {"version": "1.11"}},
            {"bad.example": {"s": "0"}},
            {"bad.example": {"s": "65536"}},
            {"bad.example": {"s": "not-a-port"}},
            {"https://bad.example": {"s": "50002"}},
            {"bad host.example": {"s": "50002"}},
        ]
        for value in bad_values:
            with self.subTest(value=value):
                with self.assertRaises(ServerListError):
                    sanitize_remote_server_list(value)

    def test_remote_response_size_is_bounded(self):
        oversized = " " * (MAX_REMOTE_BYTES + 1)
        with self.assertRaises(ServerListError):
            parse_remote_server_list(oversized)

    def test_apply_replaces_runtime_mapping_atomically(self):
        old_object = constants.RavencoinMainnet.DEFAULT_SERVERS
        changed = apply_remote_server_list(
            {"new-electrum.example": {"s": "50002", "version": "1.11"}}
        )
        self.assertTrue(changed)
        self.assertIsNot(old_object, constants.RavencoinMainnet.DEFAULT_SERVERS)
        self.assertIn(
            "new-electrum.example", constants.RavencoinMainnet.DEFAULT_SERVERS
        )
        self.assertNotIn(
            "operatorGroup",
            constants.RavencoinMainnet.DEFAULT_SERVERS["new-electrum.example"],
        )

    def test_validated_cache_round_trip_and_tamper_rejection(self):
        remote = {
            "new-electrum.example": {
                "s": "50002",
                "version": "1.11",
                "operatorGroup": "must-not-survive",
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            digest = write_cached_remote_servers(directory, remote, fetched_at=1)
            loaded = load_cached_remote_servers(directory)
            self.assertIsNotNone(loaded)
            servers, loaded_digest = loaded
            self.assertEqual(digest, loaded_digest)
            self.assertNotIn("operatorGroup", servers["new-electrum.example"])

            path = os.path.join(directory, CACHE_FILENAME)
            with open(path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
            document["servers"]["new-electrum.example"]["s"] = "50003"
            # Keep the old digest: this is a cache tamper/partial-write shape.
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            self.assertIsNone(load_cached_remote_servers(directory))


if __name__ == "__main__":
    unittest.main()
