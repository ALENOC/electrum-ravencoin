import base64
import copy
import datetime
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from electrum import constants
from electrum.server_list_updater import (
    CACHE_FILENAME,
    MAX_REMOTE_BYTES,
    REGISTRY_SIGNATURE_DOMAIN,
    TRUSTED_ANCHOR_HOSTS,
    TRUSTED_REGISTRY_KEYS,
    ServerListError,
    accept_signed_registry_document,
    apply_remote_server_list,
    apply_signed_registry,
    build_effective_server_list,
    get_builtin_anchor_list,
    get_compiled_server_list,
    load_cached_remote_servers,
    load_cached_signed_registry,
    parse_remote_server_list,
    sanitize_remote_server_list,
    sanitize_signed_server_list,
    verify_signed_registry,
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

    @staticmethod
    def signing_fixture():
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        key_id = hashlib.sha256(public).hexdigest()[:16]
        return private, key_id, public

    @staticmethod
    def signed_document(private, key_id, *, version=1, servers=None,
                        generated="2026-08-19T08:00:00+00:00",
                        expires="2027-08-19T08:00:00+00:00"):
        if servers is None:
            servers = {
                "electrumx.raventag.com": {
                    "s": "50002",
                    "version": "1.11",
                    "operatorGroup": "ALENOC",
                }
            }
        body = {
            "schemaVersion": 1,
            "registryVersion": version,
            "generatedAt": generated,
            "expiresAt": expires,
            "servers": servers,
        }
        payload = REGISTRY_SIGNATURE_DOMAIN + json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return {
            "registry": body,
            "signature": {
                "algorithm": "ed25519",
                "keyId": key_id,
                "value": base64.b64encode(private.sign(payload)).decode("ascii"),
            },
        }

    def test_raventag_is_the_only_compiled_security_anchor(self):
        anchors = get_builtin_anchor_list()
        self.assertEqual({"electrumx.raventag.com"}, set(anchors))
        self.assertEqual({"electrumx.raventag.com"}, set(TRUSTED_ANCHOR_HOSTS))
        self.assertEqual("ALENOC", anchors["electrumx.raventag.com"]["operatorGroup"])

        compiled = get_compiled_server_list()
        self.assertIn("rvn4lyfe.com", compiled)
        self.assertNotIn("operatorGroup", compiled["rvn4lyfe.com"])
        onion = "aq7vuqykup2voklcrpqljf6jnjkzrouowsjfrmybdou5kdhrpr6sjjid.onion"
        self.assertIn(onion, compiled)
        self.assertNotIn("operatorGroup", compiled[onion])

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

    def test_raventag_anchor_cannot_be_replaced_or_removed_by_unsigned_file(self):
        anchor = get_builtin_anchor_list()["electrumx.raventag.com"]
        remote = {
            "electrumx.raventag.com": {
                "s": "60000",
                "operatorGroup": "attacker",
                "version": "999",
            },
            "new-electrum.example": {"s": "50002"},
        }
        effective = build_effective_server_list(remote)
        self.assertEqual(anchor, effective["electrumx.raventag.com"])
        self.assertIn("new-electrum.example", effective)

        omitted = build_effective_server_list(
            {"new-electrum.example": {"s": "50002"}}
        )
        self.assertEqual(anchor, omitted["electrumx.raventag.com"])

    def test_non_anchor_compiled_seed_is_updateable_and_removable(self):
        compiled = get_compiled_server_list()
        self.assertEqual("50002", compiled["rvn4lyfe.com"]["s"])

        updated = build_effective_server_list(
            {"rvn4lyfe.com": {"s": "50003", "version": "1.12"}}
        )
        self.assertEqual("50003", updated["rvn4lyfe.com"]["s"])
        self.assertNotIn("operatorGroup", updated["rvn4lyfe.com"])

        removed = build_effective_server_list(
            {"another-electrum.example": {"s": "50002"}}
        )
        self.assertNotIn("rvn4lyfe.com", removed)
        self.assertIn("electrumx.raventag.com", removed)

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

    def test_signed_registry_can_add_trusted_operator_without_recompile(self):
        private, key_id, public = self.signing_fixture()
        servers = {
            "electrumx.raventag.com": {
                "s": "50002",
                "operatorGroup": "ALENOC",
            },
            "second-independent.example": {
                "s": "50002",
                "operatorGroup": "SECOND_OPERATOR",
            },
        }
        document = self.signed_document(
            private, key_id, version=7, servers=servers
        )
        body = verify_signed_registry(
            document,
            trusted_keys={key_id: public},
            now=datetime.datetime(2026, 8, 20, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(
            "SECOND_OPERATOR",
            body["servers"]["second-independent.example"]["operatorGroup"],
        )

    def test_signed_registry_is_authoritative_for_anchor_add_remove(self):
        body = {
            "schemaVersion": 1,
            "registryVersion": 2,
            "generatedAt": "2026-08-19T08:00:00+00:00",
            "expiresAt": "2027-08-19T08:00:00+00:00",
            "servers": {
                "operator-a.example": {
                    "s": "50002",
                    "operatorGroup": "A",
                },
                "operator-b.example": {
                    "s": "50002",
                    "operatorGroup": "B",
                },
            },
        }
        changed = apply_signed_registry(body)
        self.assertTrue(changed)
        self.assertNotIn(
            "electrumx.raventag.com",
            constants.RavencoinMainnet.DEFAULT_SERVERS,
        )
        self.assertEqual(
            {"A", "B"},
            {
                entry["operatorGroup"]
                for entry in constants.RavencoinMainnet.DEFAULT_SERVERS.values()
            },
        )

    def test_signed_registry_tamper_expiry_and_rollback_are_rejected(self):
        private, key_id, public = self.signing_fixture()
        document = self.signed_document(private, key_id, version=3)
        trusted = {key_id: public}
        now = datetime.datetime(2026, 8, 20, tzinfo=datetime.timezone.utc)

        self.assertEqual(
            3,
            verify_signed_registry(
                document, trusted_keys=trusted, now=now
            )["registryVersion"],
        )

        tampered = copy.deepcopy(document)
        tampered["registry"]["servers"]["electrumx.raventag.com"]["s"] = "50003"
        with self.assertRaises(ServerListError):
            verify_signed_registry(tampered, trusted_keys=trusted, now=now)

        with self.assertRaises(ServerListError):
            verify_signed_registry(
                document,
                trusted_keys=trusted,
                minimum_registry_version=4,
                now=now,
            )

        expired = self.signed_document(
            private,
            key_id,
            version=4,
            generated="2025-01-01T00:00:00+00:00",
            expires="2025-02-01T00:00:00+00:00",
        )
        with self.assertRaises(ServerListError):
            verify_signed_registry(expired, trusted_keys=trusted, now=now)

    def test_same_version_signed_equivocation_is_rejected_by_state(self):
        private, key_id, public = self.signing_fixture()
        first = self.signed_document(
            private,
            key_id,
            version=5,
            servers={
                "electrumx.raventag.com": {
                    "s": "50002",
                    "operatorGroup": "ALENOC",
                }
            },
        )
        second = self.signed_document(
            private,
            key_id,
            version=5,
            servers={
                "other.example": {
                    "s": "50002",
                    "operatorGroup": "OTHER",
                }
            },
        )
        now = datetime.datetime(2026, 8, 20, tzinfo=datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(TRUSTED_REGISTRY_KEYS, {key_id: public}, clear=True):
                accepted = accept_signed_registry_document(
                    directory, first, now=now
                )
                self.assertEqual(5, accepted["registryVersion"])
                cached = load_cached_signed_registry(directory, now=now)
                self.assertIsNotNone(cached)
                with self.assertRaises(ServerListError):
                    accept_signed_registry_document(directory, second, now=now)

    def test_builtin_registry_key_is_dedicated_and_well_formed(self):
        self.assertEqual({"d7a50f481a496f3e"}, set(TRUSTED_REGISTRY_KEYS))
        raw = TRUSTED_REGISTRY_KEYS["d7a50f481a496f3e"]
        self.assertEqual(32, len(raw))
        self.assertEqual(
            "d7a50f481a496f3e",
            hashlib.sha256(raw).hexdigest()[:16],
        )

    def test_committed_signed_registry_verifies_with_embedded_key(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "servers.signed.json",
        )
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        body = verify_signed_registry(
            document,
            now=datetime.datetime(2026, 8, 20, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(2, body["registryVersion"])
        self.assertEqual(
            "ALENOC",
            body["servers"]["electrumx.raventag.com"]["operatorGroup"],
        )

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

    def test_signed_operator_group_validation(self):
        cleaned = sanitize_signed_server_list(
            {"new.example": {"s": "50002", "operatorGroup": "OPERATOR"}}
        )
        self.assertEqual("OPERATOR", cleaned["new.example"]["operatorGroup"])
        with self.assertRaises(ServerListError):
            sanitize_signed_server_list(
                {"new.example": {"s": "50002", "operatorGroup": "bad\nvalue"}}
            )

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
        self.assertEqual(
            "ALENOC",
            constants.RavencoinMainnet.DEFAULT_SERVERS[
                "electrumx.raventag.com"
            ]["operatorGroup"],
        )

    def test_validated_unsigned_cache_round_trip_and_tamper_rejection(self):
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
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            self.assertIsNone(load_cached_remote_servers(directory))


if __name__ == "__main__":
    unittest.main()
