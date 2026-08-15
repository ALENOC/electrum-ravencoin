import base64
import datetime
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from electrum import core_safety_directory as directory
from electrum.ravencoin_backend import (
    BackendEligibilityState, classify_backend_evidence,
    parse_ravencoin_backend_evidence,
)
from electrum.tests.test_ravencoin_backend import NOW, backend_response

from . import ElectrumTestCase


def keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, {hashlib.sha256(public_bytes).hexdigest()[:16]: public_bytes}


def body(version=1, servers=None, expires_in_hours=24):
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    document = {
        "schemaVersion": 1,
        "directoryVersion": version,
        "generatedAt": now.isoformat(),
        "note": "Discovery hint only. A client must independently verify every "
                "endpoint before using it, including servers listed as SAFE.",
        "servers": servers if servers is not None else [
            {"hostname": "safe.example.org", "port": 50002, "transport": "TLS",
             "availability": "REACHABLE", "security": "SAFE",
             "operatorGroup": "EXAMPLE"},
            {"hostname": "legacy.example.org", "port": 50002, "transport": "TLS",
             "availability": "REACHABLE", "security": "BACKEND_MISSING",
             "operatorGroup": "LEGACY"},
        ],
    }
    if expires_in_hours is not None:
        document["expiresAt"] = (
            now + datetime.timedelta(hours=expires_in_hours)).isoformat()
    return document


def sign(private_key, key_id, document_body):
    payload = json.dumps(document_body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
    return {
        "directory": document_body,
        "signature": {"algorithm": "ed25519", "keyId": key_id,
                      "value": base64.b64encode(private_key.sign(payload)).decode()},
    }


class TestDirectoryVerification(ElectrumTestCase):

    def test_a_production_directory_key_is_pinned(self):
        assert directory.TRUSTED_DIRECTORY_KEYS
        for key_id, material in directory.TRUSTED_DIRECTORY_KEYS.items():
            self.assertEqual(32, len(material))
            self.assertEqual(key_id, hashlib.sha256(material).hexdigest()[:16])

    def test_directory_key_is_not_the_policy_key(self):
        from electrum import core_safety_policy
        self.assertFalse(set(directory.TRUSTED_DIRECTORY_KEYS)
                         & set(core_safety_policy.TRUSTED_POLICY_KEYS))

    def test_valid_directory_verifies(self):
        private_key, trusted = keypair()
        key_id = next(iter(trusted))
        verified = directory.verify_signed_directory(
            sign(private_key, key_id, body()), trusted_keys=trusted)
        self.assertEqual(1, verified["directoryVersion"])

    def test_tampered_directory_is_refused(self):
        private_key, trusted = keypair()
        key_id = next(iter(trusted))
        document = sign(private_key, key_id, body())
        document["directory"]["servers"][1]["security"] = "SAFE"
        with self.assertRaises(directory.DirectoryError):
            directory.verify_signed_directory(document, trusted_keys=trusted)

    def test_unknown_key_is_refused(self):
        private_key, _trusted = keypair()
        _other, other_trusted = keypair()
        document = sign(private_key, "0000000000000000", body())
        with self.assertRaises(directory.DirectoryError):
            directory.verify_signed_directory(document, trusted_keys=other_trusted)

    def test_rollback_is_refused(self):
        private_key, trusted = keypair()
        key_id = next(iter(trusted))
        with self.assertRaises(directory.DirectoryError):
            directory.verify_signed_directory(sign(private_key, key_id, body(2)),
                                              trusted_keys=trusted,
                                              minimum_version=6)

    def test_expired_directory_is_refused(self):
        private_key, trusted = keypair()
        key_id = next(iter(trusted))
        document = sign(private_key, key_id, body(expires_in_hours=1))
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        with self.assertRaises(directory.DirectoryError):
            directory.verify_signed_directory(document, trusted_keys=trusted,
                                              now=future)


class TestDirectoryIsOnlyAHint(ElectrumTestCase):

    def test_no_candidate_is_marked_verified(self):
        candidates = directory.candidates(body())
        self.assertTrue(candidates)
        self.assertTrue(all(item["verified"] is False for item in candidates))

    def test_entries_the_directory_dislikes_are_still_offered(self):
        hints = {item["hostname"]: item["hint"] for item in directory.candidates(body())}
        self.assertEqual("BACKEND_MISSING", hints["legacy.example.org"])

    def test_malformed_entries_are_dropped(self):
        servers = [
            {"hostname": "", "port": 50002, "transport": "TLS"},
            {"hostname": "a.example.org", "port": 0, "transport": "TLS"},
            {"hostname": "b.example.org", "port": 50002, "transport": "CARRIER_PIGEON"},
            {"hostname": "good.example.org", "port": 50002, "transport": "TLS",
             "security": "SAFE"},
        ]
        candidates = directory.candidates(body(servers=servers))
        self.assertEqual(["good.example.org"],
                         [item["hostname"] for item in candidates])

    def test_directory_saying_safe_does_not_make_an_unsafe_backend_eligible(self):
        """The decisive test: a SAFE label cannot rescue a failing backend."""
        candidates = directory.candidates(body())
        self.assertEqual("SAFE", candidates[0]["hint"])

        # The endpoint the directory recommends turns out to run an old Core.
        evidence = parse_ravencoin_backend_evidence(backend_response(4_070_000))
        state = classify_backend_evidence(evidence, now=NOW)
        self.assertEqual(BackendEligibilityState.CORE_TOO_OLD, state)

        # And one that reports an uncertified build is equally refused.
        unreviewed = parse_ravencoin_backend_evidence(
            backend_response(4_090_000, commit="f" * 40))
        self.assertEqual(BackendEligibilityState.CORE_UNREVIEWED_VERSION,
                         classify_backend_evidence(unreviewed, now=NOW))

    def test_client_still_works_without_any_directory(self):
        """No directory at all is a supported state, not a failure."""
        self.assertEqual([], directory.candidates({"servers": []}))
