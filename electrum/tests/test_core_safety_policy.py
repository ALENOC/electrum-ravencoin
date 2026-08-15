import base64
import datetime
import json
import os
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from electrum import core_safety_policy as policy

from . import ElectrumTestCase

CERTIFIED_COMMIT = "b60f50e04f1fba425b28804e61be2694faaf3469"
OTHER_COMMIT = "c" * 40


def keypair():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    import hashlib
    key_id = hashlib.sha256(public_bytes).hexdigest()[:16]
    return private_key, {key_id: public_bytes}, key_id


def safe_entry(commit=CERTIFIED_COMMIT, version="4.8.0",
               repository="2miners/Ravencoin"):
    return {
        "repository": repository,
        "tag": "v" + version,
        "version": version,
        "commit": commit,
        "status": "KNOWN_SAFE",
        "certification": {"profile": "rvn-consensus-2026-08-v1", "result": "PASS"},
    }


def body(version=2, releases=None, expires_in_days=90, profile=None):
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    document = {
        "schemaVersion": 1,
        "policyVersion": version,
        "generatedAt": now.isoformat(),
        "safetyProfile": profile or policy.REQUIRED_SAFETY_PROFILE,
        "releases": releases if releases is not None else [safe_entry()],
    }
    if expires_in_days is not None:
        document["expiresAt"] = (
            now + datetime.timedelta(days=expires_in_days)).isoformat()
    return document


def sign(private_key, key_id, document_body):
    payload = json.dumps(document_body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
    return {
        "policy": document_body,
        "signature": {
            "algorithm": "ed25519",
            "keyId": key_id,
            "value": base64.b64encode(private_key.sign(payload)).decode(),
        },
    }


class TestBuiltInBaseline(ElectrumTestCase):

    def test_baseline_is_valid_and_certifies_only_the_anchor(self):
        baseline = policy.load_baseline()
        policy.validate_body(baseline)
        self.assertEqual(1, len(baseline["releases"]))
        entry = baseline["releases"][0]
        self.assertEqual("2miners/Ravencoin", entry["repository"])
        self.assertEqual(CERTIFIED_COMMIT, entry["commit"])
        self.assertEqual("KNOWN_SAFE", entry["status"])

    def test_baseline_contains_no_hypothetical_future_release(self):
        baseline = policy.load_baseline()
        versions = {entry["version"] for entry in baseline["releases"]}
        self.assertEqual({"4.8.0"}, versions)

    def test_lookup_matches_identity_not_version(self):
        baseline = policy.load_baseline()
        self.assertIsNotNone(
            policy.lookup(baseline, "2miners/Ravencoin", CERTIFIED_COMMIT))
        self.assertIsNone(
            policy.lookup(baseline, "2miners/Ravencoin", OTHER_COMMIT))
        self.assertIsNone(
            policy.lookup(baseline, "RavenProject/Ravencoin", CERTIFIED_COMMIT))


class TestPolicySignature(ElectrumTestCase):

    def test_valid_signature_is_accepted(self):
        private_key, trusted, key_id = keypair()
        verified = policy.verify_signed_policy(
            sign(private_key, key_id, body()), trusted_keys=trusted)
        self.assertEqual(2, verified["policyVersion"])

    def test_an_empty_trust_store_accepts_nothing(self):
        """A build with no trust root refuses every remote policy, by design."""
        private_key, _trusted, key_id = keypair()
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(sign(private_key, key_id, body()),
                                        trusted_keys={})

    def test_tampered_policy_is_refused(self):
        private_key, trusted, key_id = keypair()
        document = sign(private_key, key_id, body())
        document["policy"]["releases"].append(safe_entry(commit=OTHER_COMMIT))
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(document, trusted_keys=trusted)

    def test_unknown_signing_key_is_refused(self):
        private_key, _trusted, key_id = keypair()
        _other_key, other_trusted, _other_id = keypair()
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(sign(private_key, key_id, body()),
                                        trusted_keys=other_trusted)

    def test_malformed_document_is_refused(self):
        _private, trusted, _key_id = keypair()
        for document in ({}, {"policy": {}}, {"signature": {}}, "not a dict"):
            with self.assertRaises(policy.PolicyError):
                policy.verify_signed_policy(document, trusted_keys=trusted)

    def test_schema_mismatch_is_refused(self):
        private_key, trusted, key_id = keypair()
        broken = body()
        broken["schemaVersion"] = 99
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(sign(private_key, key_id, broken),
                                        trusted_keys=trusted)

    def test_expired_policy_is_refused(self):
        private_key, trusted, key_id = keypair()
        document = sign(private_key, key_id, body(expires_in_days=1))
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(document, trusted_keys=trusted, now=future)

    def test_rollback_is_refused(self):
        private_key, trusted, key_id = keypair()
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(sign(private_key, key_id, body(version=3)),
                                        trusted_keys=trusted,
                                        minimum_policy_version=8)

    def test_key_rotation_accepts_both_keys(self):
        old_key, old_trusted, old_id = keypair()
        new_key, new_trusted, new_id = keypair()
        trusted = {**old_trusted, **new_trusted}
        for private_key, key_id in ((old_key, old_id), (new_key, new_id)):
            self.assertTrue(policy.verify_signed_policy(
                sign(private_key, key_id, body()), trusted_keys=trusted))


class TestPolicyStore(ElectrumTestCase):

    def test_offline_falls_back_to_the_built_in_baseline(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            store = policy.PolicyStore(cache_dir)
            effective = store.effective()
            self.assertEqual(1, len(effective["releases"]))
            self.assertIsNotNone(policy.lookup(effective, "2miners/Ravencoin",
                                               CERTIFIED_COMMIT))

    def test_corrupt_cache_is_ignored(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with open(os.path.join(cache_dir, policy.POLICY_CACHE_FILENAME), "w") as f:
                f.write("{not json")
            store = policy.PolicyStore(cache_dir)
            self.assertEqual(1, len(store.effective()["releases"]))

    def test_unsigned_cache_is_never_trusted(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with open(os.path.join(cache_dir, policy.POLICY_CACHE_FILENAME), "w") as f:
                json.dump({"policy": body(releases=[safe_entry(commit=OTHER_COMMIT)])}, f)
            store = policy.PolicyStore(cache_dir)
            self.assertIsNone(policy.lookup(store.effective(), "2miners/Ravencoin",
                                            OTHER_COMMIT))

    def test_accepted_policy_is_cached_and_survives_reload(self):
        private_key, trusted, key_id = keypair()
        original = dict(policy.TRUSTED_POLICY_KEYS)
        policy.TRUSTED_POLICY_KEYS.update(trusted)
        try:
            with tempfile.TemporaryDirectory() as cache_dir:
                store = policy.PolicyStore(cache_dir)
                document = sign(private_key, key_id,
                                body(version=5,
                                     releases=[safe_entry(),
                                               safe_entry(commit=OTHER_COMMIT,
                                                          version="4.9.0")]))
                store.accept_remote(document)
                self.assertEqual(5, store.policy_version)
                reloaded = policy.PolicyStore(cache_dir)
                self.assertEqual(5, reloaded.policy_version)
                self.assertIsNotNone(policy.lookup(reloaded.effective(),
                                                   "2miners/Ravencoin", OTHER_COMMIT))
        finally:
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS.update(original)

    def test_replaying_an_older_policy_after_revocation_is_refused(self):
        private_key, trusted, key_id = keypair()
        original = dict(policy.TRUSTED_POLICY_KEYS)
        policy.TRUSTED_POLICY_KEYS.update(trusted)
        try:
            with tempfile.TemporaryDirectory() as cache_dir:
                store = policy.PolicyStore(cache_dir)
                revoked = dict(safe_entry())
                revoked.update({"status": "REVOKED",
                                "revocationReason": "consensus regression"})
                revoked.pop("certification")
                store.accept_remote(sign(private_key, key_id,
                                         body(version=6, releases=[revoked])))
                entry = policy.lookup(store.effective(), "2miners/Ravencoin",
                                      CERTIFIED_COMMIT)
                self.assertEqual("REVOKED", entry["status"])
                with self.assertRaises(policy.PolicyError):
                    store.accept_remote(sign(private_key, key_id, body(version=5)))
        finally:
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS.update(original)

    def test_remote_policy_cannot_rehabilitate_a_baseline_refusal(self):
        baseline = policy.load_baseline()
        unsafe = dict(baseline)
        entry = dict(baseline["releases"][0])
        entry["status"] = "KNOWN_UNSAFE"
        entry["certification"] = {"profile": policy.REQUIRED_SAFETY_PROFILE,
                                  "result": "FAIL"}
        unsafe["releases"] = [entry]
        merged = policy.merge(unsafe, body(version=9, releases=[safe_entry()]))
        self.assertEqual("KNOWN_UNSAFE",
                         policy.lookup(merged, "2miners/Ravencoin",
                                       CERTIFIED_COMMIT)["status"])

    def test_policy_for_another_profile_is_refused(self):
        private_key, trusted, key_id = keypair()
        original = dict(policy.TRUSTED_POLICY_KEYS)
        policy.TRUSTED_POLICY_KEYS.update(trusted)
        try:
            with tempfile.TemporaryDirectory() as cache_dir:
                store = policy.PolicyStore(cache_dir)
                with self.assertRaises(policy.PolicyError):
                    store.accept_remote(sign(private_key, key_id,
                                             body(profile="rvn-consensus-2030-01-v4")))
        finally:
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS.update(original)


class TestProductionTrustStore(ElectrumTestCase):

    def test_a_production_key_is_pinned(self):
        assert policy.TRUSTED_POLICY_KEYS, "wallet must ship a policy trust root"
        for key_id, material in policy.TRUSTED_POLICY_KEYS.items():
            import hashlib
            self.assertEqual(32, len(material))
            self.assertEqual(key_id, hashlib.sha256(material).hexdigest()[:16])

    def test_test_keys_are_not_production_keys(self):
        _private, trusted, _key_id = keypair()
        self.assertFalse(set(trusted) & set(policy.TRUSTED_POLICY_KEYS))

    def test_a_policy_signed_by_an_untrusted_key_is_refused_by_default(self):
        private_key, _trusted, key_id = keypair()
        with self.assertRaises(policy.PolicyError):
            policy.verify_signed_policy(sign(private_key, key_id, body()))


class TestRollbackHighWaterMark(ElectrumTestCase):
    """Deleting the cache must not reopen an accepted rollback."""

    def _store_with(self, cache_dir, private_key, key_id, version, releases=None):
        original = dict(policy.TRUSTED_POLICY_KEYS)
        policy.TRUSTED_POLICY_KEYS.clear()
        import hashlib
        policy.TRUSTED_POLICY_KEYS[key_id] = private_key.public_key().public_bytes_raw()
        try:
            store = policy.PolicyStore(cache_dir)
            store.accept_remote(sign(private_key, key_id,
                                     body(version=version, releases=releases)))
            return store
        finally:
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS.update(original)

    def test_high_water_survives_a_deleted_cache(self):
        private_key, trusted, key_id = keypair()
        with tempfile.TemporaryDirectory() as cache_dir:
            self._store_with(cache_dir, private_key, key_id, 9)
            os.remove(os.path.join(cache_dir, policy.POLICY_CACHE_FILENAME))
            original = dict(policy.TRUSTED_POLICY_KEYS)
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS[key_id] = trusted[next(iter(trusted))] \
                if key_id in trusted else private_key.public_key().public_bytes_raw()
            try:
                reopened = policy.PolicyStore(cache_dir)
                self.assertGreaterEqual(reopened.policy_version, 9)
                with self.assertRaises(policy.PolicyError):
                    reopened.accept_remote(sign(private_key, key_id, body(version=8)))
            finally:
                policy.TRUSTED_POLICY_KEYS.clear()
                policy.TRUSTED_POLICY_KEYS.update(original)

    def test_revocation_cannot_be_undone_by_replaying_the_previous_policy(self):
        private_key, _trusted, key_id = keypair()
        revoked = dict(safe_entry())
        revoked.update({"status": "REVOKED", "revocationReason": "consensus bug"})
        revoked.pop("certification")
        with tempfile.TemporaryDirectory() as cache_dir:
            store = self._store_with(cache_dir, private_key, key_id, 12,
                                     releases=[revoked])
            entry = policy.lookup(store.effective(), "2miners/Ravencoin",
                                  CERTIFIED_COMMIT)
            self.assertEqual("REVOKED", entry["status"])
            original = dict(policy.TRUSTED_POLICY_KEYS)
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS[key_id] = private_key.public_key().public_bytes_raw()
            try:
                # The realistic attacker is on the network, not on the disk: it
                # can withhold or replay a policy but cannot delete local files.
                # Removing only the cached policy must not reopen the rollback.
                os.remove(os.path.join(cache_dir, policy.POLICY_CACHE_FILENAME))
                reopened = policy.PolicyStore(cache_dir)
                self.assertGreaterEqual(reopened.policy_version, 12)
                with self.assertRaises(policy.PolicyError):
                    reopened.accept_remote(sign(private_key, key_id,
                                                body(version=11)))
            finally:
                policy.TRUSTED_POLICY_KEYS.clear()
                policy.TRUSTED_POLICY_KEYS.update(original)

    def test_state_file_records_metadata_without_secrets(self):
        private_key, _trusted, key_id = keypair()
        with tempfile.TemporaryDirectory() as cache_dir:
            self._store_with(cache_dir, private_key, key_id, 4)
            with open(os.path.join(cache_dir, policy.POLICY_STATE_FILENAME)) as handle:
                state = json.load(handle)
            self.assertEqual(4, state["policyVersion"])
            self.assertEqual(key_id, state["keyId"])
            self.assertIn("policyDigest", state)
            raw = json.dumps(state)
            self.assertNotIn(private_key.private_bytes_raw().hex(), raw)

    def test_corrupt_state_file_does_not_lower_the_floor_below_the_cache(self):
        private_key, _trusted, key_id = keypair()
        with tempfile.TemporaryDirectory() as cache_dir:
            self._store_with(cache_dir, private_key, key_id, 7)
            with open(os.path.join(cache_dir, policy.POLICY_STATE_FILENAME), "w") as f:
                f.write("{corrupt")
            original = dict(policy.TRUSTED_POLICY_KEYS)
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS[key_id] = private_key.public_key().public_bytes_raw()
            try:
                reopened = policy.PolicyStore(cache_dir)
                self.assertEqual(7, reopened.policy_version)
            finally:
                policy.TRUSTED_POLICY_KEYS.clear()
                policy.TRUSTED_POLICY_KEYS.update(original)


class TestRollbackLimits(ElectrumTestCase):
    """The honest boundary of local anti-rollback state."""

    def test_wiping_all_local_state_returns_to_the_shipped_baseline(self):
        """An attacker with local file access resets the floor to the baseline.

        This is a property of any local persistence, not a hole that can be
        closed by writing another file next to the first one. What matters is
        where it lands: back at the version compiled into the wallet, which
        still refuses everything the shipped baseline refuses. A revocation that
        must survive this is folded into the baseline of the next wallet release.
        """
        private_key, _trusted, key_id = keypair()
        original = dict(policy.TRUSTED_POLICY_KEYS)
        policy.TRUSTED_POLICY_KEYS.clear()
        policy.TRUSTED_POLICY_KEYS[key_id] = private_key.public_key().public_bytes_raw()
        try:
            with tempfile.TemporaryDirectory() as cache_dir:
                store = policy.PolicyStore(cache_dir)
                store.accept_remote(sign(private_key, key_id, body(version=20)))
                for name in os.listdir(cache_dir):
                    os.remove(os.path.join(cache_dir, name))
                reopened = policy.PolicyStore(cache_dir)
                baseline_version = policy.load_baseline()["policyVersion"]
                self.assertEqual(baseline_version, reopened.policy_version)
                # And the baseline still governs what may be trusted at all.
                effective = reopened.effective()
                self.assertEqual(1, len(effective["releases"]))
        finally:
            policy.TRUSTED_POLICY_KEYS.clear()
            policy.TRUSTED_POLICY_KEYS.update(original)
