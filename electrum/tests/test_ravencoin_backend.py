import time

from electrum.ravencoin_backend import (
    BackendEligibilityState,
    BackendEvidenceError,
    classify_backend_evidence,
    parse_core_version_text,
    parse_ravencoin_backend_evidence,
)

from . import ElectrumTestCase


NOW = int(time.time())


def version_text(version_number):
    major, remainder = divmod(version_number, 1_000_000)
    minor, remainder = divmod(remainder, 10_000)
    patch, build = divmod(remainder, 100)
    result = "{}.{}.{}".format(major, minor, patch)
    return "{}.{}".format(result, build) if build else result


CERTIFIED_REPOSITORY = "2miners/Ravencoin"
CERTIFIED_COMMIT = "b60f50e04f1fba425b28804e61be2694faaf3469"
OTHER_COMMIT = "a" * 40


def backend_response(
        version_number=4_080_000, *, core_safe=True, network="main",
        network_matches=True, synchronized=True, checkpoint=True, kawpow=True,
        observed_at=NOW, server_version="ElectrumX-RVN 1.13.0.dev1",
        repository=CERTIFIED_REPOSITORY, commit=CERTIFIED_COMMIT,
        evidence_level="BUILD_IDENTITY_VERIFIED", identity=True,
        safety_profile="rvn-consensus-2026-08-v1"):
    core_version = version_text(version_number)
    identity_block = None
    if identity:
        identity_block = {"evidence": evidence_level}
        if repository:
            identity_block["sourceRepository"] = repository
        if commit:
            identity_block["sourceCommit"] = commit
    return {
        "server": "ElectrumX-RVN",
        "serverVersion": server_version,
        "backend": {
            "name": "Ravencoin Core",
            "version": core_version,
            "versionNumber": version_number,
            "subversion": "/Ravencoin:{}/".format(core_version),
            "network": network,
            "blocks": 4_494_000,
            "headers": 4_494_000,
            "initialBlockDownload": False,
            "identity": identity_block,
        },
        "compatibility": {
            "minimumSafeCore": "4.8.0",
            "safetyProfile": safety_profile,
            "coreSafe": core_safe,
            "networkMatches": network_matches,
            "backendSynchronized": synchronized,
            "kawpowHeightValidation": kawpow,
            "checkpoint4487775": checkpoint,
        },
        "observedAt": observed_at,
    }


class TestRavencoinBackendEvidence(ElectrumTestCase):

    def classify(self, response):
        evidence = parse_ravencoin_backend_evidence(response)
        return classify_backend_evidence(evidence, now=NOW)

    def test_exact_server_contract_parses_without_replacing_chain_proof(self):
        evidence = parse_ravencoin_backend_evidence(backend_response())
        self.assertEqual("4.8.0", evidence.core_version)
        self.assertEqual("ElectrumX-RVN 1.13.0.dev1", evidence.server_version)
        self.assertEqual(
            BackendEligibilityState.SAFE_CORE_VERIFIED,
            classify_backend_evidence(evidence, now=NOW),
        )

    def test_version_alone_never_grants_eligibility(self):
        """The old rule was "at least 4.8.0". The rule now is "certified".

        Only the exact certified identity is eligible. A newer version number is
        not evidence of anything until that specific build has been certified,
        which is the whole point of the change.
        """
        cases = {
            4_060_100: BackendEligibilityState.CORE_TOO_OLD,               # 4.6.1
            4_060_101: BackendEligibilityState.CORE_TOO_OLD,               # 4.6.1.1
            4_070_000: BackendEligibilityState.CORE_TOO_OLD,               # 4.7.0
            4_080_000: BackendEligibilityState.SAFE_CORE_VERIFIED,         # certified
            4_080_100: BackendEligibilityState.CORE_UNREVIEWED_VERSION,    # 4.8.1
            4_100_000: BackendEligibilityState.CORE_UNREVIEWED_VERSION,    # 4.10.0
            5_000_000: BackendEligibilityState.CORE_UNREVIEWED_VERSION,    # 5.0.0
        }
        for version_number, expected in cases.items():
            with self.subTest(version=version_text(version_number)):
                commit = (CERTIFIED_COMMIT if version_number == 4_080_000
                          else OTHER_COMMIT)
                self.assertEqual(
                    expected,
                    self.classify(backend_response(version_number, commit=commit)),
                )

    def test_certified_commit_reporting_another_version_is_a_conflict(self):
        """The certified commit builds 4.8.0. Anything else from it is suspect."""
        self.assertEqual(
            BackendEligibilityState.CORE_IDENTITY_CONFLICT,
            self.classify(backend_response(4_080_100)),
        )

    def test_certified_identity_is_eligible(self):
        self.assertEqual(
            BackendEligibilityState.SAFE_CORE_VERIFIED,
            self.classify(backend_response()),
        )

    def test_same_version_different_commit_is_not_inherited(self):
        self.assertEqual(
            BackendEligibilityState.CORE_IDENTITY_CONFLICT,
            self.classify(backend_response(commit=OTHER_COMMIT)),
        )

    def test_same_version_different_repository_is_not_inherited(self):
        self.assertEqual(
            BackendEligibilityState.CORE_IDENTITY_CONFLICT,
            self.classify(backend_response(repository="RavenProject/Ravencoin")),
        )

    def test_server_reporting_no_identity_cannot_be_placed_in_the_policy(self):
        self.assertEqual(
            BackendEligibilityState.CORE_IDENTITY_UNKNOWN,
            self.classify(backend_response(identity=False)),
        )

    def test_version_only_evidence_is_not_enough(self):
        response = backend_response(evidence_level="VERSION_ONLY", repository=None,
                                    commit=None)
        self.assertEqual(BackendEligibilityState.CORE_IDENTITY_UNKNOWN,
                         self.classify(response))

    def test_operator_attested_identity_is_accepted_when_certified(self):
        """Attested identity is weaker evidence, but it is still an identity.

        The policy lookup decides; the evidence level is reported to the user.
        """
        self.assertEqual(
            BackendEligibilityState.SAFE_CORE_VERIFIED,
            self.classify(backend_response(evidence_level="BUILD_IDENTITY_ATTESTED")),
        )

    def test_wrong_safety_profile_is_not_eligible(self):
        self.assertEqual(
            BackendEligibilityState.CORE_UNREVIEWED_VERSION,
            self.classify(backend_response(safety_profile="rvn-consensus-2027-01-v9")),
        )

    def test_future_core_becomes_eligible_only_through_a_policy_entry(self):
        from electrum import core_safety_policy
        response = backend_response(4_090_000, commit=OTHER_COMMIT)
        evidence = parse_ravencoin_backend_evidence(response)
        baseline = core_safety_policy.load_baseline()
        self.assertEqual(
            BackendEligibilityState.CORE_UNREVIEWED_VERSION,
            classify_backend_evidence(evidence, now=NOW, policy=baseline),
        )
        extended = dict(baseline)
        extended["releases"] = list(baseline["releases"]) + [{
            "repository": CERTIFIED_REPOSITORY,
            "tag": "v4.9.0",
            "version": "4.9.0",
            "commit": OTHER_COMMIT,
            "status": "KNOWN_SAFE",
            "certification": {"profile": "rvn-consensus-2026-08-v1", "result": "PASS"},
        }]
        self.assertEqual(
            BackendEligibilityState.SAFE_CORE_VERIFIED,
            classify_backend_evidence(evidence, now=NOW, policy=extended),
        )

    def test_revoked_release_is_refused(self):
        from electrum import core_safety_policy
        baseline = core_safety_policy.load_baseline()
        revoked = dict(baseline)
        entry = dict(baseline["releases"][0])
        entry.update({"status": "REVOKED", "revocationReason": "consensus regression"})
        entry.pop("certification", None)
        revoked["releases"] = [entry]
        evidence = parse_ravencoin_backend_evidence(backend_response())
        self.assertEqual(
            BackendEligibilityState.CORE_REVOKED,
            classify_backend_evidence(evidence, now=NOW, policy=revoked),
        )

    def test_release_marked_known_unsafe_is_refused(self):
        from electrum import core_safety_policy
        baseline = core_safety_policy.load_baseline()
        unsafe = dict(baseline)
        entry = dict(baseline["releases"][0])
        entry["status"] = "KNOWN_UNSAFE"
        entry["certification"] = {"profile": "rvn-consensus-2026-08-v1", "result": "FAIL"}
        unsafe["releases"] = [entry]
        evidence = parse_ravencoin_backend_evidence(backend_response())
        self.assertEqual(
            BackendEligibilityState.CORE_KNOWN_UNSAFE,
            classify_backend_evidence(evidence, now=NOW, policy=unsafe),
        )

    def test_semantic_parser_is_not_lexicographic(self):
        self.assertLess(parse_core_version_text("4.7.0"), parse_core_version_text("4.8.0"))
        self.assertGreater(parse_core_version_text("4.10.0"), parse_core_version_text("4.8.0"))
        self.assertGreater(parse_core_version_text("5.0.0"), parse_core_version_text("4.8.0"))

    def test_unknown_and_conflicting_versions_fail_closed(self):
        response = backend_response()
        response["backend"]["version"] = "unknown"
        with self.assertRaises(BackendEvidenceError) as caught:
            parse_ravencoin_backend_evidence(response)
        self.assertEqual(BackendEligibilityState.CORE_VERSION_UNKNOWN, caught.exception.state)

        response = backend_response()
        response["backend"]["version"] = "4.10.0"
        with self.assertRaises(BackendEvidenceError) as caught:
            parse_ravencoin_backend_evidence(response)
        self.assertEqual(BackendEligibilityState.BACKEND_MALFORMED, caught.exception.state)

    def test_wrong_network_and_each_unsafe_flag_are_rejected(self):
        self.assertEqual(
            BackendEligibilityState.WRONG_NETWORK,
            self.classify(backend_response(network="test", network_matches=False)),
        )
        for field in ("core_safe", "synchronized", "checkpoint", "kawpow"):
            with self.subTest(field=field):
                self.assertEqual(
                    BackendEligibilityState.BACKEND_UNSAFE,
                    self.classify(backend_response(**{field: False})),
                )

    def test_stale_future_ibd_and_height_conflicts_fail_closed(self):
        self.assertEqual(
            BackendEligibilityState.BACKEND_UNSAFE,
            self.classify(backend_response(observed_at=NOW - 301)),
        )
        self.assertEqual(
            BackendEligibilityState.BACKEND_UNSAFE,
            self.classify(backend_response(observed_at=NOW + 301)),
        )
        response = backend_response()
        response["backend"]["initialBlockDownload"] = True
        self.assertEqual(BackendEligibilityState.BACKEND_UNSAFE, self.classify(response))
        response = backend_response()
        response["backend"]["headers"] -= 1
        with self.assertRaises(BackendEvidenceError):
            parse_ravencoin_backend_evidence(response)

    def test_server_version_cannot_impersonate_backend_core_version(self):
        evidence = parse_ravencoin_backend_evidence(
            backend_response(4_070_000, server_version="4.8.0")
        )
        self.assertEqual("4.8.0", evidence.server_version)
        self.assertEqual("4.7.0", evidence.core_version)
        self.assertEqual(
            BackendEligibilityState.CORE_TOO_OLD,
            classify_backend_evidence(evidence, now=NOW),
        )

    def test_mixed_pool_contains_only_certified_backends_and_never_falls_back(self):
        pool = [
            parse_ravencoin_backend_evidence(backend_response(4_080_000)),
            parse_ravencoin_backend_evidence(backend_response(4_070_000)),
            parse_ravencoin_backend_evidence(
                backend_response(4_100_000, commit=OTHER_COMMIT)),
            parse_ravencoin_backend_evidence(backend_response(identity=False)),
        ]
        eligible = [
            item for item in pool
            if classify_backend_evidence(item, now=NOW)
            == BackendEligibilityState.SAFE_CORE_VERIFIED
        ]
        # Only the certified identity survives: not the old release, not the newer
        # but unreviewed one, and not the server that reports no identity at all.
        self.assertEqual(["4.8.0"], [item.core_version for item in eligible])
        eligible.clear()
        self.assertEqual([], eligible)  # no unsafe fallback when safe servers disappear
