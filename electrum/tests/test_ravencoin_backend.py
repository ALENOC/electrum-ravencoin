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


def backend_response(
        version_number=4_080_000, *, core_safe=True, network="main",
        network_matches=True, synchronized=True, checkpoint=True, kawpow=True,
        observed_at=NOW, server_version="ElectrumX-RVN 1.13.0.dev1"):
    core_version = version_text(version_number)
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
        },
        "compatibility": {
            "minimumSafeCore": "4.8.0",
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

    def test_numeric_version_matrix(self):
        cases = {
            4_060_100: BackendEligibilityState.CORE_TOO_OLD,       # 4.6.1
            4_060_101: BackendEligibilityState.CORE_TOO_OLD,       # 4.6.1.1
            4_070_000: BackendEligibilityState.CORE_TOO_OLD,       # 4.7.0
            4_080_000: BackendEligibilityState.SAFE_CORE_VERIFIED, # 4.8.0
            4_080_100: BackendEligibilityState.SAFE_CORE_VERIFIED, # 4.8.1
            4_100_000: BackendEligibilityState.SAFE_CORE_VERIFIED, # 4.10.0
            5_000_000: BackendEligibilityState.SAFE_CORE_VERIFIED, # 5.0.0
        }
        for version_number, expected in cases.items():
            with self.subTest(version=version_text(version_number)):
                self.assertEqual(expected, self.classify(backend_response(version_number)))

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

    def test_mixed_pool_contains_only_safe_backends_and_never_falls_back(self):
        pool = [
            parse_ravencoin_backend_evidence(backend_response(4_080_000)),
            parse_ravencoin_backend_evidence(backend_response(4_070_000)),
            parse_ravencoin_backend_evidence(backend_response(4_100_000)),
        ]
        eligible = [
            item for item in pool
            if classify_backend_evidence(item, now=NOW)
            == BackendEligibilityState.SAFE_CORE_VERIFIED
        ]
        self.assertEqual(["4.8.0", "4.10.0"], [item.core_version for item in eligible])
        eligible.clear()
        self.assertEqual([], eligible)  # no unsafe fallback when safe servers disappear
