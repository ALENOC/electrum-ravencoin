from electrum.ravencoin_backend import parse_ravencoin_backend_evidence

from . import ElectrumTestCase


def backend_response(version_number=4_080_000, *, core_safe=True):
    return {
        "server": "ElectrumX-RVN",
        "serverVersion": "ElectrumX-RVN 1.13.0.dev1",
        "backend": {
            "name": "Ravencoin Core",
            "version": "4.8.0",
            "versionNumber": version_number,
            "subversion": "/Ravencoin:4.8.0/",
            "network": "main",
            "blocks": 4_494_000,
            "headers": 4_494_000,
            "initialBlockDownload": None,
        },
        "compatibility": {
            "minimumSafeCore": "4.8.0",
            "coreSafe": core_safe,
            "networkMatches": True,
            "backendSynchronized": True,
            "kawpowHeightValidation": True,
            "checkpoint4487775": True,
        },
        "observedAt": 1_786_754_000,
    }


class TestRavencoinBackendEvidence(ElectrumTestCase):

    def test_parses_maintained_server_evidence_without_promoting_it_to_chain_proof(self):
        evidence = parse_ravencoin_backend_evidence(backend_response())
        self.assertEqual("4.8.0", evidence.core_version)
        self.assertEqual("ElectrumX-RVN 1.13.0.dev1", evidence.server_version)
        self.assertTrue(evidence.server_reports_compatible_backend)

    def test_unsafe_self_report_remains_explicit(self):
        evidence = parse_ravencoin_backend_evidence(
            backend_response(4_070_000, core_safe=False)
        )
        self.assertFalse(evidence.server_reports_compatible_backend)

    def test_rejects_malformed_or_internally_impossible_response(self):
        response = backend_response()
        response["backend"]["headers"] = response["backend"]["blocks"] - 1
        with self.assertRaises(ValueError):
            parse_ravencoin_backend_evidence(response)

        with self.assertRaises(ValueError):
            parse_ravencoin_backend_evidence({"server": "ElectrumX-RVN"})
