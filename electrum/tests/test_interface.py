import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiorpcx.jsonrpc import JSONRPC, RPCError

from electrum.interface import GracefulDisconnect, Interface, RequestTimedOut, ServerAddr
from electrum.ravencoin_backend import BackendEligibilityState

from .test_ravencoin_backend import backend_response

from . import ElectrumTestCase


class TestServerAddr(ElectrumTestCase):

    def test_from_str(self):
        self.assertEqual(ServerAddr(host="104.198.149.61", port=80, protocol="t"),
                         ServerAddr.from_str("104.198.149.61:80:t"))
        self.assertEqual(ServerAddr(host="ecdsa.net", port=110, protocol="s"),
                         ServerAddr.from_str("ecdsa.net:110:s"))
        self.assertEqual(ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s"),
                         ServerAddr.from_str("[2400:6180:0:d1::86b:e001]:50002:s"))
        self.assertEqual(ServerAddr(host="localhost", port=8080, protocol="s"),
                         ServerAddr.from_str("localhost:8080:s"))

    def test_from_str_with_inference(self):
        self.assertEqual(None, ServerAddr.from_str_with_inference("104.198.149.61"))
        self.assertEqual(None, ServerAddr.from_str_with_inference("ecdsa.net"))
        self.assertEqual(None, ServerAddr.from_str_with_inference("2400:6180:0:d1::86b:e001"))
        self.assertEqual(None, ServerAddr.from_str_with_inference("[2400:6180:0:d1::86b:e001]"))
        self.assertEqual(ServerAddr(host="104.198.149.61", port=80, protocol="s"),
                         ServerAddr.from_str_with_inference("104.198.149.61:80"))
        self.assertEqual(ServerAddr(host="ecdsa.net", port=110, protocol="s"),
                         ServerAddr.from_str_with_inference("ecdsa.net:110"))
        self.assertEqual(ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s"),
                         ServerAddr.from_str_with_inference("[2400:6180:0:d1::86b:e001]:50002"))

        self.assertEqual(ServerAddr(host="104.198.149.61", port=80, protocol="t"),
                         ServerAddr.from_str_with_inference("104.198.149.61:80:t"))
        self.assertEqual(ServerAddr(host="ecdsa.net", port=110, protocol="s"),
                         ServerAddr.from_str_with_inference("ecdsa.net:110:s"))
        self.assertEqual(ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s"),
                         ServerAddr.from_str_with_inference("[2400:6180:0:d1::86b:e001]:50002:s"))

    def test_to_friendly_name(self):
        self.assertEqual("104.198.149.61:80:t",
                         ServerAddr(host="104.198.149.61", port=80, protocol="t").to_friendly_name())
        self.assertEqual("ecdsa.net:110",
                         ServerAddr(host="ecdsa.net", port=110, protocol="s").to_friendly_name())
        self.assertEqual("ecdsa.net:50001:t",
                         ServerAddr(host="ecdsa.net", port=50001, protocol="t").to_friendly_name())
        self.assertEqual("[2400:6180:0:d1::86b:e001]:50002",
                         ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002,
                                    protocol="s").to_friendly_name())
        self.assertEqual("[2400:6180:0:d1::86b:e001]:50001:t",
                         ServerAddr(host="2400:6180:0:d1::86b:e001", port=50001,
                                    protocol="t").to_friendly_name())


class TestRequiredRavencoinBackendCapability(unittest.IsolatedAsyncioTestCase):

    @staticmethod
    def interface_with_response(response):
        interface = object.__new__(Interface)
        interface.session = Mock()
        interface.session.send_request = AsyncMock(return_value=response)
        interface.logger = Mock()
        interface.ravencoin_backend_state = BackendEligibilityState.CORE_VERSION_UNKNOWN
        interface.ravencoin_backend_error = None
        interface.server_version = (
            response.get("serverVersion") if isinstance(response, dict) else None
        )
        interface.chain_validation_state = "PENDING"
        return interface

    async def test_safe_response_is_eligible_prerequisite(self):
        interface = self.interface_with_response(backend_response())
        evidence = await interface.request_ravencoin_backend_evidence(required=True)
        self.assertEqual("4.8.0", evidence.core_version)
        self.assertEqual(
            BackendEligibilityState.SAFE_CORE_VERIFIED,
            interface.ravencoin_backend_state,
        )

    async def test_method_not_found_fails_closed(self):
        interface = self.interface_with_response(None)
        interface.session.send_request.side_effect = RPCError(
            JSONRPC.METHOD_NOT_FOUND, "method not found"
        )
        with self.assertRaises(GracefulDisconnect):
            await interface.request_ravencoin_backend_evidence(required=True)
        self.assertEqual(
            BackendEligibilityState.BACKEND_METHOD_UNAVAILABLE,
            interface.ravencoin_backend_state,
        )

    async def test_timeout_fails_closed(self):
        interface = self.interface_with_response(None)
        interface.session.send_request.side_effect = RequestTimedOut("timeout")
        with self.assertRaises(GracefulDisconnect):
            await interface.request_ravencoin_backend_evidence(required=True)
        self.assertEqual(BackendEligibilityState.UNREACHABLE,
                         interface.ravencoin_backend_state)

    async def test_malformed_response_fails_closed_without_logging_body(self):
        interface = self.interface_with_response({"server": "untrusted"})
        with self.assertRaises(GracefulDisconnect):
            await interface.request_ravencoin_backend_evidence(required=True)
        self.assertEqual(BackendEligibilityState.BACKEND_MALFORMED,
                         interface.ravencoin_backend_state)
        interface.logger.info.assert_called_once_with(
            'server returned malformed Ravencoin backend evidence'
        )

    async def test_old_core_rejected_even_if_server_version_claims_4_8(self):
        interface = self.interface_with_response(
            backend_response(4_070_000, server_version="4.8.0")
        )
        interface.server_version = "4.8.0"
        with self.assertRaises(GracefulDisconnect) as caught:
            await interface.request_ravencoin_backend_evidence(required=True)
        self.assertIn("Core 4.7.0", str(caught.exception))
        self.assertEqual(BackendEligibilityState.CORE_TOO_OLD,
                         interface.ravencoin_backend_state)

    async def test_conflicting_electrumx_identity_fails_closed(self):
        interface = self.interface_with_response(backend_response())
        interface.server_version = "different ElectrumX identity"
        with self.assertRaises(GracefulDisconnect):
            await interface.request_ravencoin_backend_evidence(required=True)
        self.assertEqual(BackendEligibilityState.BACKEND_MALFORMED,
                         interface.ravencoin_backend_state)

    async def test_capability_remains_optional_off_mainnet(self):
        interface = self.interface_with_response(None)
        interface.session.send_request.side_effect = RPCError(
            JSONRPC.METHOD_NOT_FOUND, "method not found"
        )
        self.assertIsNone(
            await interface.request_ravencoin_backend_evidence(required=False)
        )

    async def test_chain_conflict_never_marks_interface_ready(self):
        interface = self.interface_with_response(backend_response())
        interface._process_header_at_tip = AsyncMock(
            side_effect=GracefulDisconnect("checkpoint conflict")
        )
        interface._mark_ready = Mock()
        with self.assertRaises(GracefulDisconnect):
            await interface._validate_tip_and_mark_ready()
        interface._mark_ready.assert_not_called()
        self.assertEqual("CONFLICT", interface.chain_validation_state)
        self.assertEqual(BackendEligibilityState.CHAIN_CONFLICT,
                         interface.ravencoin_backend_state)

    async def test_perfect_backend_claim_with_chain_conflict_is_never_verified_safe(self):
        """SAFE_CORE_VERIFIED is a self-reported claim, not remote-binary
        attestation (F4): a malicious server can make the backend-gate state
        SAFE_CORE_VERIFIED purely by claiming the certified identity, but that
        alone must never be enough to use the server. The independent chain
        leg still has to agree, and a conflict there must sink the whole
        endpoint regardless of how perfect the backend claim looked.
        """
        interface = self.interface_with_response(backend_response())
        interface.ravencoin_backend = await interface.request_ravencoin_backend_evidence(
            required=True
        )
        self.assertEqual(BackendEligibilityState.SAFE_CORE_VERIFIED,
                         interface.ravencoin_backend_state)
        interface._process_header_at_tip = AsyncMock(
            side_effect=GracefulDisconnect("checkpoint conflict")
        )
        interface._mark_ready = Mock()
        with self.assertRaises(GracefulDisconnect):
            await interface._validate_tip_and_mark_ready()
        interface._mark_ready.assert_not_called()
        self.assertFalse(interface.is_safe_ravencoin_mainnet_endpoint)
        self.assertEqual(BackendEligibilityState.CHAIN_CONFLICT,
                         interface.ravencoin_backend_state)

    async def test_periodic_revalidation_downgrades_a_now_unsafe_backend(self):
        """F5: SAFE_CORE_VERIFIED must not survive indefinitely on stale
        evidence. revalidate_backend_periodically re-requests
        server.ravencoin_backend on a live session; if the server's evidence
        is no longer safe, the session is torn down exactly like the initial
        gate rather than staying latched on the first classification.
        """
        interface = self.interface_with_response(backend_response())
        interface.ravencoin_backend = await interface.request_ravencoin_backend_evidence(
            required=True
        )
        self.assertEqual(BackendEligibilityState.SAFE_CORE_VERIFIED,
                         interface.ravencoin_backend_state)
        # The server's evidence changes on the next poll: no longer safe.
        interface.session.send_request = AsyncMock(
            return_value=backend_response(core_safe=False)
        )
        with patch("electrum.interface.asyncio.sleep", new=AsyncMock()):
            with self.assertRaises(GracefulDisconnect):
                await interface.revalidate_backend_periodically()
        self.assertEqual(BackendEligibilityState.BACKEND_UNSAFE,
                         interface.ravencoin_backend_state)

    async def test_periodic_revalidation_keeps_polling_while_still_safe(self):
        interface = self.interface_with_response(backend_response())
        interface.ravencoin_backend = await interface.request_ravencoin_backend_evidence(
            required=True
        )
        sleeps = AsyncMock(side_effect=[None, None, RuntimeError("stop test loop")])
        with patch("electrum.interface.asyncio.sleep", new=sleeps):
            with self.assertRaises(RuntimeError):
                await interface.revalidate_backend_periodically()
        self.assertEqual(3, sleeps.await_count)
        self.assertEqual(BackendEligibilityState.SAFE_CORE_VERIFIED,
                         interface.ravencoin_backend_state)

    async def test_valid_chain_marks_safe_interface_ready(self):
        interface = self.interface_with_response(backend_response())
        interface.ravencoin_backend = await interface.request_ravencoin_backend_evidence(
            required=True
        )
        interface._process_header_at_tip = AsyncMock(return_value=True)
        interface._mark_ready = Mock()
        self.assertTrue(await interface._validate_tip_and_mark_ready())
        interface._mark_ready.assert_called_once_with()
        self.assertEqual("VERIFIED", interface.chain_validation_state)
        self.assertTrue(interface.is_safe_ravencoin_mainnet_endpoint)
