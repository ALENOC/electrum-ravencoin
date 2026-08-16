import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiorpcx.jsonrpc import JSONRPC, RPCError

from electrum.interface import (GracefulDisconnect, Interface, RequestCorrupted,
                                RequestTimedOut, ServerAddr)
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
        interface.blockchain = None
        interface.tip_header = None
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
        interface._initialize_blockchain_state = Mock()
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
        interface._initialize_blockchain_state = Mock()
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
        interface._initialize_blockchain_state = Mock()
        interface._process_header_at_tip = AsyncMock(return_value=True)
        interface._mark_ready = Mock()
        self.assertTrue(await interface._validate_tip_and_mark_ready())
        interface._mark_ready.assert_called_once_with()
        self.assertEqual("VERIFIED", interface.chain_validation_state)
        self.assertTrue(interface.is_safe_ravencoin_mainnet_endpoint)


class TestBlockchainInitializationOrdering(unittest.IsolatedAsyncioTestCase):
    """N1 regression: _process_header_at_tip() dereferences self.blockchain,
    which used to be initialized only inside _mark_ready() -- but the fork's
    security redesign moved _mark_ready() to *after* _process_header_at_tip()
    (correctly, for readiness/trust), which orphaned the blockchain-object
    selection and made every session crash with AttributeError on the first
    header. These tests run the real (unmocked) _initialize_blockchain_state,
    _process_header_at_tip, and _mark_ready bodies -- reverting either the
    ordering in _validate_tip_and_mark_ready or the extraction of
    _initialize_blockchain_state must make them fail, not just pass because a
    mock was called.
    """

    @staticmethod
    def _bare_interface(*, fake_chain):
        interface = object.__new__(Interface)
        interface.session = Mock()
        interface.logger = Mock()
        interface.chain_validation_state = "PENDING"
        interface.ravencoin_backend_state = BackendEligibilityState.SAFE_CORE_VERIFIED
        interface.ravencoin_backend = Mock()
        interface.blockchain = None
        interface.tip_header = {"block_height": 5}
        interface.tip = 5
        interface.network = Mock()
        interface.network.bhi_lock = asyncio.Lock()
        interface.ready = asyncio.get_running_loop().create_future()
        interface.got_disconnected = asyncio.Event()
        interface._fake_chain = fake_chain
        return interface

    async def test_blockchain_is_set_before_process_header_at_tip_observes_it(self):
        fake_chain = Mock()
        fake_chain.height = Mock(return_value=5)
        fake_chain.check_header = Mock(return_value=True)  # "already have this header"
        interface = self._bare_interface(fake_chain=fake_chain)

        with patch("electrum.interface.blockchain.check_header", return_value=fake_chain):
            # Real _initialize_blockchain_state, real _process_header_at_tip,
            # real _mark_ready -- nothing about chain selection or header
            # processing is mocked away.
            blockchain_updated = await interface._validate_tip_and_mark_ready()

        self.assertIsNotNone(interface.blockchain, "blockchain must be initialized")
        self.assertIs(interface.blockchain, fake_chain)
        self.assertFalse(blockchain_updated)  # fast-forward path: already had this header
        self.assertEqual("VERIFIED", interface.chain_validation_state)
        self.assertTrue(interface.ready.done())
        self.assertEqual(1, interface.ready.result())
        self.assertTrue(interface.is_safe_ravencoin_mainnet_endpoint)

    async def test_validation_failure_still_blocks_readiness_after_blockchain_init(self):
        """Blockchain initialization must not be conflated with security
        readiness: even once self.blockchain is set, a validation failure in
        _process_header_at_tip() must still prevent _mark_ready() from ever
        resolving the ready future.
        """
        fake_chain = Mock()
        # height too low, and check_header refuses -> _process_header_at_tip
        # falls through to self.step(), which we make raise, simulating a
        # real chain-validation failure (e.g. checkpoint conflict).
        fake_chain.height = Mock(return_value=0)
        fake_chain.check_header = Mock(return_value=False)
        interface = self._bare_interface(fake_chain=fake_chain)
        interface.step = AsyncMock(side_effect=GracefulDisconnect("checkpoint conflict"))

        with patch("electrum.interface.blockchain.check_header", return_value=fake_chain):
            with self.assertRaises(GracefulDisconnect):
                await interface._validate_tip_and_mark_ready()

        # Blockchain selection (pure init) still happened...
        self.assertIsNotNone(interface.blockchain)
        # ...but readiness/trust was never granted.
        self.assertEqual("CONFLICT", interface.chain_validation_state)
        self.assertFalse(interface.ready.done())
        self.assertFalse(interface.is_safe_ravencoin_mainnet_endpoint)


class TestIsSafeRavencoinMainnetEndpointProperty(unittest.TestCase):
    """N4: is_safe_ravencoin_mainnet_endpoint is the designated final-trust
    predicate (interface.py). Before this test, the entire focused suite
    passed even with the chain_validation_state leg deleted from the
    property (only the backend-claim leg remained), because nothing pinned
    the property's boolean algebra directly -- only its *consequences* via
    higher-level flows. This exercises the full truth table so dropping,
    inverting, or OR-ing any single leg is caught here directly.
    """

    @staticmethod
    def _interface(*, backend_state, chain_state, backend_evidence):
        iface = object.__new__(Interface)
        iface.ravencoin_backend_state = backend_state
        iface.chain_validation_state = chain_state
        iface.ravencoin_backend = backend_evidence
        return iface

    def test_all_three_legs_required(self):
        SAFE = BackendEligibilityState.SAFE_CORE_VERIFIED
        UNSAFE = BackendEligibilityState.CHAIN_CONFLICT
        evidence = Mock()
        cases = [
            # (backend_state, chain_state, evidence, expected)
            (SAFE, "VERIFIED", evidence, True),
            (SAFE, "VERIFIED", None, False),           # backend evidence missing
            (SAFE, "PENDING", evidence, False),         # chain not yet verified
            (SAFE, "CONFLICT", evidence, False),         # this is exactly N4's mutation target
            (UNSAFE, "VERIFIED", evidence, False),       # backend claim not safe
            (UNSAFE, "CONFLICT", evidence, False),
            (UNSAFE, "VERIFIED", None, False),
        ]
        for backend_state, chain_state, ev, expected in cases:
            with self.subTest(backend_state=backend_state, chain_state=chain_state,
                              evidence=ev is not None):
                iface = self._interface(backend_state=backend_state, chain_state=chain_state,
                                        backend_evidence=ev)
                self.assertEqual(expected, iface.is_safe_ravencoin_mainnet_endpoint)


class TestChunkStraddlesKawpowActivation(unittest.IsolatedAsyncioTestCase):
    """N3: request_chunk() must accept a chunk whose headers straddle
    KawpowActivationHeight (some legacy 80-byte, some kawpow 120-byte),
    since verify_chunk/save_chunk already parse each header at its own
    size. The prior check compared only the chunk's end height against the
    activation height and demanded uniform 120-byte headers for the *whole*
    chunk, incorrectly rejecting a genuinely mixed, correct response with
    RequestCorrupted.
    """

    @staticmethod
    def _interface_for_chunk_test(response):
        iface = object.__new__(Interface)
        iface.session = Mock()
        iface.session.send_request = AsyncMock(return_value=response)
        iface.logger = Mock()
        iface._requested_chunks = set()
        iface.blockchain = Mock()
        iface.blockchain.connect_chunk = AsyncMock(return_value=True)
        return iface

    async def test_chunk_straddling_activation_is_accepted(self):
        activation = 1000
        legacy_count = 20
        kawpow_count = 16
        size = legacy_count + kawpow_count
        height = activation - legacy_count
        hex_blob = "00" * (legacy_count * 80 + kawpow_count * 120)
        response = {"count": size, "hex": hex_blob, "max": 2016}
        iface = self._interface_for_chunk_test(response)

        with patch("electrum.interface.constants.net.KawpowActivationHeight", activation), \
             patch("electrum.interface.constants.net.DGW_CHECKPOINTS_START", 10_000_000):
            result = await iface.request_chunk(height, tip=height + size - 1)

        self.assertEqual((True, size), result)
        iface.blockchain.connect_chunk.assert_awaited_once_with(height, hex_blob)

    async def test_pure_legacy_chunk_still_rejects_wrong_length(self):
        activation = 1000
        # wrong: kawpow-sized (120b) hex for a chunk entirely below activation
        response = {"count": 10, "hex": "00" * (10 * 120), "max": 2016}
        iface = self._interface_for_chunk_test(response)
        with patch("electrum.interface.constants.net.KawpowActivationHeight", activation), \
             patch("electrum.interface.constants.net.DGW_CHECKPOINTS_START", 10_000_000):
            with self.assertRaises(RequestCorrupted):
                await iface.request_chunk(0, tip=9)

    async def test_pure_kawpow_chunk_still_rejects_wrong_length(self):
        activation = 1000
        # wrong: legacy-sized (80b) hex for a chunk entirely above activation
        response = {"count": 10, "hex": "00" * (10 * 80), "max": 2016}
        iface = self._interface_for_chunk_test(response)
        with patch("electrum.interface.constants.net.KawpowActivationHeight", activation), \
             patch("electrum.interface.constants.net.DGW_CHECKPOINTS_START", 10_000_000):
            with self.assertRaises(RequestCorrupted):
                await iface.request_chunk(2000, tip=2009)

    async def test_straddling_chunk_with_wrong_length_is_still_rejected(self):
        """The fix must not become permissive in general -- a straddling
        chunk with a genuinely wrong total length must still be refused."""
        activation = 1000
        legacy_count = 20
        kawpow_count = 16
        size = legacy_count + kawpow_count
        height = activation - legacy_count
        # one byte short of the correct mixed-size total
        hex_blob = "00" * (legacy_count * 80 + kawpow_count * 120 - 1)
        response = {"count": size, "hex": hex_blob, "max": 2016}
        iface = self._interface_for_chunk_test(response)
        with patch("electrum.interface.constants.net.KawpowActivationHeight", activation), \
             patch("electrum.interface.constants.net.DGW_CHECKPOINTS_START", 10_000_000):
            with self.assertRaises(RequestCorrupted):
                await iface.request_chunk(height, tip=height + size - 1)
