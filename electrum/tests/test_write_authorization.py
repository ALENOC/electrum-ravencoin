"""F2 write-authorization gate: independent-operator consensus for broadcast.

interface.ready, the policy-conforming backend claim, and
chain_validation_state == VERIFIED are each necessary but not sufficient for
trusted chain-dependent state. A single server is still one operator. The
same independent recent-chain evidence now gates both broadcast and promotion
of server-provided state to SPV-verified wallet state.
These tests exercise the real, unmocked Network.get_write_authorization()
and Network.broadcast_transaction() against fixture interfaces standing in
for the adversarial scenarios from the F2 re-audit.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from electrum import constants
from electrum.interface import Interface, ServerAddr
from electrum.network import (
    BroadcastNotAuthorized,
    MIN_INDEPENDENT_OPERATOR_GROUPS,
    Network,
    RECENT_AGREEMENT_WINDOW,
    WriteAuthorizationState,
    operator_group_for_server,
)
from electrum.ravencoin_backend import BackendEligibilityState

from . import ElectrumTestCase


HONEST_HEIGHT = 4_000_000
HONEST_HASH = "aa" * 32
FABRICATED_HASH = "bb" * 32

FIXTURE_SERVERS = {
    "cipig-a.example": {"operatorGroup": "CIPIG"},
    "cipig-b.example": {"operatorGroup": "CIPIG"},
    "cipig-c.example": {"operatorGroup": "CIPIG"},
    "alenoc-a.example": {"operatorGroup": "ALENOC"},
    "alenoc-b.example": {"operatorGroup": "ALENOC"},
    "independent.example": {"operatorGroup": "INDEPENDENT_OP"},
    "no-metadata.example": {},  # present in the list but no operatorGroup key
}


def _server(host: str) -> ServerAddr:
    return ServerAddr.from_str(f"{host}:50001:t")


def _safe_interface(host: str, *, height: int = HONEST_HEIGHT, chain_hash: str = HONEST_HASH,
                    safe: bool = True) -> Interface:
    """A fixture Interface individually reaching the exact state that, before
    this remediation, was sufficient to authorize a broadcast on its own."""
    iface = object.__new__(Interface)
    iface.server = _server(host)
    if safe:
        iface.ravencoin_backend_state = BackendEligibilityState.SAFE_CORE_VERIFIED
        iface.chain_validation_state = "VERIFIED"
        iface.ravencoin_backend = Mock()
    else:
        iface.ravencoin_backend_state = BackendEligibilityState.CHAIN_CONFLICT
        iface.chain_validation_state = "CONFLICT"
        iface.ravencoin_backend = None
    iface.blockchain = Mock()
    iface.blockchain.height = Mock(return_value=height)
    iface.blockchain.get_hash = Mock(return_value=chain_hash)
    iface.session = Mock()
    iface.session.send_request = AsyncMock(return_value="ff" * 32)
    iface.logger = Mock()
    # readiness primitives for _validated_interfaces()/revalidation checks
    iface.ready = Mock()
    iface.ready.done = Mock(return_value=True)
    iface.got_disconnected = Mock()
    iface.got_disconnected.is_set = Mock(return_value=False)
    iface.tip = height
    return iface


def _network_with_interfaces(*interfaces: Interface) -> Network:
    net = object.__new__(Network)
    net.logger = Mock()
    net.interfaces_lock = __import__("threading").Lock()
    net.interfaces = {iface.server: iface for iface in interfaces}
    net.interface = interfaces[0] if interfaces else None
    net.default_server_changed_event = asyncio.Event() if interfaces else None
    return net


class TestOperatorGroupForServer(ElectrumTestCase):

    def test_known_server_returns_its_group(self):
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            self.assertEqual("CIPIG", operator_group_for_server(_server("cipig-a.example")))

    def test_unknown_server_returns_none(self):
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            self.assertIsNone(operator_group_for_server(_server("totally-unknown.example")))

    def test_known_server_missing_operator_group_key_returns_none(self):
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            self.assertIsNone(operator_group_for_server(_server("no-metadata.example")))

    def test_does_not_infer_group_from_hostname_or_ip_shape(self):
        """Two totally different, unrelated hostnames with no directory
        metadata must not be treated as independent -- absence of identity
        is not evidence of independence."""
        with patch.object(constants.net, "DEFAULT_SERVERS", {}):
            self.assertIsNone(operator_group_for_server(_server("1.2.3.4")))
            self.assertIsNone(operator_group_for_server(_server("totally-unrelated-host.example")))


class TestWriteAuthorizationGate(ElectrumTestCase):
    """Direct tests of Network.get_write_authorization()."""

    def test_no_validated_interfaces_is_unverified(self):
        net = _network_with_interfaces()
        auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.UNVERIFIED_CHAIN, auth.state)

    def test_unsafe_interfaces_do_not_count(self):
        iface = _safe_interface("cipig-a.example", safe=False)
        net = _network_with_interfaces(iface)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.UNVERIFIED_CHAIN, auth.state)

    def test_single_operator_group_is_insufficient(self):
        """Case A / B: one malicious (or honest) operator, any number of its
        own endpoints, is not independent consensus."""
        a = _safe_interface("cipig-a.example")
        b = _safe_interface("cipig-b.example")
        c = _safe_interface("cipig-c.example")
        net = _network_with_interfaces(a, b, c)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY, auth.state)
        self.assertEqual(1, auth.operator_group_count)

    def test_two_independent_agreeing_operators_authorize(self):
        a = _safe_interface("cipig-a.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        b = _safe_interface("independent.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        net = _network_with_interfaces(a, b)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, auth.state)
        self.assertEqual(2, auth.operator_group_count)

    def test_two_independent_conflicting_operators_block(self):
        a = _safe_interface("cipig-a.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        b = _safe_interface("independent.example", height=HONEST_HEIGHT, chain_hash=FABRICATED_HASH)
        net = _network_with_interfaces(a, b)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, auth.state)

    def test_conflict_result_is_independent_of_connection_order(self):
        a = _safe_interface("cipig-a.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        b = _safe_interface("independent.example", height=HONEST_HEIGHT, chain_hash=FABRICATED_HASH)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth_ab = _network_with_interfaces(a, b).get_write_authorization()
            auth_ba = _network_with_interfaces(b, a).get_write_authorization()
        self.assertEqual(auth_ab.state, auth_ba.state)
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, auth_ab.state)

    def test_agreeing_operators_are_authorized_regardless_of_connection_order(self):
        a = _safe_interface("cipig-a.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        b = _safe_interface("independent.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth_ab = _network_with_interfaces(a, b).get_write_authorization()
            auth_ba = _network_with_interfaces(b, a).get_write_authorization()
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, auth_ab.state)
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, auth_ba.state)

    def test_minor_tip_divergence_between_honest_operators_is_not_a_conflict(self):
        """Two honest, independent operators a couple of blocks apart at the
        tip (propagation delay) must not manufacture a false CHAIN_CONFLICT:
        the recent-agreement window ends at the *shortest* validated tip, so
        normal lag within MAX_WITNESS_TIP_LAG stays usable."""
        a = _safe_interface("cipig-a.example", height=HONEST_HEIGHT, chain_hash=HONEST_HASH)
        b = _safe_interface("independent.example", height=HONEST_HEIGHT - 2, chain_hash=HONEST_HASH)
        net = _network_with_interfaces(a, b)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, auth.state)
        # sanity: the window genuinely ended at the shortest tip
        self.assertEqual(HONEST_HEIGHT - 2, auth.window_tip)
        self.assertEqual(HONEST_HEIGHT - 2 - RECENT_AGREEMENT_WINDOW + 1, auth.window_start)
        a.blockchain.get_hash.assert_called_with(HONEST_HEIGHT - 2)

    def test_unknown_operator_endpoint_does_not_count_toward_diversity(self):
        """Case (Step 11): a valid-looking, individually-safe server with no
        known operatorGroup must not silently become its own independent
        group, even paired with one real known operator."""
        known = _safe_interface("cipig-a.example")
        unknown = _safe_interface("no-metadata.example")
        net = _network_with_interfaces(known, unknown)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY, auth.state)
        self.assertEqual(1, auth.operator_group_count)

    def test_three_operators_two_conflicting_is_still_a_conflict_not_a_vote(self):
        """No majority rule: 2-against-1 must still fail closed, not win by
        endpoint/operator count."""
        a = _safe_interface("cipig-a.example", chain_hash=HONEST_HASH)
        b = _safe_interface("alenoc-a.example", chain_hash=HONEST_HASH)
        c = _safe_interface("independent.example", chain_hash=FABRICATED_HASH)
        net = _network_with_interfaces(a, b, c)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, auth.state)

    def test_oneserver_mode_does_not_bypass_the_gate(self):
        """Step 13: there is no separate trusted/owned-infrastructure mode
        with its own anchors in this codebase today (oneserver + TLS
        fingerprint pinning still describes exactly one operator, and does
        not defend against a malicious/compromised pinned server). Public
        mode must not be silently relaxed for it."""
        a = _safe_interface("cipig-a.example")
        net = _network_with_interfaces(a)
        net.oneserver = True
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY, auth.state)


class TestBroadcastGuardedByWriteAuthorization(unittest.IsolatedAsyncioTestCase):
    """The original F2 regression: construct interfaces in exactly the state
    that used to be sufficient to authorize broadcast, and prove the real,
    unmocked Network.broadcast_transaction() refuses to send.
    """

    @staticmethod
    def _fake_tx(txid="ff" * 32):
        tx = Mock()
        tx.outputs = Mock(return_value=[])
        tx.serialize = Mock(return_value="ff" * 10)
        tx.txid = Mock(return_value=txid)
        return tx

    @staticmethod
    def _live(iface: Interface) -> Interface:
        """Give a fixture interface real (resolved) ready/got_disconnected
        primitives, as best_effort_reliable requires of self.interface."""
        iface.ready = asyncio.get_running_loop().create_future()
        iface.ready.set_result(1)
        iface.got_disconnected = asyncio.Event()
        return iface

    async def test_single_fabricated_chain_operator_cannot_authorize_broadcast(self):
        """Case A: one malicious server, individually SAFE_CORE_VERIFIED +
        VERIFIED + ready -- exactly the pre-remediation F2 PoC end state.
        Must not reach the RPC at all.
        """
        malicious = self._live(_safe_interface("cipig-a.example"))  # stands in for the impostor
        net = _network_with_interfaces(malicious)
        tx = self._fake_tx()
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            with self.assertRaises(BroadcastNotAuthorized) as caught:
                await net.broadcast_transaction(tx, timeout=5)
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY,
                         caught.exception.authorization.state)
        malicious.session.send_request.assert_not_called()

    async def test_two_endpoints_same_malicious_operator_cannot_authorize_broadcast(self):
        """Case B: two endpoints, same operatorGroup -- must still count as
        one, and still block."""
        a = self._live(_safe_interface("cipig-a.example"))
        b = self._live(_safe_interface("cipig-b.example"))
        net = _network_with_interfaces(a, b)
        tx = self._fake_tx()
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            with self.assertRaises(BroadcastNotAuthorized):
                await net.broadcast_transaction(tx, timeout=5)
        a.session.send_request.assert_not_called()
        b.session.send_request.assert_not_called()

    async def test_conflicting_independent_operators_cannot_authorize_broadcast(self):
        """Case C: independent operators disagree -- fail closed."""
        a = self._live(_safe_interface("cipig-a.example", chain_hash=HONEST_HASH))
        b = self._live(_safe_interface("independent.example", chain_hash=FABRICATED_HASH))
        net = _network_with_interfaces(a, b)
        tx = self._fake_tx()
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            with self.assertRaises(BroadcastNotAuthorized) as caught:
                await net.broadcast_transaction(tx, timeout=5)
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT,
                         caught.exception.authorization.state)
        a.session.send_request.assert_not_called()
        b.session.send_request.assert_not_called()

    async def test_two_independent_agreeing_operators_authorize_broadcast(self):
        """Case D: independent, agreeing operators -- the RPC should be sent
        (to the currently-selected main interface, as before)."""
        a = self._live(_safe_interface("cipig-a.example", chain_hash=HONEST_HASH))
        b = self._live(_safe_interface("independent.example", chain_hash=HONEST_HASH))
        net = _network_with_interfaces(a, b)
        tx = self._fake_tx(txid=a.blockchain.get_hash.return_value and "ff" * 32)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            await net.broadcast_transaction(tx, timeout=5)
        # broadcast used the (unchanged) main-interface send path
        net.interface.session.send_request.assert_awaited_once_with(
            'blockchain.transaction.broadcast', [tx.serialize()], timeout=5)

    async def test_directory_listing_alone_does_not_authorize_broadcast(self):
        """Case E: a server present in a correctly-signed directory (i.e.
        carrying an operatorGroup claim) but that never actually passed
        individual backend/chain validation must not count. Simulated here
        by an interface that is *not* individually safe -- directory
        membership never substitutes for that validation.
        """
        listed_but_unvalidated = self._live(_safe_interface("independent.example", safe=False))
        only_operator = self._live(_safe_interface("cipig-a.example"))
        net = _network_with_interfaces(only_operator, listed_but_unvalidated)
        tx = self._fake_tx()
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            with self.assertRaises(BroadcastNotAuthorized) as caught:
                await net.broadcast_transaction(tx, timeout=5)
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY,
                         caught.exception.authorization.state)
        only_operator.session.send_request.assert_not_called()

    async def test_ready_safe_verified_alone_is_not_sufficient_comment_regression(self):
        """Guards against someone reverting the gate back to
        `assert interface.ready.done(); send RPC`: an interface that is
        fully ready/safe/verified, alone, must still be refused.
        """
        solo = self._live(_safe_interface("cipig-a.example"))
        net = _network_with_interfaces(solo)
        tx = self._fake_tx()
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            with self.assertRaises(BroadcastNotAuthorized):
                await net.broadcast_transaction(tx, timeout=5)
        solo.session.send_request.assert_not_called()
