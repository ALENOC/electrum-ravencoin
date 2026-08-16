"""F-1/F-2 remediation: recent-chain consensus and relay-target binding.

Regression tests for the two release-blocking bypasses found in the F2
write-gate re-audit:

F-1 (anchor-window bypass): agreement at a single buried anchor authorized
   groups whose chains diverged everywhere above it. Authorization now
   requires the identical canonical block hash (Blockchain.get_hash) at
   EVERY height of a bounded recent window ending at the shortest validated
   tip, plus a freshness bound against the best tip any connected interface
   reports.

F-2 (unbound relay target / TOCTOU): the broadcast RPC went to whatever
   self.interface was at send time. Authorization is now a capability that
   binds the exact participant Interface objects and one relay target, and
   broadcast_transaction uses only that target.

All tests run the real Network.get_write_authorization() and (for the F-2
cases) the real Network.broadcast_transaction() production boundary, with
per-height hash fixtures: blockchains agree on an honest prefix and may fork
at a chosen height, so window semantics are actually exercised (a constant
hash mock cannot distinguish anchor from window agreement).
"""
import asyncio
import hashlib
import itertools
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch

from electrum import constants
from electrum.interface import Interface, ServerAddr
from electrum.network import (
    BroadcastNotAuthorized,
    MAX_WITNESS_TIP_LAG,
    MIN_INDEPENDENT_OPERATOR_GROUPS,
    Network,
    RECENT_AGREEMENT_WINDOW,
    WriteAuthorization,
    WriteAuthorizationState,
    operator_group_for_server,
)
from electrum.ravencoin_backend import BackendEligibilityState

from . import ElectrumTestCase

H = 4_000_000  # honest tip height; window covers [H-11, H]


def _hh(label: str, height: int) -> str:
    return hashlib.sha256(f"{label}|{height}".encode()).hexdigest()


def honest_hash(height: int) -> str:
    return _hh("honest", height)


def forked_chain(fork_at: int, label: str = "evil"):
    """hash-per-height chain: honest prefix below fork_at, `label` above."""
    def hash_at(height: int) -> str:
        if height < fork_at:
            return honest_hash(height)
        return _hh(label, height)
    return hash_at


def spoofed_chain(spoof_height: int, spoof_hash: str):
    """Honest everywhere except one interior height (window endpoints match)."""
    def hash_at(height: int) -> str:
        if height == spoof_height:
            return spoof_hash
        return honest_hash(height)
    return hash_at


FIXTURE_SERVERS = {
    "a1.example": {"operatorGroup": "OP_A"},
    "a2.example": {"operatorGroup": "OP_A"},
    "b1.example": {"operatorGroup": "OP_B"},
    "c1.example": {"operatorGroup": "OP_C"},
    "evil1.example": {"operatorGroup": "OP_EVIL"},
    "unknown.example": {},  # listed without operator metadata
    # "not-listed.example" intentionally absent: stands in for a manual server
}


def _server(host: str) -> ServerAddr:
    return ServerAddr.from_str(f"{host}:50001:t")


def make_iface(host, *, chain=honest_hash, height=H, tip=None, safe=True,
               live=False):
    """Individually validated fixture interface on a per-height chain.

    live=True gives real asyncio ready/got_disconnected primitives as
    best_effort_reliable requires of the main interface."""
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
    iface.blockchain.get_hash = Mock(side_effect=chain)
    iface.session = Mock()
    iface.session.send_request = AsyncMock(return_value="ff" * 32)
    iface.logger = Mock()
    iface.tip = height if tip is None else tip
    if live:
        iface.ready = asyncio.get_running_loop().create_future()
        iface.ready.set_result(1)
        iface.got_disconnected = asyncio.Event()
    else:
        iface.ready = Mock()
        iface.ready.done = Mock(return_value=True)
        iface.got_disconnected = Mock()
        iface.got_disconnected.is_set = Mock(return_value=False)
    return iface


def make_net(*interfaces, main=None):
    net = object.__new__(Network)
    net.logger = Mock()
    net.interfaces_lock = threading.Lock()
    net.interfaces = {iface.server: iface for iface in interfaces}
    net.interface = main if main is not None else (interfaces[0] if interfaces else None)
    net.default_server_changed_event = asyncio.Event()
    return net


def fake_tx():
    tx = Mock()
    tx.outputs = Mock(return_value=[])
    tx.serialize = Mock(return_value="ff" * 10)
    tx.txid = Mock(return_value="ff" * 32)
    return tx


def total_sends(net) -> int:
    count = 0
    for iface in net.interfaces.values():
        count += iface.session.send_request.await_count
    if net.interface is not None and net.interface.server not in net.interfaces:
        count += net.interface.session.send_request.await_count
    return count


class TestRecentChainAgreement(ElectrumTestCase):
    """F-1 gate cases: forks in/around the window, freshness, evidence failure."""

    def _auth(self, net):
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            return net.get_write_authorization()

    def test_A_full_window_agreement_authorizes(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example")
        auth = self._auth(make_net(a, b))
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, auth.state)
        self.assertEqual((H - RECENT_AGREEMENT_WINDOW + 1, H), (auth.window_start, auth.window_tip))
        self.assertEqual(2, auth.operator_group_count)
        # every height of the window was compared, not just the endpoints
        for height in range(auth.window_start, auth.window_tip + 1):
            a.blockchain.get_hash.assert_any_call(height)
            b.blockchain.get_hash.assert_any_call(height)
        # the capability binds the exact participants and a relay target
        self.assertEqual(2, len(auth.participant_interfaces))
        self.assertIn(auth.relay_interface, auth.participant_interfaces)

    def test_B_fork_at_common_height_blocks(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=forked_chain(H))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b)).state)

    def test_C_fork_one_below_common_blocks(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=forked_chain(H - 1))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b)).state)

    def test_D_fork_two_below_common_blocks(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=forked_chain(H - 2))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b)).state)

    def test_E_fork_five_below_common_blocks(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=forked_chain(H - 5))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b)).state)

    def test_F2_taller_fabricated_chain_blocked_by_freshness(self):
        """The audited taller-chain variant: evil claims H+100 with the fork
        just above the honest tip. The window cannot see blocks above the
        shortest tip -- the freshness bound must."""
        a = make_iface("a1.example")
        evil = make_iface("evil1.example", chain=forked_chain(H + 1, "tall-evil"), height=H + 100)
        self.assertEqual(WriteAuthorizationState.STALE_CHAIN_EVIDENCE,
                         self._auth(make_net(a, evil)).state)

    def test_G_interior_fork_with_matching_window_endpoints_blocks(self):
        """Window endpoints agree, one interior height differs: a comparison
        of only the first/last hashes would miss this."""
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=spoofed_chain(H - 6, "ee" * 32))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b)).state)

    def test_H_stale_witness_beyond_lag_bound_blocks(self):
        a = make_iface("a1.example", height=H, tip=H)
        b = make_iface("b1.example", height=H - (MAX_WITNESS_TIP_LAG + 3),
                       tip=H - (MAX_WITNESS_TIP_LAG + 3))
        self.assertEqual(WriteAuthorizationState.STALE_CHAIN_EVIDENCE,
                         self._auth(make_net(a, b)).state)

    def test_H2_lag_at_exactly_bound_is_fresh(self):
        a = make_iface("a1.example", height=H, tip=H)
        b = make_iface("b1.example", height=H - MAX_WITNESS_TIP_LAG,
                       tip=H - MAX_WITNESS_TIP_LAG)
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, self._auth(make_net(a, b)).state)

    def test_H3_stale_main_interface_does_not_lower_freshness_bar(self):
        """A silent-but-connected stale witness must not authorize writes
        about a present the rest of the network has moved past: the bar is
        the best tip ANY connected interface reports."""
        stale_a = make_iface("a1.example", height=H - 500, tip=H - 500)
        stale_b = make_iface("b1.example", height=H - 500, tip=H - 500)
        fresh_unknown = make_iface("unknown.example", height=H, tip=H)  # cannot vote, can raise the bar
        self.assertEqual(WriteAuthorizationState.STALE_CHAIN_EVIDENCE,
                         self._auth(make_net(stale_a, stale_b, fresh_unknown)).state)

    def test_I_missing_window_evidence_blocks(self):
        def missing_at(height):
            if height == H - 4:
                raise KeyError(height)  # stands in for MissingHeader
            return honest_hash(height)
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=missing_at)
        self.assertEqual(WriteAuthorizationState.UNVERIFIED_CHAIN, self._auth(make_net(a, b)).state)

    def test_J_evidence_exception_blocks(self):
        def boom(height):
            raise RuntimeError("evidence gathering failed")
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=boom)
        self.assertEqual(WriteAuthorizationState.UNVERIFIED_CHAIN, self._auth(make_net(a, b)).state)

    def test_J2_height_exception_blocks(self):
        """A participant whose blockchain.height() raises must fail the gate
        closed with a defined state, never crash it open (phase-7 attack)."""
        a = make_iface("a1.example")
        b = make_iface("b1.example")
        b.blockchain.height = Mock(side_effect=RuntimeError("boom"))
        self.assertEqual(WriteAuthorizationState.UNVERIFIED_CHAIN, self._auth(make_net(a, b)).state)

    def test_J4_non_integer_height_blocks(self):
        """A witness height that is not a plain int (float/bool/str) is
        malformed evidence and must fail closed, not be truncated into the
        window or freshness arithmetic (phase-6 'wrong type' attack)."""
        for bad in (H + 0.5, float(H), True, "4000000"):
            a = make_iface("a1.example")
            b = make_iface("b1.example", height=bad, tip=bad)
            self.assertEqual(
                WriteAuthorizationState.UNVERIFIED_CHAIN,
                self._auth(make_net(a, b)).state,
                msg=f"height={bad!r}")

    def test_J5_fractional_tip_cannot_lower_freshness_bar(self):
        """A fractional server-reported tip must round the freshness bar UP
        (ceil), never truncate it down: honest A+B at H with a connected
        spammer claiming tip H+2.5 must read as lag 3, not 2."""
        a = make_iface("a1.example", height=H, tip=H)
        b = make_iface("b1.example", height=H, tip=H)
        spam = make_iface("unknown.example", height=H, tip=H + 2.5)
        self.assertEqual(WriteAuthorizationState.STALE_CHAIN_EVIDENCE,
                         self._auth(make_net(a, b, spam)).state)

    def test_J3_connected_height_exception_does_not_crash_gate(self):
        """A connected interface (even a non-voting one) whose height() raises
        must not break evidence gathering; its server-reported tip still
        counts toward the freshness bar."""
        a = make_iface("a1.example")
        b = make_iface("b1.example")
        spam = make_iface("unknown.example", height=H + 500, tip=H + 500)
        spam.blockchain.height = Mock(side_effect=RuntimeError("boom"))
        self.assertEqual(WriteAuthorizationState.STALE_CHAIN_EVIDENCE,
                         self._auth(make_net(a, b, spam)).state)

    def test_K_three_groups_two_agree_one_conflicts_no_majority(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example")
        c = make_iface("c1.example", chain=forked_chain(H - 30))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b, c)).state)

    def test_L_two_endpoints_of_one_operator_are_one_group(self):
        a1 = make_iface("a1.example")
        a2 = make_iface("a2.example")
        auth = self._auth(make_net(a1, a2))
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY, auth.state)
        self.assertEqual(1, auth.operator_group_count)

    def test_M_known_plus_unknown_manual_is_insufficient(self):
        a = make_iface("a1.example")
        unknown = make_iface("not-listed.example")  # manual server: no operator identity
        auth = self._auth(make_net(a, unknown))
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY, auth.state)
        self.assertEqual(1, auth.operator_group_count)

    def test_window_underflow_fails_closed(self):
        a = make_iface("a1.example", height=RECENT_AGREEMENT_WINDOW - 1)
        b = make_iface("b1.example", height=RECENT_AGREEMENT_WINDOW - 1)
        self.assertEqual(WriteAuthorizationState.UNVERIFIED_CHAIN, self._auth(make_net(a, b)).state)

    def test_deep_fork_below_window_still_detected(self):
        """Divergence persists at every height above a fork point: a fork far
        below the window must not slip through just because it is old."""
        a = make_iface("a1.example")
        b = make_iface("b1.example", chain=forked_chain(H - 10_000))
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT, self._auth(make_net(a, b)).state)

    def test_permutation_invariance(self):
        ifaces = [make_iface("a1.example"), make_iface("a2.example"),
                  make_iface("b1.example"), make_iface("c1.example", chain=forked_chain(H - 30))]
        seen = set()
        for perm in itertools.permutations(ifaces):
            auth = self._auth(make_net(*perm))
            seen.add((auth.state, auth.operator_group_count))
        self.assertEqual({(WriteAuthorizationState.CHAIN_CONFLICT, 3)}, seen)


class TestRelayTargetBinding(unittest.IsolatedAsyncioTestCase):
    """F-2 cases through the real broadcast_transaction() boundary, plus the
    permanent end-to-end F-1 regression."""

    def _net_ab(self):
        """A+B honest known groups agreeing; main interface = A."""
        a = make_iface("a1.example", live=True)
        b = make_iface("b1.example", live=True)
        return a, b, make_net(a, b, main=a)

    async def _broadcast(self, net):
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            await net.broadcast_transaction(fake_tx(), timeout=5)

    async def test_F_permanent_regression_old_anchor_bypass_geometry(self):
        """The audited F-1 bypass exactly: fork one block ABOVE the old
        min(heights)-6 anchor, evil group a known independent operator and
        the main interface. Old gate: AUTHORIZED + raw tx relayed to evil.
        Required now: blocked before any RPC."""
        a = make_iface("a1.example", live=True)
        evil = make_iface("evil1.example", chain=forked_chain(H - 5), live=True)
        net = make_net(a, evil, main=evil)
        with self.assertRaises(BroadcastNotAuthorized) as caught:
            await self._broadcast(net)
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT,
                         caught.exception.authorization.state)
        self.assertEqual(0, total_sends(net))

    async def test_1_main_interface_unauthorized_unknown_gets_no_rpc(self):
        """A+B authorize; self.interface is a ready, individually validated
        but unknown-operator server on a fabricated chain. It must receive
        ZERO rpc calls; the relay is a bound participant."""
        a, b, net = self._net_ab()
        evil_main = make_iface("unknown.example", chain=forked_chain(3_900_000), live=True)
        net.interfaces[evil_main.server] = evil_main
        net.interface = evil_main
        await self._broadcast(net)
        self.assertEqual(0, evil_main.session.send_request.await_count)
        relayed = [i for i in (a, b) if i.session.send_request.await_count == 1]
        self.assertEqual(1, len(relayed))
        relayed[0].session.send_request.assert_awaited_once_with(
            'blockchain.transaction.broadcast', ['ff' * 10], timeout=5)

    async def test_1b_manual_unlisted_main_interface_gets_no_rpc(self):
        a, b, net = self._net_ab()
        manual = make_iface("not-listed.example", chain=forked_chain(3_900_000), live=True)
        net.interfaces[manual.server] = manual
        net.interface = manual
        await self._broadcast(net)
        self.assertEqual(0, manual.session.send_request.await_count)
        self.assertEqual(1, a.session.send_request.await_count + b.session.send_request.await_count)

    async def test_2_mid_call_interface_swap_gets_no_rpc(self):
        """self.interface changes to the malicious server inside the
        gate->send window: the capability was already bound, so the swap
        cannot redirect the relay."""
        a, b, net = self._net_ab()
        evil = make_iface("unknown.example", chain=forked_chain(3_900_000), live=True)
        original = Network.get_write_authorization

        def swapping_gate(self):
            result = original(self)
            self.interface = evil  # concurrent switch_to_interface lands here
            return result
        with patch.object(Network, "get_write_authorization", swapping_gate), \
                patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            await net.broadcast_transaction(fake_tx(), timeout=5)
        self.assertEqual(0, evil.session.send_request.await_count)
        self.assertEqual(1, a.session.send_request.await_count + b.session.send_request.await_count)

    async def test_3_relay_target_disconnects_before_broadcast(self):
        a, b, net = self._net_ab()
        a.got_disconnected.set()  # target died before the call
        with self.assertRaises(BroadcastNotAuthorized) as caught:
            await self._broadcast(net)
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY,
                         caught.exception.authorization.state)
        self.assertEqual(0, total_sends(net))

    async def test_4_relay_target_not_ready_before_broadcast(self):
        """With B as main, a not-ready A drops out of the authorization
        evidence entirely: one group remains, write blocked, no RPC."""
        a, b, net = self._net_ab()
        net.interface = b
        a.ready = Mock()
        a.ready.done = Mock(return_value=False)
        with self.assertRaises(BroadcastNotAuthorized) as caught:
            await self._broadcast(net)
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY,
                         caught.exception.authorization.state)
        self.assertEqual(0, total_sends(net))

    async def test_5_relay_target_loses_safe_backend_state(self):
        a, b, net = self._net_ab()
        a.ravencoin_backend_state = BackendEligibilityState.CHAIN_CONFLICT
        a.chain_validation_state = "CONFLICT"
        with self.assertRaises(BroadcastNotAuthorized):
            await self._broadcast(net)
        self.assertEqual(0, total_sends(net))

    async def test_6_chain_evidence_changes_before_broadcast(self):
        a, b, net = self._net_ab()
        a.blockchain.get_hash = Mock(side_effect=forked_chain(H - 5))
        with self.assertRaises(BroadcastNotAuthorized) as caught:
            await self._broadcast(net)
        self.assertEqual(WriteAuthorizationState.CHAIN_CONFLICT,
                         caught.exception.authorization.state)
        self.assertEqual(0, total_sends(net))

    async def test_7_replacement_object_same_host_cannot_reuse_authorization(self):
        """An authorization capability bound to interface object a1 must not
        survive replacement of the registered interface for the same host:
        hostname/operatorGroup equality is not object identity. A fresh
        authorization may of course bind the new object."""
        a, b, net = self._net_ab()
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
            self.assertTrue(net._relay_target_still_authorized(auth))
        replacement = make_iface("a1.example", live=True)
        net.interfaces[replacement.server] = replacement
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            self.assertFalse(net._relay_target_still_authorized(auth))
            # fresh decision binds the new object and relays through it
            await net.broadcast_transaction(fake_tx(), timeout=5)
        self.assertEqual(0, a.session.send_request.await_count)
        self.assertEqual(1, replacement.session.send_request.await_count)

    async def test_8_safe_known_non_participant_main_gets_no_rpc(self):
        """self.interface is a known-operator server whose individual safety
        state has degraded (ready but no longer validated): it is not a
        participant, so it must not relay."""
        a, b, net = self._net_ab()
        degraded = make_iface("c1.example", safe=False, live=True)
        net.interfaces[degraded.server] = degraded
        net.interface = degraded
        await self._broadcast(net)
        self.assertEqual(0, degraded.session.send_request.await_count)
        self.assertEqual(1, a.session.send_request.await_count + b.session.send_request.await_count)

    async def test_relay_prefers_participant_main_else_lexical_minimum(self):
        a, b, net = self._net_ab()
        net.interface = b  # main interface is participant B
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
            await net.broadcast_transaction(fake_tx(), timeout=5)
        self.assertIs(b, auth.relay_interface)
        b.session.send_request.assert_awaited_once()
        self.assertEqual(0, a.session.send_request.await_count)

    async def test_relay_selection_ignores_unregistered_same_host_clone(self):
        """self.interface is an UNREGISTERED replacement object for a
        participant's host. Relay preference must key on object identity of
        participants, never on hostname equality with self.interface: the
        clone is not the object whose evidence was authorized (and the relay
        falls through to the deterministic lexical minimum participant)."""
        a, b, net = self._net_ab()
        clone = make_iface("b1.example", live=True)  # same host as b, different object
        net.interface = clone  # not registered in net.interfaces
        await self._broadcast(net)
        self.assertEqual(0, clone.session.send_request.await_count)
        a.session.send_request.assert_awaited_once()  # lexical minimum, not b
        self.assertEqual(0, b.session.send_request.await_count)

    async def test_relay_selection_independent_of_insertion_order(self):
        from electrum.interface import ServerAddr as _SA
        expected = _SA.from_str("a1.example:50001:t")  # lexical minimum participant
        relays = set()
        for hosts in [("a1.example", "b1.example"), ("b1.example", "a1.example")]:
            net = make_net(*[make_iface(h) for h in hosts])
            net.interface = None  # isolate selection from main-interface preference
            with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
                relays.add(net.get_write_authorization().relay_interface.server)
        self.assertEqual({expected}, relays)

    async def test_original_f2_single_operator_still_blocked(self):
        evil = make_iface("evil1.example", chain=forked_chain(3_900_000), live=True)
        net = make_net(evil, main=evil)
        with self.assertRaises(BroadcastNotAuthorized) as caught:
            await self._broadcast(net)
        self.assertEqual(WriteAuthorizationState.INSUFFICIENT_OPERATOR_DIVERSITY,
                         caught.exception.authorization.state)
        self.assertEqual(0, total_sends(net))


class TestRelayRevalidation(ElectrumTestCase):
    """Direct pre-send revalidation semantics (the hook the broadcast path
    calls; cases that cannot be interleaved legitimately because nothing
    awaits between gate and send)."""

    def _authorized_net(self):
        a = make_iface("a1.example")
        b = make_iface("b1.example")
        net = make_net(a, b, main=a)
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            auth = net.get_write_authorization()
        self.assertEqual(WriteAuthorizationState.AUTHORIZED, auth.state)
        return net, a, b, auth

    def _reval(self, net, auth):
        with patch.object(constants.net, "DEFAULT_SERVERS", FIXTURE_SERVERS):
            return net._relay_target_still_authorized(auth)

    def test_valid_target_passes(self):
        net, a, b, auth = self._authorized_net()
        self.assertTrue(self._reval(net, auth))

    def test_disconnected_target_fails(self):
        net, a, b, auth = self._authorized_net()
        a.got_disconnected.is_set = Mock(return_value=True)
        self.assertFalse(self._reval(net, auth))

    def test_unsafe_target_fails(self):
        net, a, b, auth = self._authorized_net()
        a.ravencoin_backend_state = BackendEligibilityState.CHAIN_CONFLICT
        self.assertFalse(self._reval(net, auth))

    def test_unregistered_target_fails(self):
        net, a, b, auth = self._authorized_net()
        net.interfaces.pop(a.server)
        self.assertFalse(self._reval(net, auth))

    def test_replaced_target_object_fails(self):
        net, a, b, auth = self._authorized_net()
        net.interfaces[a.server] = make_iface("a1.example")
        self.assertFalse(self._reval(net, auth))

    def test_non_participant_relay_fails_even_if_safe(self):
        """A forged capability whose relay target is not one of the
        participants must be rejected even when the target is individually
        perfectly safe (relay must come from the evidence set)."""
        net, a, b, auth = self._authorized_net()
        outsider = make_iface("c1.example")  # safe, known, but not a participant
        net.interfaces[outsider.server] = outsider
        forged = auth._replace(relay_interface=outsider)
        self.assertFalse(self._reval(net, forged))

    def test_none_relay_fails(self):
        net, a, b, auth = self._authorized_net()
        self.assertFalse(self._reval(net, auth._replace(relay_interface=None)))
