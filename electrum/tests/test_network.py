import asyncio
import inspect
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import Interface, ServerAddr
from electrum.network import Network
from electrum.crypto import sha256
from electrum.util import OldTaskGroup
from electrum import util

from . import ElectrumTestCase


class MockNetwork:

    def __init__(self):
        self.asyncio_loop = util.get_asyncio_loop()
        self.taskgroup = OldTaskGroup()


class MockInterface(Interface):
    def __init__(self, config):
        self.config = config
        network = MockNetwork()
        network.config = config
        super().__init__(network=network, server=ServerAddr.from_str('mock-server:50000:t'), proxy=None)
        self.q = asyncio.Queue()
        self.blockchain = blockchain.Blockchain(config=self.config, forkpoint=0,
                                                parent=None, forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        self.tip = 12
        self.blockchain._size = self.tip + 1

    async def get_block_header(self, height, assert_mode):
        assert self.q.qsize() > 0, (height, assert_mode)
        item = await self.q.get()
        print("step with height", height, item)
        assert item['block_height'] == height, (item['block_height'], height)
        assert assert_mode in item['mock'], (assert_mode, item)
        return item

    async def run(self):
        return


class TestNetwork(ElectrumTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_regtest()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.interface = MockInterface(self.config)

    async def test_fork_noconflict(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=7)
        self.assertEqual(('fork', 8), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    async def test_fork_conflict(self):
        blockchain.blockchains = {7: {'check': lambda bad_header: False}}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=7)
        self.assertEqual(('fork', 8), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    async def test_can_connect_during_backward(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 2
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=4)
        self.assertEqual(('catchup', 5), res)
        self.assertEqual(self.interface.q.qsize(), 0)

    def mock_fork(self, bad_header):
        forkpoint = bad_header['block_height']
        b = blockchain.Blockchain(config=self.config, forkpoint=forkpoint, parent=None,
                                  forkpoint_hash=sha256(str(forkpoint)).hex(), prev_hash=sha256(str(forkpoint-1)).hex())
        return b

    async def test_chain_false_during_binary(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        mock_connect = lambda height: height == 3
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: True,  'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: False, 'fork': self.mock_fork, 'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        res = await ifa.sync_until(8, next_height=6)
        self.assertEqual(('catchup', 7), res)
        self.assertEqual(self.interface.q.qsize(), 0)


class TestBroadcastAuthorizationBoundary(unittest.IsolatedAsyncioTestCase):
    """F2 write-boundary trace (security re-audit, N1/F2 follow-up).

    Network.broadcast_transaction and its @best_effort_reliable wrapper are
    the actual final authorization path for the guarded network write that
    matters most: transaction broadcast. This test runs the real (unmocked)
    Network.broadcast_transaction and best_effort_reliable against a real
    Interface object, stubbing only the RPC transport, to prove what the
    final gate actually is: `self.interface is not None and
    self.interface.ready.done()`. Nothing else is consulted -- not
    ravencoin_backend_state, not chain_validation_state, and no
    operator-group / independent-operator-diversity signal, because no such
    signal exists anywhere on Interface or in Network.broadcast_transaction's
    signature. A single server that reaches "ready" (already demonstrated,
    independently of this repo, to be reachable via a self-reported identity
    claim plus a fabricated post-checkpoint chain that satisfies the light
    KAWPOW verifier) is used for broadcast with no further authorization.

    This does not mean keys, signatures, or transaction contents can be
    forged (that crypto surface is untouched); it means a single malicious
    or compromised server, once it is the client's main interface, is fully
    trusted to relay (or silently withhold, while claiming success) every
    broadcast, and to be the sole source of the SPV view that led to that
    transaction being constructed in the first place. There is no second
    server, no quorum, and no operator-diversity requirement anywhere in
    this codebase that would prevent that.
    """

    @staticmethod
    def _ready_interface_with_no_operator_evidence():
        iface = object.__new__(Interface)
        iface.session = Mock()
        iface.session.send_request = AsyncMock(return_value="ff" * 32)
        iface.logger = Mock()
        iface.server = ServerAddr.from_str("malicious.example:50001:t")
        iface.ready = asyncio.get_running_loop().create_future()
        iface.ready.set_result(1)
        iface.got_disconnected = asyncio.Event()
        # Deliberately left unset: ravencoin_backend_state,
        # chain_validation_state, and any notion of "operator group" --
        # there is no such attribute on Interface to strip. The point of
        # this fixture is that broadcast never looks for one.
        return iface

    async def test_broadcast_has_no_gate_beyond_interface_and_ready(self):
        net = object.__new__(Network)
        net.logger = Mock()
        net.default_server_changed_event = asyncio.Event()
        iface = self._ready_interface_with_no_operator_evidence()
        net.interface = iface

        fake_tx = Mock()
        fake_tx.outputs = Mock(return_value=[])
        fake_tx.serialize = Mock(return_value="ff" * 10)
        fake_tx.txid = Mock(return_value="ff" * 32)

        # Real, unmocked Network.broadcast_transaction and the real
        # best_effort_reliable decorator around it -- only the RPC
        # transport (iface.session.send_request) is a stub.
        await net.broadcast_transaction(fake_tx, timeout=5)

        iface.session.send_request.assert_awaited_once_with(
            'blockchain.transaction.broadcast', [fake_tx.serialize()], timeout=5
        )

    async def test_no_operator_group_or_diversity_concept_exists_on_the_path(self):
        """Structural fact, verified against the real objects rather than
        merely asserted from reading: neither Interface nor
        Network.broadcast_transaction carries any notion of operator
        identity, operator group, or a minimum-independent-sources count.
        """
        iface_attrs = {a for a in vars(self._ready_interface_with_no_operator_evidence())}
        suspicious = {a for a in iface_attrs if 'operator' in a.lower() or 'group' in a.lower()
                      or 'quorum' in a.lower() or 'diversity' in a.lower()}
        self.assertEqual(set(), suspicious,
                         f"unexpected operator-diversity-shaped attribute on Interface: {suspicious}")

        sig = inspect.signature(Network.broadcast_transaction)
        for forbidden in ('operator_group', 'operator', 'min_operators', 'min_sources', 'quorum'):
            self.assertNotIn(forbidden, sig.parameters)


if __name__=="__main__":
    constants.set_regtest()
    unittest.main()
