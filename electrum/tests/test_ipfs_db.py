"""Regression tests for the IPFSDB singleton and headless-daemon shutdown.

Defects covered (found by the release-readiness hang investigation):
1. IPFSDB.__new__ checked ``hasattr(cls, "instance")`` while setting
   ``_instance``, so the singleton guard never tripped and every
   construction re-created and re-bound the object.
2. Daemon.stop() unconditionally called IPFSDB.get_instance().write();
   only the Qt GUI initializes the DB, so any headless daemon crashed on
   shutdown with AttributeError (which, via a leaked test lock, also hung
   entire test files).
"""
import asyncio
import tempfile

from electrum import util
from electrum.daemon import Daemon
from electrum.ipfs_db import IPFSDB
from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase


class _IPFSDBStateIsolated(ElectrumTestCase):
    """IPFSDB is a process-global singleton; isolate its initialization
    state per test so order never matters."""

    def setUp(self):
        super().setUp()
        self._saved_instance = getattr(IPFSDB, "_instance", None)
        if hasattr(IPFSDB, "_instance"):
            del IPFSDB._instance

    def tearDown(self):
        if self._saved_instance is not None or hasattr(IPFSDB, "_instance"):
            IPFSDB._instance = self._saved_instance
        super().tearDown()


class TestIPFSDBSingleton(_IPFSDBStateIsolated):

    def test_not_initialized_by_default(self):
        self.assertFalse(IPFSDB.is_initialized())
        with self.assertRaises(AttributeError):
            IPFSDB.get_instance()

    def test_construction_is_singleton(self):
        path = tempfile.mkdtemp()
        a = IPFSDB(path + "/ipfs.json", path + "/ipfs_raw")
        b = IPFSDB(path + "/ipfs.json", path + "/ipfs_raw")
        self.assertIs(a, b)
        self.assertTrue(IPFSDB.is_initialized())


class TestHeadlessDaemonStop(_IPFSDBStateIsolated):

    async def test_daemon_stop_without_ipfs_initialization(self):
        """A daemon started without the Qt GUI must stop cleanly even
        though IPFSDB.initialize() was never called."""
        self.assertFalse(IPFSDB.is_initialized())
        config = SimpleConfig({'electrum_path': self.electrum_path})
        config.NETWORK_OFFLINE = True
        daemon = Daemon(config=config, listen_jsonrpc=False)
        self.assertIsNone(daemon.network)
        await daemon.stop()  # must not raise
