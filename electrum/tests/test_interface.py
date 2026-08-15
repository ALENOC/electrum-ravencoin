import unittest
from unittest.mock import AsyncMock, Mock

from aiorpcx.jsonrpc import JSONRPC, RPCError

from electrum.interface import ServerAddr
from electrum.interface import Interface

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
                         ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s").to_friendly_name())
        self.assertEqual("[2400:6180:0:d1::86b:e001]:50001:t",
                         ServerAddr(host="2400:6180:0:d1::86b:e001", port=50001, protocol="t").to_friendly_name())


class TestOptionalRavencoinBackendCapability(unittest.IsolatedAsyncioTestCase):

    @staticmethod
    def interface_with_response(response):
        interface = object.__new__(Interface)
        interface.session = Mock()
        interface.session.send_request = AsyncMock(return_value=response)
        interface.logger = Mock()
        return interface

    async def test_maintained_server_response_is_available_as_self_report(self):
        interface = self.interface_with_response(backend_response())
        evidence = await interface.request_ravencoin_backend_evidence()
        self.assertEqual("4.8.0", evidence.core_version)
        self.assertTrue(evidence.server_reports_compatible_backend)

    async def test_method_not_found_preserves_legacy_server_compatibility(self):
        interface = self.interface_with_response(None)
        interface.session.send_request.side_effect = RPCError(
            JSONRPC.METHOD_NOT_FOUND, "method not found"
        )
        evidence = await interface.request_ravencoin_backend_evidence()
        self.assertIsNone(evidence)
        interface.logger.info.assert_not_called()

    async def test_malformed_response_is_unknown_without_disconnect(self):
        interface = self.interface_with_response({"server": "untrusted"})
        evidence = await interface.request_ravencoin_backend_evidence()
        self.assertIsNone(evidence)
        interface.logger.info.assert_called_once()
