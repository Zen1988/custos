import unittest
from unittest.mock import Mock, patch

import requests

from custos.providers.vcenter import VCenterClient, VCenterConfig, VCenterError


class VCenterTests(unittest.TestCase):
    def config(self, **kwargs):
        return VCenterConfig("https://vc.example.test", "reader", "secret", **kwargs)

    def response(self, data=None, status=200):
        return Mock(status_code=status, json=Mock(return_value=data))

    @patch("custos.providers.vcenter.requests.Session")
    def test_inventory_session_lifecycle_and_tls(self, factory):
        session = factory.return_value
        session.headers = {}
        session.request.side_effect = [self.response("private-token"), self.response([
            {"vm": "vm-12", "name": "app", "power_state": "POWERED_ON",
             "cpu_count": 2, "memory_size_MiB": 4096}]), self.response()]
        with VCenterClient(self.config()) as client:
            self.assertEqual(client.list_vms()[0].id, "vm-12")
        self.assertEqual([call.args[0] for call in session.request.call_args_list],
                         ["POST", "GET", "DELETE"])
        for call in session.request.call_args_list:
            self.assertIs(call.kwargs["verify"], True)
            self.assertFalse(call.kwargs["allow_redirects"])
            self.assertEqual(call.kwargs["timeout"], 15)
        self.assertNotIn("vmware-api-session-id", session.headers)
        session.close.assert_called_once()

    def test_reject_unsafe_origins(self):
        for url in ["http://vc", "https://user:secret@vc", "https://vc/api", "https://vc?q=1"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                VCenterConfig(url, "reader", "secret")
        self.assertNotIn("secret", repr(self.config()))

    @patch("custos.providers.vcenter.requests.Session")
    def test_auth_error_does_not_leak_provider_body(self, factory):
        factory.return_value.request.return_value = self.response("secret", 401)
        with self.assertRaisesRegex(VCenterError, "authentication failed"):
            with VCenterClient(self.config()):
                self.fail("Must not connect")
        factory.return_value.close.assert_called_once()

    @patch("custos.providers.vcenter.requests.Session")
    def test_inventory_failure_still_logs_out(self, factory):
        factory.return_value.request.side_effect = [self.response("token"),
                                                    self.response({}), self.response()]
        with self.assertRaisesRegex(VCenterError, "invalid VM"):
            with VCenterClient(self.config()) as client:
                client.list_vms()
        self.assertEqual(factory.return_value.request.call_args.args[0], "DELETE")

    @patch("custos.providers.vcenter.requests.Session")
    def test_transport_error_is_sanitized(self, factory):
        factory.return_value.request.side_effect = requests.exceptions.SSLError("secret")
        with self.assertRaisesRegex(VCenterError, "CA trust") as error:
            with VCenterClient(self.config()):
                pass
        self.assertNotIn("secret", str(error.exception))


if __name__ == "__main__":
    unittest.main()
