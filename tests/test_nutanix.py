from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from custos.backend_setup import SetupError
from custos.providers.nutanix import Client, ProviderDenied, VMS, discover, execute, normalized, read_status


class NutanixTests(unittest.TestCase):
    def setUp(self):
        self.uid = str(uuid4())
        self.remote = SimpleNamespace(provider="nutanix", endpoint="https://pc.test:9440", service_username="shared-nutanix")
        self.config = SimpleNamespace(vcenter_uid="nutanix:pc-1", scope={"vm_uids": [self.uid]},
                                      trusted_pem=None, encrypted_password="ciphertext")
        self.vm = SimpleNamespace(id="vm", provider_uid=self.uid, provider_ref=self.uid)

    def row(self, state="OFF"):
        return {"extId": self.uid, "name": "App", "powerState": state,
            "guestTools": {"isReachable": True}, "nics": [{"networkInfo": {"ipv4Info": {
                "learnedIpAddresses": [{"value": "192.0.2.10"}, {"value": "127.0.0.1"}]}}}]}

    def client(self):
        client = Mock()
        client.identity.return_value = "pc-1"
        client.vm.return_value = Mock(headers={"ETag": "etag-vm"}, json=Mock(return_value={"data": self.row()}))
        client.request.return_value = Mock(json=Mock(return_value={"data": {"extId": "task-1"}}))
        client.task_result.return_value = "succeeded"
        client.list.return_value = []
        return client

    def test_discovery_reports_unknown_action_permissions_honestly(self):
        with patch("custos.providers.nutanix.Client") as factory:
            client = factory.return_value.__enter__.return_value
            client.identity.return_value = "pc-1"
            client.list.return_value = [self.row()]
            report = discover(self.remote.endpoint, "shared", "password", "Nutanix AHV v4.0")
        self.assertEqual(report["vcenter_uid"], "nutanix:pc-1")
        self.assertEqual(report["vms"][0]["ips"], ["192.0.2.10"])
        self.assertTrue(report["vms"][0]["capabilities"]["view"])
        self.assertIsNone(report["vms"][0]["capabilities"]["reset"])

    def test_start_uses_etag_idempotency_and_returns_task_completion(self):
        client = self.client()
        operation_id = str(uuid4())
        callback = Mock()
        with patch("custos.providers.nutanix.client_for") as factory:
            factory.return_value.__enter__.return_value = client
            result = execute(self.remote, self.config, self.vm, "start", operation_id, callback)
        self.assertEqual(result, "succeeded")
        call = client.request.call_args
        self.assertEqual(call.args, ("POST", VMS + "/" + self.uid + "/$actions/power-on"))
        self.assertEqual(call.kwargs["headers"], {"If-Match": "etag-vm", "Ntnx-Request-Id": operation_id})
        callback.assert_called_once_with("task-1")

    def test_ngt_unavailable_blocks_graceful_action_without_fallback(self):
        client = self.client()
        row = self.row("ON")
        row["guestTools"]["isReachable"] = False
        client.vm.return_value.json.return_value = {"data": row}
        with patch("custos.providers.nutanix.client_for") as factory:
            factory.return_value.__enter__.return_value = client
            with self.assertRaisesRegex(SetupError, "Guest Tools"):
                execute(self.remote, self.config, self.vm, "stop", str(uuid4()), Mock())
        client.request.assert_not_called()

    def test_provider_denial_is_failure_not_success(self):
        client = self.client()
        client.request.side_effect = ProviderDenied("Nutanix rejected the operation permission")
        with patch("custos.providers.nutanix.client_for") as factory:
            factory.return_value.__enter__.return_value = client
            with self.assertRaises(ProviderDenied):
                execute(self.remote, self.config, self.vm, "start", str(uuid4()), Mock())

    def test_snapshot_uses_recovery_point_and_expiry(self):
        client = self.client()
        with patch("custos.providers.nutanix.client_for") as factory:
            factory.return_value.__enter__.return_value = client
            self.assertEqual(execute(self.remote, self.config, self.vm, "snapshot", str(uuid4()), Mock()), "succeeded")
        body = client.request.call_args.kwargs["json"]
        self.assertEqual(body["vmRecoveryPoints"], [{"vmExtId": self.uid}])
        self.assertEqual(body["recoveryPointType"], "CRASH_CONSISTENT")
        self.assertIn("expirationTime", body)

    def test_login_status_checks_uuid_and_identity(self):
        client = self.client()
        with patch("custos.providers.nutanix.client_for") as factory:
            factory.return_value.__enter__.return_value = client
            self.assertEqual(read_status(self.remote, self.config, [self.vm]), {"vm": "POWERED_OFF"})
            client.identity.return_value = "different-pc"
            self.assertEqual(read_status(self.remote, self.config, [self.vm]), {"vm": "UNKNOWN"})

    def test_pagination_and_duplicate_page_rejection(self):
        client = Client.__new__(Client)
        client.get = Mock(side_effect=[{"data": [self.row()], "metadata": {"totalAvailableResults": 2}},
                                      {"data": [self.row()], "metadata": {"totalAvailableResults": 2}}])
        with self.assertRaisesRegex(SetupError, "duplicate"):
            client.list(VMS)

    def test_transport_does_not_follow_redirects_or_inherit_proxy_credentials(self):
        with patch("custos.providers.nutanix.origin"), patch("custos.providers.nutanix.requests.Session") as factory:
            factory.return_value.request.return_value = Mock(status_code=403)
            with Client("https://pc.test:9440", "user", "password") as client:
                with self.assertRaises(ProviderDenied):
                    client.get(VMS)
        self.assertFalse(factory.return_value.trust_env)
        self.assertFalse(factory.return_value.request.call_args.kwargs["allow_redirects"])
        factory.return_value.close.assert_called_once()
