import os
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import Session

from custos.backend_setup import SetupError, decrypt, discover, encrypt
from custos.database import (AdminRole, BackendConfig, Base, RemoteSystem, Tenant, VM, VMAddress)
from custos.local_identity import create_local_user
from web.app import create_app


class BackendWizardTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"CUSTOS_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "DATABASE_URL": "sqlite://"})
        self.engine = self.app.extensions["custos_engine"]
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as db, db.begin():
            user = create_local_user(db, "admin", "Admin", "test password for admin")
            self.user_id = user.id
            db.add(AdminRole(principal_id=user.id))
            db.add(Tenant(id="t", name="Tenant"))
        self.client = self.app.test_client()
        with self.client.session_transaction(base_url="https://localhost") as cookie:
            cookie["principal_id"] = self.user_id
            cookie["csrf"] = "csrf-test"

    def post(self, **data):
        return self.client.post("/admin/backends/setup", base_url="https://localhost", data={"csrf": "csrf-test", **data})

    def report(self, missing=False):
        actions = {a: True for a in ["view", "console", "start", "stop", "reboot", "reset", "snapshot"]}
        actions["reset"] = not missing
        return {"version": "8.0.3", "vcenter_uid": "vc-uuid", "vms": [{"uid": "vm-uuid", "ref": "vm-12",
            "name": "App", "ips": ["192.0.2.2", "2001:db8::2"], "state": "poweredOn", "tools": "guestToolsRunning",
            "capabilities": actions}]}

    def connect(self):
        self.client.get("/admin/backends/setup", base_url="https://localhost")
        with patch("web.backend_wizard.certificate_test", return_value={"trusted": True}):
            response = self.post(action="connect", name="VC", version="8.0 U3", endpoint="https://vc.test")
        self.assertEqual(response.status_code, 200)

    def api(self, missing=False):
        with patch("web.backend_wizard.discover", return_value=self.report(missing)):
            return self.post(action="api", username="svc", password="backend-super-secret")

    def test_admin_redirect_and_nonadmin_block(self):
        self.assertEqual(self.client.get("/", base_url="https://localhost").location, "/admin/backends/setup")
        with Session(self.engine) as db, db.begin():
            db.delete(db.get(AdminRole, self.user_id))
        self.assertEqual(self.client.get("/admin/backends/setup", base_url="https://localhost").status_code, 403)

    def test_complete_scoped_sync_encrypted_secret_and_all_addresses(self):
        self.connect()
        response = self.api()
        self.assertNotIn("backend-super-secret", response.text)
        with patch("web.backend_wizard.discover", return_value=self.report()), patch(
                "web.backend_wizard.resolve_addresses", return_value={"192.0.2.2": "app.test", "2001:db8::2": None}) as dns:
            response = self.post(action="sync", vm="vm-uuid", tenant="t", accept="yes")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Backend sync complete", response.text)
        dns.assert_called_once_with(["192.0.2.2", "2001:db8::2"])
        with Session(self.engine) as db:
            config = db.scalar(select(BackendConfig))
            self.assertNotIn("backend-super-secret", config.encrypted_password)
            self.assertEqual(decrypt(config.encrypted_password), "backend-super-secret")
            vm = db.scalar(select(VM))
            self.assertEqual((vm.provider_uid, vm.provider_ref, vm.dns_name), ("vm-uuid", "vm-12", "app.test"))
            self.assertEqual(len(db.scalars(select(VMAddress)).all()), 2)

    def test_insufficient_privilege_blocks_sync_without_partial_import(self):
        self.connect()
        self.api(missing=True)
        with patch("web.backend_wizard.discover", return_value=self.report(missing=True)):
            response = self.post(action="sync", vm="vm-uuid", tenant="t", accept="yes")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Insufficient privileges", response.text)
        with Session(self.engine) as db:
            self.assertIsNone(db.scalar(select(RemoteSystem)))
            self.assertIsNone(db.scalar(select(VM)))

    def test_csrf_and_out_of_order_submission_denied(self):
        self.client.get("/admin/backends/setup", base_url="https://localhost")
        response = self.client.post("/admin/backends/setup", base_url="https://localhost", data={"action": "sync"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.post(action="sync").status_code, 400)

    def test_wrong_encryption_key_cannot_decrypt(self):
        value = encrypt("secret")
        with patch.dict(os.environ, {"CUSTOS_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            with self.assertRaises(SetupError):
                decrypt(value)

    def test_certificate_requires_explicit_acceptance(self):
        self.client.get("/admin/backends/setup", base_url="https://localhost")
        report = {"trusted": False, "pem": "test-certificate", "fingerprint": "abc123",
                  "subject": "CN=vc.test", "issuer": "Example CA", "expires": "2030-01-01"}
        with patch("web.backend_wizard.certificate_test", return_value=report):
            page = self.post(action="connect", name="VC", version="9.x", endpoint="https://vc.test")
        self.assertIn("abc123", page.text)
        self.assertEqual(self.post(action="trust").status_code, 400)
        with patch("web.backend_wizard.origin", return_value=SimpleNamespace(hostname="vc.test", port=443)), patch(
                "socket.create_connection"), patch("web.backend_wizard.tls_context") as context:
            page = self.post(action="trust", accept="yes")
        context.assert_called_once_with("test-certificate")
        self.assertIn("Connection verified", page.text)
        self.assertNotIn("test-certificate", page.text)

    def test_missing_encryption_key_blocks_api_test(self):
        self.connect()
        with patch.dict(os.environ):
            os.environ.pop("CUSTOS_ENCRYPTION_KEY", None)
            with patch("web.backend_wizard.discover") as api:
                response = self.post(action="api", username="svc", password="private-password")
                api.assert_not_called()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("private-password", response.text)

    def test_nutanix_onboarding_requires_privilege_attestation(self):
        self.client.get("/admin/backends/setup", base_url="https://localhost")
        with patch("web.backend_wizard.certificate_test", return_value={"trusted": True}):
            response = self.post(action="connect", name="PC", provider="nutanix", version="Nutanix AHV v4.0", endpoint="https://pc.test:9440")
        self.assertEqual(response.status_code, 200)
        report = self.report()
        report["vcenter_uid"] = "nutanix:pc-uuid"
        report["vms"][0]["capabilities"] = {"view": True, **{a: None for a in ["console", "start", "stop", "reboot", "reset", "snapshot"]}}
        with patch("web.backend_wizard.discover", return_value=report):
            response = self.post(action="api", username="svc", password="private-password")
            self.assertIn("unverified", response.text)
            self.assertEqual(self.post(action="sync", vm="vm-uuid", tenant="t", accept="yes").status_code, 400)
            with patch("web.backend_wizard.resolve_addresses", return_value={}):
                response = self.post(action="sync", vm="vm-uuid", tenant="t", accept="yes", privilege_ack="yes")
        self.assertEqual(response.status_code, 200)
        with Session(self.engine) as db:
            self.assertEqual(db.scalar(select(RemoteSystem)).provider, "nutanix")

    @patch("custos.backend_setup.Disconnect")
    @patch("custos.backend_setup.SmartConnect")
    @patch("custos.backend_setup.origin")
    def test_sdk_inventory_and_effective_privileges(self, origin, connect, disconnect):
        origin.return_value = SimpleNamespace(hostname="vc.test", port=443)
        content = connect.return_value.RetrieveContent.return_value
        content.about.version = "8.0.3"
        content.about.instanceUuid = "vc-uuid"
        content.sessionManager.currentSession.key = "session"
        vm = SimpleNamespace(config=SimpleNamespace(instanceUuid="uuid"), name="app", _moId="vm-1",
            runtime=SimpleNamespace(powerState="poweredOn"), guest=SimpleNamespace(
                toolsRunningStatus="guestToolsRunning", ipAddress="192.0.2.1", net=[SimpleNamespace(ipAddress=["192.0.2.1", "::1", "2001:db8::1"])]))
        view = content.viewManager.CreateContainerView.return_value
        view.view = [vm]
        content.authorizationManager.HasPrivilegeOnEntity.return_value = [True] * 7
        report = discover("https://vc.test", "svc", "secret", "8.0 U3")
        self.assertEqual(report["vms"][0]["ips"], ["192.0.2.1", "2001:db8::1"])
        self.assertTrue(report["vms"][0]["capabilities"]["reset"])
        view.Destroy.assert_called_once()
        disconnect.assert_called_once()
