import re
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from sqlalchemy.orm import Session

from custos.database import Base
from custos.local_identity import create_local_user
from web.app import create_app


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-only-secret",
                               "DATABASE_URL": "sqlite://"})
        self.engine = self.app.extensions["custos_engine"]
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as db, db.begin():
            user = create_local_user(db, "psm-account", "PSM account", "test account password")
            self.user_id = user.id
        self.client = self.app.test_client()

    def token(self):
        response = self.client.get("/login", base_url="https://localhost")
        return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)

    def test_psm_form_login_and_session_cookie(self):
        token = self.token()
        response = self.client.post("/login", base_url="https://localhost", data={
            "csrf": token, "username": "psm-account", "password": "test account password"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("Secure", response.headers["Set-Cookie"])
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertEqual(self.client.get("/", base_url="https://localhost").status_code, 200)
        with Session(self.engine) as db, db.begin():
            from custos.database import Principal
            db.get(Principal, self.user_id).enabled = False
        self.assertEqual(self.client.get("/", base_url="https://localhost").status_code, 302)

    def test_invalid_password_and_csrf(self):
        self.assertEqual(self.client.get("/", base_url="https://localhost").status_code, 302)
        self.assertEqual(self.client.post("/login", base_url="https://localhost", data={}).status_code, 400)
        response = self.client.post("/login", base_url="https://localhost", data={
            "csrf": self.token(), "username": "psm-account", "password": "wrong"})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid username or password", response.text)

    def test_workspace_filters_resources_and_revokes_access(self):
        from custos.database import Grant, RemoteSystem, ResourceGroup, Tenant, TenantMember, VM
        with Session(self.engine) as db, db.begin():
            db.add_all([Tenant(id="t", name="Tenant A"), Tenant(id="other", name="Hidden Tenant"),
                RemoteSystem(id="r", name="VC", endpoint="https://vc.test", service_username="svc", credential_ref="secret/vc")])
            db.flush()
            db.add_all([VM(id="visible", tenant_id="t", remote_system_id="r", provider_uid="1", provider_ref="vm-1",
                inventory_name="fallback", dns_name="authorized.example.test", primary_ip="192.0.2.1",
                observed_at=datetime.now(timezone.utc)),
                VM(id="hidden", tenant_id="other", remote_system_id="r", provider_uid="2", provider_ref="vm-2",
                inventory_name="secret-vm", observed_at=datetime.now(timezone.utc)),
                ResourceGroup(id="rg", tenant_id="t", name="All VC", mode="dynamic", rule={"remote_system_id": "r"})])
            db.flush()
            db.add_all([TenantMember(tenant_id="t", principal_id=self.user_id),
                Grant(id="view", tenant_id="t", principal_id=self.user_id, group_id="rg", action="view"),
                Grant(tenant_id="t", principal_id=self.user_id, group_id="rg", action="start")])
        self.client.post("/login", base_url="https://localhost", data={"csrf": self.token(),
            "username": "psm-account", "password": "test account password"})
        page = self.client.get("/", base_url="https://localhost").text
        self.assertIn("authorized.example.test", page)
        self.assertIn("start", page)
        self.assertNotIn("secret-vm", page)
        self.assertNotIn("Hidden Tenant", page)
        with Session(self.engine) as db, db.begin():
            db.get(Grant, "view").enabled = False
        self.assertIn("No resources assigned", self.client.get("/", base_url="https://localhost").text)

    def test_directory_login_redirect_and_password_not_retained(self):
        from custos.database import Directory, Principal
        with Session(self.engine) as db, db.begin():
            db.add(Directory(id="ad", name="AD", endpoint="ldaps://ad.test", base_dn="dc=test",
                             credential_ref="env:SECRET", last_success_at=datetime.now(timezone.utc)))
            db.flush()
            db.add(Principal(id="ad-user", directory_id="ad", external_id="guid", kind="user", display_name="AD User"))
        page = self.client.get("/login/directory/ad", base_url="https://localhost")
        token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        def authenticate(db, directory_id, username, password):
            self.assertEqual((directory_id, username, password), ("ad", "alice", "psm-injected-secret"))
            return db.get(Principal, "ad-user")
        with patch("web.app.authenticate_directory", side_effect=authenticate):
            response = self.client.post("/login/directory/ad", base_url="https://localhost", data={
                "csrf": token, "username": "alice", "password": "psm-injected-secret"})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("psm-injected-secret", response.headers["Set-Cookie"])
        page = self.client.get("/", base_url="https://localhost")
        self.assertEqual(page.status_code, 200)
        self.assertIn("No resources assigned", page.text)
        with Session(self.engine) as db, db.begin():
            db.get(Directory, "ad").enabled = False
        self.assertEqual(self.client.get("/", base_url="https://localhost").status_code, 302)

    def seed_status_vms(self):
        from custos.database import Grant, RemoteSystem, ResourceGroup, Tenant, TenantMember, VM
        with Session(self.engine) as db, db.begin():
            db.add_all([Tenant(id="t", name="T"), RemoteSystem(id="vc", name="VC", endpoint="https://vc.test",
                service_username="shared", credential_ref="encrypted-db:vc")])
            db.flush()
            for identity in ["visible", "hidden"]:
                db.add(VM(id=identity, tenant_id="t", remote_system_id="vc", provider_uid=identity,
                    provider_ref="vm-" + identity, inventory_name=identity,
                    dns_name=identity + ".example.test", power_state="POWERED_ON", tags={"access": identity}))
            db.add(ResourceGroup(id="rg", tenant_id="t", name="Visible", mode="dynamic", rule={"tags": {"access": "visible"}}))
            db.flush()
            db.add_all([TenantMember(tenant_id="t", principal_id=self.user_id),
                Grant(tenant_id="t", principal_id=self.user_id, group_id="rg", action="view")])

    def test_login_checks_only_authorized_vm_and_shows_red(self):
        self.seed_status_vms()
        def read(remote, config, records):
            self.assertEqual([vm.id for vm in records], ["visible"])
            return {"visible": "POWERED_OFF"}
        with patch("custos.login_status.read_status", side_effect=read) as backend:
            response = self.client.post("/login", base_url="https://localhost", data={"csrf": self.token(),
                "username": "psm-account", "password": "test account password"})
            self.assertEqual(response.status_code, 302)
            backend.assert_called_once()
        page = self.client.get("/", base_url="https://localhost").text
        self.assertIn("visible.example.test", page)
        self.assertIn('aria-label="Down"', page)
        self.assertNotIn('aria-label="Up"', page)
        self.assertNotIn("hidden.example.test", page)
        self.assertNotIn("Last refreshed", page)

    def test_failed_backend_check_does_not_show_cached_green(self):
        self.seed_status_vms()
        with patch("custos.login_status.read_status", return_value={"visible": "UNKNOWN"}):
            self.client.post("/login", base_url="https://localhost", data={"csrf": self.token(),
                "username": "psm-account", "password": "test account password"})
        page = self.client.get("/", base_url="https://localhost").text
        self.assertIn('aria-label="Status unavailable"', page)
        self.assertNotIn('aria-label="Up"', page)
