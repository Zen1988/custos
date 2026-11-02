from datetime import datetime, timezone
import tempfile
from pathlib import Path
import unittest

from cryptography.fernet import Fernet
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from custos.authorization import ACTIONS, permitted
from custos.database import (Base, Directory, GroupMember, Principal, RemoteSystem, ResourceGroup,
                             Tenant, VM)
from custos.rbac import RbacError, RoleBinding, attach, snapshot_group


class IsolatedRbacTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.engine = create_engine("sqlite:///" + str(base / "inventory.db"))
        Base.metadata.create_all(self.engine)
        url = "sqlite:///" + str(base / "rbac.db")
        self.key = Fernet.generate_key().decode()
        self.store = attach(self.engine, read_url=url, write_url=url, key=self.key)
        self.store.initialize()
        self.db = Session(self.engine)
        self.addCleanup(self.store.reader.dispose)
        self.addCleanup(self.store.writer.dispose)
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.db.close)
        self.db.add_all([Tenant(id="t", name="Tenant"), Tenant(id="other", name="Other"),
            Directory(id="d", name="AD", endpoint="ldaps://ad.test", base_dn="dc=test", credential_ref="env:PW",
                      last_success_at=datetime.now(timezone.utc)),
            RemoteSystem(id="vc", name="VC", endpoint="https://vc.test", service_username="shared", credential_ref="ref")])
        self.db.flush()
        self.db.add_all([Principal(id="u", directory_id="d", external_id="guid-user", kind="user", display_name="Alice"),
            Principal(id="g", directory_id="d", external_id="guid-group", kind="group", display_name="Team"),
            ResourceGroup(id="rg", tenant_id="t", name="Apps", mode="dynamic", rule={"name_regex": "^APP-"}),
            VM(id="vm", tenant_id="t", remote_system_id="vc", provider_uid="uuid", provider_ref="vm-1", inventory_name="APP-01"),
            VM(id="other-vm", tenant_id="other", remote_system_id="vc", provider_uid="uuid2", provider_ref="vm-2", inventory_name="APP-02")])
        self.db.flush()
        self.db.add(GroupMember(group_id="g", user_id="u"))
        self.db.commit()

    def allowed(self, action, vm="vm"):
        return permitted(self.db, "u", vm, action, inventory_max_age=None)

    def bind(self, role):
        return self.store.add("g", "group", role, snapshot_group(self.db, self.db.get(ResourceGroup, "rg")))

    def test_readonly_group_mapping_and_operator(self):
        binding = self.bind("readonly")
        self.assertTrue(self.allowed("view"))
        for action in ACTIONS - {"view"}:
            self.assertFalse(self.allowed(action))
        self.store.remove(binding)
        self.bind("operator")
        for action in ACTIONS:
            self.assertTrue(self.allowed(action))
        self.assertFalse(self.allowed("view", "other-vm"))

    def test_admin_group_sees_all_and_membership_revocation(self):
        self.store.add("g", "group", "admin")
        self.assertTrue(self.allowed("view", "other-vm"))
        self.assertTrue(self.allowed("reset", "other-vm"))
        self.db.delete(self.db.get(GroupMember, ("g", "u")))
        self.db.commit()
        self.assertFalse(self.allowed("view", "other-vm"))

    def test_wrong_key_denies_access_and_ciphertext_contains_no_role(self):
        self.bind("operator")
        with Session(self.store.reader) as db:
            raw = db.scalar(select(RoleBinding)).encrypted_policy
            self.assertNotIn("operator", raw)
            self.assertNotIn("subject_id", raw)
        self.store.cipher = Fernet(Fernet.generate_key())
        self.assertFalse(self.allowed("view"))

    def test_mapping_revocation_and_main_rule_tamper_cannot_broaden(self):
        self.db.get(VM, "vm").inventory_name = "DB-01"
        self.db.commit()
        binding = self.bind("operator")
        self.db.get(ResourceGroup, "rg").rule = {"name_regex": ".*"}
        self.db.commit()
        self.assertFalse(self.allowed("view"))
        self.db.get(VM, "vm").inventory_name = "APP-01"
        self.db.commit()
        self.assertTrue(self.allowed("view"))
        self.store.remove(binding)
        self.assertFalse(self.allowed("view"))

    def test_same_inventory_database_rejected(self):
        with self.assertRaises(RbacError):
            attach(self.engine, read_url=str(self.engine.url), key=self.key)

    def test_legacy_inventory_admin_does_not_override_isolated_rbac(self):
        from custos.database import AdminRole
        self.db.add(AdminRole(principal_id="u"))
        self.db.commit()
        self.assertFalse(self.allowed("view"))

    def test_web_assigns_group_role_to_isolated_store(self):
        from web.app import create_app
        self.store.add("u", "user", "admin")
        app = create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE_URL": str(self.engine.url),
            "RBAC_DATABASE_URL": str(self.store.reader.url), "RBAC_ADMIN_DATABASE_URL": str(self.store.writer.url),
            "RBAC_KEY": self.key})
        web_engine = app.extensions["custos_engine"]
        self.addCleanup(web_engine.dispose)
        self.addCleanup(web_engine.custos_rbac_store.reader.dispose)
        self.addCleanup(web_engine.custos_rbac_store.writer.dispose)
        client = app.test_client()
        with client.session_transaction(base_url="https://localhost") as cookie:
            cookie["principal_id"], cookie["csrf"] = "u", "csrf"
        response = client.post("/admin/role-mappings", base_url="https://localhost", data={
            "csrf": "csrf", "action": "assign", "subject": "g", "role": "readonly", "resource_group": "rg"})
        self.assertEqual(response.status_code, 200)
        binding = next(p for p in self.store.policies() if p["role"] == "readonly")
        self.assertEqual(binding["subject_id"], "g")
        response = client.post("/admin/role-mappings", base_url="https://localhost", data={
            "csrf": "csrf", "action": "remove", "binding_id": binding["id"]})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(any(p["role"] == "readonly" for p in self.store.policies()))

    def test_isolated_rbac_admin_sees_every_users_logs(self):
        from custos.audit import record
        from web.app import create_app
        self.store.add("g", "group", "admin")
        record(self.db, "other-user-private-event", "ok", actor_id="another-user", actor_name="Other User")
        self.db.commit()
        app = create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE_URL": str(self.engine.url),
            "RBAC_DATABASE_URL": str(self.store.reader.url), "RBAC_ADMIN_DATABASE_URL": str(self.store.writer.url), "RBAC_KEY": self.key})
        engine = app.extensions["custos_engine"]
        self.addCleanup(engine.dispose)
        self.addCleanup(engine.custos_rbac_store.reader.dispose)
        self.addCleanup(engine.custos_rbac_store.writer.dispose)
        client = app.test_client()
        with client.session_transaction(base_url="https://localhost") as cookie:
            cookie["principal_id"], cookie["csrf"] = "u", "token"
        page = client.get("/activity", base_url="https://localhost")
        self.assertEqual(page.status_code, 200)
        self.assertIn("other-user-private-event", page.text)
        self.assertIn("All users and system events", page.text)
