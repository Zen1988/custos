from datetime import datetime, timedelta, timezone
import unittest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from custos.authorization import permitted
from custos.database import (Base, Directory, Grant, GroupMember, Principal, RemoteSystem,
                             ResourceGroup, ResourceGroupVM, Tenant, TenantMember, VM)


class AccessTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://")
        event.listen(engine, "connect", lambda c, _: c.execute("PRAGMA foreign_keys=ON"))
        Base.metadata.create_all(engine)
        self.db = Session(engine)
        self.addCleanup(engine.dispose)
        self.addCleanup(self.db.close)
        self.now = datetime.now(timezone.utc)
        self.db.add_all([Tenant(id="a", name="A"), Tenant(id="b", name="B"),
            Directory(id="d", name="AD", endpoint="ldaps://ad.test", base_dn="dc=test",
                      credential_ref="secret/ad", last_success_at=self.now),
            RemoteSystem(id="vc", name="VC", endpoint="https://vc.test",
                         service_username="custos", credential_ref="secret/vc")])
        self.db.flush()
        self.user = Principal(id="u", directory_id="d", external_id="guid-u", kind="user", display_name="User")
        self.vm = VM(id="vm", tenant_id="a", remote_system_id="vc", provider_uid="uuid-1",
                     provider_ref="vm-1", inventory_name="app", observed_at=self.now, tags={"env": "dev"})
        self.group = ResourceGroup(id="r", tenant_id="a", name="Dev", mode="dynamic", rule={"tags": {"env": "dev"}})
        self.db.add_all([self.user, self.vm, self.group])
        self.db.flush()
        self.db.add_all([TenantMember(tenant_id="a", principal_id="u"),
                         Grant(tenant_id="a", principal_id="u", group_id="r", action="view")])
        self.db.flush()

    def allowed(self, action="view"):
        return permitted(self.db, "u", "vm", action, now=self.now)

    def test_explicit_action_and_dynamic_match(self):
        self.assertTrue(self.allowed())
        for action in ["reset", "reboot", "delete", "start"]:
            self.assertFalse(self.allowed(action))
        self.vm.tags = {"env": "prod"}
        self.assertFalse(self.allowed())

    def test_static_group(self):
        self.group.mode = "static"
        self.assertFalse(self.allowed())
        self.db.add(ResourceGroupVM(group_id="r", vm_id="vm", tenant_id="a"))
        self.assertTrue(self.allowed())

    def test_stale_and_disabled(self):
        directory = self.db.get(Directory, "d")
        directory.last_success_at = self.now - timedelta(hours=1)
        self.assertFalse(self.allowed())
        directory.last_success_at = self.now
        self.vm.observed_at = self.now - timedelta(hours=1)
        self.assertFalse(self.allowed())
        self.vm.observed_at = self.now
        self.user.enabled = False
        self.assertFalse(self.allowed())

    def test_tenant_boundary(self):
        self.vm.tenant_id = "b"
        self.assertFalse(self.allowed())

    def test_group_grant_and_revocation(self):
        self.db.delete(self.db.get(TenantMember, ("a", "u")))
        self.db.add(Principal(id="g", directory_id="d", external_id="guid-g", kind="group", display_name="Team"))
        self.db.flush()
        member = GroupMember(group_id="g", user_id="u")
        self.db.add_all([member, TenantMember(tenant_id="a", principal_id="g"),
                         Grant(tenant_id="a", principal_id="g", group_id="r", action="reset")])
        self.assertTrue(self.allowed("reset"))
        self.db.delete(member)
        self.assertFalse(self.allowed("reset"))

    def test_unknown_rule_denied(self):
        self.group.rule = {"expression": "True"}
        self.assertFalse(self.allowed())

    def test_secondary_address_rule_is_used_by_authorization(self):
        from custos.database import VMAddress
        self.db.add(VMAddress(vm_id="vm", ip="10.20.30.9", checked_at=self.now))
        self.group.rule = {"subnet": "10.20.30.0/24"}
        self.assertTrue(self.allowed())
        self.vm.tenant_id = "b"
        self.assertFalse(self.allowed())

    def test_cross_tenant_membership_rejected(self):
        self.vm.tenant_id = "b"
        self.db.flush()
        self.db.add(ResourceGroupVM(group_id="r", vm_id="vm", tenant_id="a"))
        with self.assertRaises(IntegrityError):
            self.db.flush()
        self.db.rollback()
