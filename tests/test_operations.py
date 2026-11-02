from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.orm import Session

from custos.audit import record
from custos.database import (AdminRole, AuditEvent, BackendConfig, Base, Grant, Operation,
    RemoteSystem, ResourceGroup, SyncSchedule, Tenant, TenantMember, VM, VMOperationLock)
from custos.local_identity import create_local_user
from custos.worker import run_once, run_operation
from web.app import create_app


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE_URL": "sqlite://"})
        self.engine = self.app.extensions["custos_engine"]
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as db, db.begin():
            users = [create_local_user(db, n, n, "a long test password") for n in ["alice", "bob"]]
            self.alice, self.bob = [u.id for u in users]
            db.add_all([Tenant(id="t", name="Tenant"), RemoteSystem(id="vc", name="VC", endpoint="https://vc.test",
                service_username="shared-operator", credential_ref="encrypted-db:vc")])
            db.flush()
            db.add_all([BackendConfig(remote_system_id="vc", version="9.x", vcenter_uid="vc-uuid",
                encrypted_password="ciphertext", scope={"vm_uids": ["uuid"]}),
                VM(id="vm", tenant_id="t", remote_system_id="vc", provider_uid="uuid", provider_ref="vm-1",
                   inventory_name="App", observed_at=datetime.now(timezone.utc)),
                ResourceGroup(id="rg", tenant_id="t", name="VMs", mode="dynamic", rule={"remote_system_id": "vc"})])
            db.flush()
            for user in users:
                db.add(TenantMember(tenant_id="t", principal_id=user.id))
                for action in ["view", "start", "reset"]:
                    db.add(Grant(tenant_id="t", principal_id=user.id, group_id="rg", action=action))
        self.client = self.app.test_client()
        with Session(self.engine) as db, db.begin():
            from custos.backend_health import set_health
            set_health(db, "vc", True)
        self.sign_in(self.alice)

    def sign_in(self, actor):
        with self.client.session_transaction(base_url="https://localhost") as cookie:
            cookie["principal_id"], cookie["csrf"] = actor, "test-csrf"

    def submit(self, key="request-1234567890", action="start"):
        return self.client.post("/vms/vm/actions/" + action, base_url="https://localhost", data={
            "csrf": "test-csrf", "confirm": "yes", "idempotency_key": key})

    def op(self):
        with Session(self.engine) as db:
            return db.scalar(select(Operation)).id

    def test_cross_user_vm_lock_and_idempotency(self):
        self.assertEqual(self.submit().status_code, 302)
        self.assertEqual(self.submit().status_code, 302)  # Repeat does not queue twice.
        self.sign_in(self.bob)
        self.assertEqual(self.submit("another-request-123", "reset").status_code, 409)
        locks = self.client.get("/api/vm-locks", base_url="https://localhost").json
        self.assertTrue(locks["vm"]["locked"])
        page = self.client.get("/", base_url="https://localhost").text
        self.assertIn("disabled", page)
        with Session(self.engine) as db:
            self.assertEqual(len(db.scalars(select(Operation)).all()), 1)

    def test_worker_rechecks_revoked_grant(self):
        self.submit()
        operation_id = self.op()
        with Session(self.engine) as db, db.begin():
            grant = db.scalar(select(Grant).where(Grant.principal_id == self.alice, Grant.action == "start"))
            grant.enabled = False
        with patch("custos.worker.execute") as execute:
            run_operation(self.engine, operation_id)
            execute.assert_not_called()
        with Session(self.engine) as db:
            self.assertEqual(db.get(Operation, operation_id).status, "failed")
            self.assertIsNone(db.get(VMOperationLock, "vm"))

    def test_known_completion_releases_lock_and_saves_task(self):
        self.submit()
        operation_id = self.op()
        def execute(remote, config, vm, action, correlation, task_recorded):
            self.assertEqual(remote.service_username, "shared-operator")
            task_recorded("task-123")
            return "succeeded"
        with patch("custos.worker.execute", side_effect=execute):
            run_operation(self.engine, operation_id)
        with Session(self.engine) as db:
            self.assertIsNone(db.get(VMOperationLock, "vm"))
            op = db.get(Operation, operation_id)
            self.assertEqual((op.status, op.provider_task), ("succeeded", "task-123"))
            self.assertTrue(db.scalar(select(AuditEvent).where(AuditEvent.correlation_id == operation_id,
                                                             AuditEvent.outcome == "succeeded")))

    def test_unknown_lock_retained_until_provider_completion(self):
        self.submit()
        operation_id = self.op()
        with patch("custos.worker.execute", return_value="unknown"):
            run_operation(self.engine, operation_id)
        with Session(self.engine) as db:
            self.assertIsNotNone(db.get(VMOperationLock, "vm"))
        with patch("custos.worker.observe", return_value="succeeded"):
            run_once(self.engine)
        with Session(self.engine) as db:
            self.assertIsNone(db.get(VMOperationLock, "vm"))

    def test_activity_own_only_and_admin_all(self):
        with Session(self.engine) as db, db.begin():
            record(db, "alice-only", "ok", actor_id=self.alice)
            record(db, "bob-only", "ok", actor_id=self.bob)
        page = self.client.get("/activity", base_url="https://localhost").text
        self.assertIn("alice-only", page)
        self.assertNotIn("bob-only", page)
        with Session(self.engine) as db, db.begin():
            db.add(AdminRole(principal_id=self.alice))
        self.assertIn("bob-only", self.client.get("/activity", base_url="https://localhost").text)

    def test_due_sync_only_and_advance_schedule(self):
        with Session(self.engine) as db, db.begin():
            db.add(SyncSchedule(remote_system_id="vc", frequency="daily",
                                next_run_at=datetime.now(timezone.utc)-timedelta(minutes=1)))
        with patch("custos.worker.sync_backend") as sync:
            run_once(self.engine)
            run_once(self.engine)
        sync.assert_called_once_with(self.engine, "vc")

    def test_no_permission_no_operation(self):
        self.assertEqual(self.submit(action="snapshot").status_code, 403)
        with Session(self.engine) as db:
            self.assertIsNone(db.scalar(select(Operation)))

    def test_audit_is_append_only(self):
        with Session(self.engine) as db:
            record(db, "test", "ok")
            db.commit()
            row = db.scalar(select(AuditEvent))
            row.detail = "changed"
            with self.assertRaisesRegex(ValueError, "append-only"):
                db.commit()

    def test_admin_resource_group_preview_and_create(self):
        with Session(self.engine) as db, db.begin():
            db.add(AdminRole(principal_id=self.alice))
        data = {"csrf": "test-csrf", "name": "App group", "tenant": "t",
                "mode": "dynamic", "name_regex": "^App$", "action": "preview"}
        response = self.client.post("/admin/resource-groups", base_url="https://localhost", data=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Preview: 1 members", response.text)
        response = self.client.post("/admin/resource-groups", base_url="https://localhost", data={**data, "action": "create"})
        self.assertEqual(response.status_code, 200)
        with Session(self.engine) as db:
            group = db.scalar(select(ResourceGroup).where(ResourceGroup.name == "App group"))
            self.assertEqual(group.rule, {"name_regex": "^App$"})

    def test_group_admin_only_and_static_rejects_unknown_members(self):
        self.assertEqual(self.client.get("/admin/resource-groups", base_url="https://localhost").status_code, 403)
        with Session(self.engine) as db, db.begin():
            db.add(AdminRole(principal_id=self.alice))
        response = self.client.post("/admin/resource-groups", base_url="https://localhost", data={
            "csrf": "test-csrf", "name": "Static", "tenant": "t", "mode": "static", "vm": "not-in-tenant", "action": "create"})
        self.assertEqual(response.status_code, 400)

    def test_backend_failure_disables_every_action_and_displays_banner(self):
        from custos.backend_health import set_health
        with Session(self.engine) as db, db.begin():
            set_health(db, "vc", False)
        self.assertEqual(self.submit().status_code, 409)
        page = self.client.get("/", base_url="https://localhost").text
        self.assertIn("Affected VM actions are disabled", page)
        self.assertIn("Backend unavailable", page)
        locks = self.client.get("/api/vm-locks", base_url="https://localhost").json
        self.assertTrue(locks["vm"]["disabled"])

    def test_archive_removes_resources_and_restore_returns_original_access(self):
        import os
        from cryptography.fernet import Fernet
        from custos.backend_archive import archive, restore
        from custos.database import BackendArchive
        from custos.authorization import permitted
        with patch.dict(os.environ, {"CUSTOS_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            with Session(self.engine) as db, db.begin():
                identifier = archive(db, "vc", self.alice)
            with Session(self.engine) as db:
                self.assertIsNone(db.get(VM, "vm"))
                self.assertIsNone(db.get(RemoteSystem, "vc"))
                self.assertIsNotNone(db.get(BackendArchive, identifier))
                self.assertFalse(permitted(db, self.alice, "vm", "view", inventory_max_age=None))
            with patch("custos.backend_archive.decrypt", return_value="secret"), patch(
                    "custos.backend_archive.discover", return_value={"vcenter_uid": "vc-uuid", "vms": [{"uid": "uuid"}]}):
                with Session(self.engine) as db, db.begin():
                    restore(db, identifier, self.alice)
            with Session(self.engine) as db:
                self.assertEqual(db.get(VM, "vm").provider_uid, "uuid")
                self.assertTrue(permitted(db, self.alice, "vm", "view", inventory_max_age=None))
                self.assertIsNone(db.get(BackendArchive, identifier))

    def test_archive_rejects_locked_vm(self):
        from custos.backend_archive import archive
        from custos.backend_setup import SetupError
        self.submit()
        with Session(self.engine) as db, db.begin():
            with self.assertRaisesRegex(SetupError, "pending"):
                archive(db, "vc", self.alice)

    def test_admin_updates_api_account_through_portal_without_secret_leak(self):
        import os
        from cryptography.fernet import Fernet
        from custos.backend_setup import decrypt
        with Session(self.engine) as db, db.begin():
            db.add(AdminRole(principal_id=self.alice))
        report = {"vcenter_uid": "vc-uuid", "vms": [{"uid": "uuid", "capabilities": {"view": True, "reset": True}}]}
        with patch.dict(os.environ, {"CUSTOS_ENCRYPTION_KEY": Fernet.generate_key().decode()}), patch(
                "web.integrations.discover", return_value=report):
            response = self.client.post("/admin/integrations", base_url="https://localhost", data={
                "csrf": "test-csrf", "action": "update", "remote_id": "vc", "username": "new-operator",
                "password": "new-private-password", "endpoint": "https://new-vc.test"})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("new-private-password", response.text)
            with Session(self.engine) as db:
                self.assertEqual(db.get(RemoteSystem, "vc").service_username, "new-operator")
                self.assertEqual(db.get(RemoteSystem, "vc").endpoint, "https://new-vc.test")
                self.assertEqual(decrypt(db.get(BackendConfig, "vc").encrypted_password), "new-private-password")

    def queue_reboot(self):
        with Session(self.engine) as db, db.begin():
            db.add(Grant(tenant_id="t", principal_id=self.alice, group_id="rg", action="reboot"))
        self.assertEqual(self.submit(action="reboot").status_code, 302)
        return self.op()

    def test_requester_confirms_reboot_and_releases_shared_lock(self):
        operation_id = self.queue_reboot()
        with patch("custos.worker.execute", return_value="accepted"):
            run_operation(self.engine, operation_id)
        page = self.client.get("/activity", base_url="https://localhost").text
        self.assertIn("Confirm reboot completed and release lock", page)
        response = self.client.post(f"/operations/{operation_id}/confirm-reboot", base_url="https://localhost",
            data={"csrf": "test-csrf", "confirm": "yes"})
        self.assertEqual(response.status_code, 302)
        with Session(self.engine) as db:
            self.assertIsNone(db.get(VMOperationLock, "vm"))
            self.assertEqual(db.get(Operation, operation_id).status, "user_confirmed")
            event = db.scalar(select(AuditEvent).where(AuditEvent.event == "vm.reboot.confirm"))
            self.assertEqual(event.actor_id, self.alice)

    def test_other_user_cannot_confirm_reboot_and_early_release_blocked(self):
        operation_id = self.queue_reboot()
        endpoint = f"/operations/{operation_id}/confirm-reboot"
        self.assertEqual(self.client.post(endpoint, base_url="https://localhost", data={
            "csrf": "test-csrf", "confirm": "yes"}).status_code, 409)
        self.sign_in(self.bob)
        self.assertEqual(self.client.post(endpoint, base_url="https://localhost", data={
            "csrf": "test-csrf", "confirm": "yes"}).status_code, 403)
        self.assertNotIn("Your reboot confirmations", self.client.get("/activity", base_url="https://localhost").text)

    def test_green_or_provider_task_status_does_not_release_reboot_lock(self):
        operation_id = self.queue_reboot()
        with patch("custos.worker.execute", return_value="accepted"):
            run_operation(self.engine, operation_id)
        with Session(self.engine) as db, db.begin():
            db.get(Operation, operation_id).provider_task = "task-reboot"
            db.get(VM, "vm").power_state = "POWERED_ON"
        with patch("custos.worker.observe", return_value="succeeded") as observe:
            run_once(self.engine)
            observe.assert_not_called()
        with Session(self.engine) as db:
            self.assertIsNotNone(db.get(VMOperationLock, "vm"))

    def test_setup_guide_admin_only_and_renders_installation_steps(self):
        self.assertEqual(self.client.get("/admin/setup-guide", base_url="https://localhost").status_code, 403)
        with Session(self.engine) as db, db.begin():
            db.add(AdminRole(principal_id=self.alice))
        response = self.client.get("/admin/setup-guide", base_url="https://localhost")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Custos setup guide", response.text)
        self.assertIn('class="toc"', response.text)
        self.assertIn("sudo apt install", response.text)
        self.assertIn("custos-web.service", response.text)
        self.assertIn("Option B — Apache", response.text)
        self.assertIn("URL_ENCODED_PASSWORD", response.text)
