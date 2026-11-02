from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch, Mock, AsyncMock
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from custos.backend_health import set_health
from custos.backend_setup import SetupError
from custos.console_gateway import claim, cleanup, close_session, heartbeat
from custos.database import (AuthSession, Base, ConsoleSession, Grant, Operation, RemoteSystem,
    BackendConfig, ResourceGroup, Tenant, TenantMember, VM, VMOperationLock)
from custos.local_identity import create_local_user
from web.app import create_app


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test", "DATABASE_URL": "sqlite://"})
        self.engine = self.app.extensions["custos_engine"]
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as db, db.begin():
            user = create_local_user(db, "user", "User", "long test password")
            self.actor = user.id
            db.add_all([Tenant(id="t", name="Tenant"), RemoteSystem(id="vc", name="VC", provider="vcenter",
                endpoint="https://vc.test", service_username="operator", credential_ref="ref")])
            db.flush()
            db.add_all([VM(id="vm", tenant_id="t", remote_system_id="vc", provider_uid="uuid", provider_ref="vm-1",
                          inventory_name="App", power_state="POWERED_ON"),
                BackendConfig(remote_system_id="vc", version="9.x", vcenter_uid="vc-uuid", encrypted_password="encrypted", scope={"vm_uids": ["uuid"]}),
                ResourceGroup(id="r", tenant_id="t", name="VMs", mode="dynamic", rule={"remote_system_id": "vc"}),
                AuthSession(id="login", principal_id=user.id, expires_at=datetime.now(timezone.utc)+timedelta(minutes=15))])
            db.flush()
            db.add(TenantMember(tenant_id="t", principal_id=user.id))
            for action in ["view", "console"]:
                db.add(Grant(tenant_id="t", principal_id=user.id, group_id="r", action=action))
            set_health(db, "vc", True)
        self.client = self.app.test_client()
        with self.client.session_transaction(base_url="https://localhost") as cookie:
            cookie["principal_id"], cookie["login_id"], cookie["csrf"] = self.actor, "login", "csrf"

    def issue(self):
        with patch("web.console.assets_ready", return_value=True):
            response = self.client.post("/vms/vm/console", base_url="https://localhost", data={"csrf": "csrf"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("encrypted", response.text)
        self.assertNotIn("vc.test", response.text)
        with Session(self.engine) as db:
            return db.scalar(select(ConsoleSession)).id

    def test_single_use_authorization_and_vm_lock_lifetime(self):
        identifier = self.issue()
        remote, config, vm, operation_id = claim(self.engine, identifier, self.actor, "login")
        self.assertEqual(remote.service_username, "operator")
        with self.assertRaises(SetupError):
            claim(self.engine, identifier, self.actor, "login")
        with Session(self.engine) as db:
            self.assertIsNotNone(db.get(VMOperationLock, "vm"))
        close_session(self.engine, identifier, "closed")
        with Session(self.engine) as db:
            self.assertIsNone(db.get(VMOperationLock, "vm"))
            self.assertEqual(db.get(Operation, operation_id).status, "console_closed")

    def test_logout_revokes_live_console(self):
        identifier = self.issue()
        claim(self.engine, identifier, self.actor, "login")
        self.assertTrue(heartbeat(self.engine, identifier))
        self.client.post("/logout", base_url="https://localhost", data={"csrf": "csrf"})
        self.assertFalse(heartbeat(self.engine, identifier))

    def test_wrong_actor_and_expired_console_denied(self):
        identifier = self.issue()
        with self.assertRaises(SetupError):
            claim(self.engine, identifier, "another-user", "login")
        with Session(self.engine) as db, db.begin():
            db.get(ConsoleSession, identifier).expires_at = datetime.now(timezone.utc)-timedelta(seconds=1)
        with self.assertRaises(SetupError):
            claim(self.engine, identifier, self.actor, "login")
        cleanup(self.engine)
        with Session(self.engine) as db:
            self.assertIsNone(db.get(VMOperationLock, "vm"))

    def test_console_blocks_other_console(self):
        self.issue()
        with patch("web.console.assets_ready", return_value=True):
            self.assertEqual(self.client.post("/vms/vm/console", base_url="https://localhost", data={"csrf": "csrf"}).status_code, 409)

    def test_asgi_broker_relays_frames_without_exposing_provider_url(self):
        try:
            from websockets.asyncio.client import connect
            from custos.console_gateway import create_gateway
        except ImportError:
            self.skipTest("Console optional runtime is not installed")
        import asyncio
        from types import SimpleNamespace
        with patch.dict("os.environ", {"CUSTOS_PUBLIC_ORIGIN": "https://localhost"}), patch("web.app.create_app", return_value=self.app):
            gateway = create_gateway()
        cookie = self.app.session_interface.get_signing_serializer(self.app).dumps({"principal_id": self.actor, "login_id": "login"})
        scope = {"type": "websocket", "asgi": {"version": "3.0"}, "scheme": "wss", "path": "/console/ws/opaque-id",
            "raw_path": b"/console/ws/opaque-id", "query_string": b"", "root_path": "", "subprotocols": [],
            "server": ("localhost",443), "client": ("192.0.2.1",1234), "headers": [
                (b"origin",b"https://localhost"), (b"cookie", ("session="+cookie).encode())]}
        upstream = Mock(subprotocol=None)
        async def frames():
            yield b"screen-frame"
        upstream.__aiter__ = lambda *args: frames()
        async def conversation():
            queue = asyncio.Queue()
            await queue.put({"type":"websocket.connect"})
            output = []
            async def emit(value):
                output.append(value)
            await asyncio.wait_for(gateway(scope, queue.get, emit), timeout=5)
            return output
        with patch("custos.console_gateway.claim", return_value=(SimpleNamespace(provider="vcenter"),
                SimpleNamespace(trusted_pem=None), SimpleNamespace(), "op")), patch(
                "custos.console_gateway.acquire", return_value={"url":"wss://provider.test/ticket/never-expose", "headers":{}}), patch(
                "custos.console_gateway.heartbeat", return_value=True), patch(
                "custos.console_gateway.close_session") as closed, patch.object(connect,"__aenter__", new=AsyncMock(return_value=upstream)), patch.object(
                connect,"__aexit__", new=AsyncMock(return_value=None)):
            output = asyncio.run(conversation())
        self.assertTrue(any(message.get("bytes") == b"screen-frame" for message in output))
        self.assertNotIn("never-expose", str(output))
        closed.assert_called_once()


class ClusterTests(unittest.TestCase):
    def test_cluster_mode_rejects_sqlite(self):
        from custos.clustering import require_cluster_database
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        with patch.dict("os.environ", {"CUSTOS_CLUSTER_MODE": "true"}):
            with self.assertRaisesRegex(ValueError, "PostgreSQL"):
                require_cluster_database(engine)

    def test_nonleader_does_not_run_jobs_or_recover_other_worker(self):
        from contextlib import contextmanager
        from custos.worker import run_once
        @contextmanager
        def follower(engine):
            yield False
        with patch("custos.clustering.worker_leader", follower), patch("custos.worker._run_once") as cycle:
            run_once(None)
            cycle.assert_not_called()
