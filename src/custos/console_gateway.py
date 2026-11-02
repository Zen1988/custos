"""Same-origin WebSocket broker: opaque Custos session in, provider ticket stays here."""
import asyncio
from datetime import datetime, timedelta, timezone
import os

from sqlalchemy import select, update, delete
from sqlalchemy.orm import Session
from custos.audit import record
from custos.authorization import permitted
from custos.backend_health import available
from custos.backend_setup import SetupError, tls_context
from custos.console_tickets import acquire
from custos.database import AuthSession, BackendConfig, ConsoleSession, Operation, RemoteSystem, VM, VMOperationLock


def future(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value > datetime.now(timezone.utc)


def authorized(db, console):
    auth = db.get(AuthSession, console.login_id)
    vm = db.get(VM, console.vm_id)
    lock = db.get(VMOperationLock, console.vm_id)
    return bool(auth and not auth.revoked and auth.principal_id == console.actor_id and future(auth.expires_at)
        and vm and lock and lock.operation_id == console.operation_id and available(db, vm.remote_system_id)
        and permitted(db, console.actor_id, vm.id, "view", inventory_max_age=None)
        and permitted(db, console.actor_id, vm.id, "console", inventory_max_age=None))


def claim(engine, identifier, actor_id, login_id):
    with Session(engine, expire_on_commit=False) as db, db.begin():
        console = db.get(ConsoleSession, identifier)
        if not console or console.actor_id != actor_id or console.login_id != login_id or not future(console.expires_at) or not authorized(db, console):
            raise SetupError("Console authorization denied or expired")
        now = datetime.now(timezone.utc)
        count = db.execute(update(ConsoleSession).where(ConsoleSession.id == identifier, ConsoleSession.state == "issued")
            .values(state="connected", expires_at=now + timedelta(minutes=10), heartbeat_at=now)).rowcount
        if not count:
            raise SetupError("Console authorization has already been consumed")
        op = db.get(Operation, console.operation_id)
        op.status = "console_active"
        vm = db.get(VM, console.vm_id)
        remote = db.get(RemoteSystem, vm.remote_system_id)
        config = db.get(BackendConfig, remote.id)
        if not config or vm.provider_uid not in config.scope["vm_uids"]:
            raise SetupError("Console VM is outside registered scope")
        record(db, "console.connect", "started", actor_id=actor_id, target=vm.id, correlation_id=op.id)
        return remote, config, vm, op.id


def close_session(engine, identifier, outcome):
    with Session(engine) as db, db.begin():
        console = db.get(ConsoleSession, identifier)
        if not console or console.state == "closed":
            return
        console.state = "closed"
        op = db.get(Operation, console.operation_id)
        op.status = "console_closed"
        db.execute(delete(VMOperationLock).where(VMOperationLock.operation_id == op.id))
        record(db, "console.close", outcome, actor_id=console.actor_id, target=console.vm_id, correlation_id=op.id)


def heartbeat(engine, identifier):
    with Session(engine) as db, db.begin():
        console = db.get(ConsoleSession, identifier)
        if not console or console.state != "connected" or not future(console.expires_at) or not authorized(db, console):
            return False
        console.heartbeat_at = datetime.now(timezone.utc)
        return True


def cleanup(engine):
    with Session(engine) as db:
        sessions = list(db.scalars(select(ConsoleSession).where(ConsoleSession.state != "closed")))
        identifiers = [row.id for row in sessions if not future(row.expires_at) or
            (row.state == "connected" and not future((row.heartbeat_at.replace(tzinfo=timezone.utc) if row.heartbeat_at.tzinfo is None else row.heartbeat_at) + timedelta(seconds=60)))]
    for identifier in identifiers:
        close_session(engine, identifier, "expired")


def create_gateway():
    from starlette.applications import Starlette
    from starlette.middleware.wsgi import WSGIMiddleware
    from starlette.routing import Mount, WebSocketRoute
    from websockets.asyncio.client import connect
    from web.app import create_app
    flask_app = create_app()
    engine = flask_app.extensions["custos_engine"]
    expected_origin = os.environ.get("CUSTOS_PUBLIC_ORIGIN", "").rstrip("/")
    if not expected_origin.startswith("https://"):
        raise ValueError("Configure CUSTOS_PUBLIC_ORIGIN as the public HTTPS origin")
    class DirectConnect(connect):
        def process_redirect(self, exc):
            return exc  # Never forward a ticket/cookie to a redirected destination.
    import logging
    transport_log = logging.getLogger("custos.console.transport")
    transport_log.disabled = True  # Protocol debug logs can contain tickets or typed credentials.

    async def console_socket(websocket):
        identifier = websocket.path_params["identifier"]
        claimed = False
        outcome = "closed"
        actor_id = None
        try:
            if websocket.headers.get("origin", "").rstrip("/") != expected_origin:
                raise SetupError("Invalid console origin")
            serializer = flask_app.session_interface.get_signing_serializer(flask_app)
            cookie = websocket.cookies.get(flask_app.config["SESSION_COOKIE_NAME"], "")
            identity = serializer.loads(cookie, max_age=900)
            actor_id = identity.get("principal_id")
            remote, config, vm, op_id = await asyncio.to_thread(claim, engine, identifier,
                identity.get("principal_id"), identity.get("login_id"))
            claimed = True
            ticket = await asyncio.to_thread(acquire, remote, config, vm, op_id)
            context = tls_context()
            if os.environ.get("CUSTOS_CONSOLE_CA_BUNDLE"):
                context.load_verify_locations(cafile=os.environ["CUSTOS_CONSOLE_CA_BUNDLE"])
            # Nutanix console shares the configured Prism endpoint's trust.
            if remote.provider == "nutanix" and config.trusted_pem:
                context = tls_context(config.trusted_pem)
            protocols = [value for value in websocket.scope.get("subprotocols", []) if value in {"binary", "base64"}]
            async with DirectConnect(ticket["url"], ssl=context, additional_headers=ticket["headers"],
                    proxy=None, logger=transport_log, subprotocols=protocols or None,
                    open_timeout=15, max_size=16*1024*1024, compression=None) as upstream:
                if not await asyncio.to_thread(heartbeat, engine, identifier):
                    raise SetupError("Console access expired during connection establishment")
                await websocket.accept(subprotocol=upstream.subprotocol)
                async def browser_to_provider():
                    while True:
                        message = await websocket.receive()
                        if message["type"] == "websocket.disconnect":
                            return
                        await upstream.send(message.get("bytes") if message.get("bytes") is not None else message["text"])
                async def provider_to_browser():
                    async for message in upstream:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)
                async def watch_access():
                    nonlocal outcome
                    while True:
                        await asyncio.sleep(5)
                        if not await asyncio.to_thread(heartbeat, engine, identifier):
                            outcome = "revoked_or_expired"
                            return
                tasks = [asyncio.create_task(function()) for function in [browser_to_provider, provider_to_browser, watch_access]]
                try:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    if any(not task.cancelled() and task.exception() for task in done):
                        outcome = "failed"
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            outcome = "failed"  # Never log provider URLs, tickets, cookies or handshake exceptions.
            if not claimed:
                with Session(engine) as db, db.begin():
                    record(db, "console.connect", "denied", target=identifier, actor_id=actor_id)
        finally:
            try:
                await websocket.close()
            except Exception:
                pass
            if claimed:
                await asyncio.to_thread(close_session, engine, identifier, outcome)

    return Starlette(routes=[WebSocketRoute("/console/ws/{identifier}", console_socket),
                             Mount("/", app=WSGIMiddleware(flask_app))])
