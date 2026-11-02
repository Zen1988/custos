from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from flask import Blueprint, abort, current_app, render_template, request, session, url_for
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from custos.audit import record
from custos.authorization import permitted
from custos.backend_health import available
from custos.database import AuthSession, ConsoleSession, Operation, RemoteSystem, VM, VMOperationLock

blueprint = Blueprint("console", __name__)


def assets_ready(provider):
    if not os.environ.get("CUSTOS_PUBLIC_ORIGIN") or not os.environ.get("CUSTOS_CONSOLE_ALLOWED_HOSTS"):
        return False
    if provider == "vcenter":
        root = Path(os.environ.get("CUSTOS_WEBMKS_ASSET_DIR", "web/static/vendor/webmks"))
        return all((root / name).is_file() for name in ["wmks.min.js", "jquery.min.js", "jquery-ui.min.js", "wmks-all.css"])
    root = Path(os.environ.get("CUSTOS_NOVNC_ASSET_DIR", "web/static/vendor/novnc"))
    return provider == "nutanix" and (root / "core/rfb.js").is_file()


@blueprint.get("/console-assets/<provider>/<path:filename>")
def asset(provider, filename):
    from flask import send_from_directory
    if provider not in {"vcenter", "nutanix"}:
        abort(404)
    directory = os.environ.get("CUSTOS_WEBMKS_ASSET_DIR", "web/static/vendor/webmks") if provider == "vcenter" else os.environ.get("CUSTOS_NOVNC_ASSET_DIR", "web/static/vendor/novnc")
    return send_from_directory(str(Path(directory).resolve()), filename)


@blueprint.post("/vms/<vm_id>/console")
def launch(vm_id):
    current_app.extensions["custos_csrf"]()
    actor = session.get("principal_id")
    try:
        with Session(current_app.extensions["custos_engine"]) as db, db.begin():
            if not permitted(db, actor, vm_id, "view", inventory_max_age=None) or not permitted(db, actor, vm_id, "console", inventory_max_age=None):
                abort(403)
            vm = db.get(VM, vm_id)
            remote = db.scalar(select(RemoteSystem).where(RemoteSystem.id == vm.remote_system_id).with_for_update())
            if not available(db, remote.id) or vm.power_state != "POWERED_ON":
                return "Console requires an available, powered-on VM.", 409
            if not assets_ready(remote.provider):
                return "Console is not configured. Contact your Custos administrator.", 503
            login_id = session.get("login_id")
            auth = db.get(AuthSession, login_id) if login_id else None
            if not auth or auth.revoked or auth.principal_id != actor:
                return "Sign in again before opening a console.", 401
            now = datetime.now(timezone.utc)
            op = Operation(actor_id=actor, vm_id=vm_id, action="console", status="console_issued", created_at=now,
                           idempotency_key="console-" + os.urandom(24).hex())
            db.add(op)
            db.flush()
            db.add(VMOperationLock(vm_id=vm_id, operation_id=op.id))
            console = ConsoleSession(actor_id=actor, vm_id=vm_id, operation_id=op.id, login_id=login_id,
                expires_at=now + timedelta(seconds=30), heartbeat_at=now)
            db.add(console)
            db.flush()
            record(db, "console.issue", "succeeded", actor_id=actor, target=vm_id, correlation_id=op.id)
            return render_template("console.html", console_id=console.id, provider=remote.provider,
                                   vm_name=vm.dns_name or vm.inventory_name)
    except IntegrityError:
        return "The VM already has an operation or console in progress.", 409
