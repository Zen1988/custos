from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from custos.audit import record
from custos.authorization import permitted
from custos.database import AuditEvent, BackendConfig, Operation, RemoteSystem, SyncSchedule, VM, VMOperationLock
from custos.vm_actions import EXECUTABLE
from custos.worker import FREQUENCIES
from web.backend_wizard import is_admin

blueprint = Blueprint("activity", __name__)


@blueprint.get("/api/vm-locks")
def vm_locks():
    actor = session.get("principal_id")
    if not actor:
        abort(401)
    result = {}
    with Session(current_app.extensions["custos_engine"]) as db:
        for vm in db.scalars(select(VM).where(VM.enabled.is_(True))):
            if not permitted(db, actor, vm.id, "view", inventory_max_age=None):
                continue
            lock = db.get(VMOperationLock, vm.id)
            operation = db.get(Operation, lock.operation_id) if lock else None
            from custos.backend_health import available
            backend_available = available(db, vm.remote_system_id)
            result[vm.id] = {"locked": bool(lock), "text":
                "Backend unavailable" if not backend_available else ((operation.action + " · " + operation.status) if operation else "Available"),
                "disabled": bool(lock) or not backend_available, "backend_unavailable": not backend_available}
    return jsonify(result)


@blueprint.post("/vms/<vm_id>/actions/<action>")
def submit(vm_id, action):
    current_app.extensions["custos_csrf"]()
    actor = session.get("principal_id")
    engine = current_app.extensions["custos_engine"]
    try:
        with Session(engine) as db, db.begin():
            if action not in EXECUTABLE or not permitted(db, actor, vm_id, "view", inventory_max_age=None) or not permitted(db, actor, vm_id, action, inventory_max_age=None):
                abort(403)
            if request.form.get("confirm") != "yes":
                abort(400)
            key = request.form.get("idempotency_key", "")
            if not 16 <= len(key) <= 100:
                abort(400)
            existing = db.scalar(select(Operation).where(Operation.idempotency_key == key))
            if existing:
                if (existing.actor_id, existing.vm_id, existing.action) != (actor, vm_id, action):
                    abort(409)
                return redirect(url_for("activity.history"))
            vm = db.get(VM, vm_id)
            db.scalar(select(RemoteSystem).where(RemoteSystem.id == vm.remote_system_id).with_for_update())
            from custos.backend_health import available
            if not available(db, vm.remote_system_id):
                return "Backend unavailable; VM actions are disabled.", 409
            config = db.get(BackendConfig, vm.remote_system_id)
            if not config or vm.provider_uid not in config.scope["vm_uids"]:
                abort(409)
            op = Operation(actor_id=actor, vm_id=vm_id, action=action,
                           created_at=datetime.now(timezone.utc), idempotency_key=key)
            db.add(op)
            db.flush()
            db.add(VMOperationLock(vm_id=vm_id, operation_id=op.id))
            db.flush()
            record(db, "vm." + action, "queued", actor_id=actor, target=vm_id,
                   correlation_id=op.id, source_ip=request.remote_addr)
    except IntegrityError:
        return "A VM operation is already pending; check Activity before retrying.", 409
    return redirect(url_for("activity.history"))


@blueprint.get("/activity")
def history():
    actor = session.get("principal_id")
    if not actor:
        return redirect(url_for("login"))
    with Session(current_app.extensions["custos_engine"]) as db:
        from custos.database import Directory, LocalCredential, Principal
        from custos.authorization import recent
        user = db.get(Principal, actor)
        if not user or not user.enabled or user.kind != "user":
            abort(403)
        if user.directory_id:
            directory = db.get(Directory, user.directory_id)
            if not directory or not directory.enabled or not recent(directory.last_success_at, datetime.now(timezone.utc), timedelta(minutes=15)):
                abort(403)
        elif not db.get(LocalCredential, actor):
            abort(403)
        admin = is_admin(db, actor)
        query = select(AuditEvent)
        if not admin:
            query = query.where(AuditEvent.actor_id == actor)
        event_filter = request.args.get("event", "")[:100]
        if event_filter:
            query = query.where(AuditEvent.event == event_filter)
        page = max(1, min(request.args.get("page", 1, type=int), 100000))
        events = db.scalars(query.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id).offset((page-1)*100).limit(100)).all()
        schedules = db.execute(select(SyncSchedule, RemoteSystem).join(RemoteSystem)).all() if admin else []
        unresolved = db.scalars(select(Operation).where(Operation.status.in_(["accepted", "unknown"]))).all() if admin else []
        reboot_confirmations = db.execute(select(Operation, VM).join(VM).where(Operation.actor_id == actor,
            Operation.action == "reboot", Operation.status.in_(["queued", "executing", "accepted", "unknown"]))).all()
        from sqlalchemy import func
        from custos.database import SyslogOutbox
        pending_syslog = db.scalar(select(func.count()).select_from(SyslogOutbox).where(SyslogOutbox.delivered_at.is_(None))) if admin else None
        return render_template("activity.html", events=events, page=page, event_filter=event_filter,
                               admin=admin, schedules=schedules, unresolved=unresolved, reboot_confirmations=reboot_confirmations,
                               pending_syslog=pending_syslog, csrf=session["csrf"])


@blueprint.post("/operations/<operation_id>/confirm-reboot")
def confirm_reboot(operation_id):
    current_app.extensions["custos_csrf"]()
    actor = session.get("principal_id")
    with Session(current_app.extensions["custos_engine"]) as db, db.begin():
        op = db.scalar(select(Operation).where(Operation.id == operation_id).with_for_update())
        if not op or op.actor_id != actor or op.action != "reboot":
            abort(403)
        if not permitted(db, actor, op.vm_id, "view", inventory_max_age=None):
            abort(403)
        if op.status not in {"accepted", "unknown"}:
            return "Wait until the reboot request finishes submitting before confirming completion.", 409
        if request.form.get("confirm") != "yes":
            abort(400)
        reason = request.form.get("reason", "").strip()
        if len(reason) > 300:
            abort(400)
        op.status = "user_confirmed"
        from sqlalchemy import delete
        db.execute(delete(VMOperationLock).where(VMOperationLock.operation_id == op.id))
        record(db, "vm.reboot.confirm", "user_confirmed", actor_id=actor, target=op.vm_id,
               correlation_id=op.id, detail="Requester verified reboot completion and released the lock" + (": " + reason if reason else ""))
    return redirect(url_for("activity.history"))


@blueprint.post("/admin/backends/<remote_id>/schedule")
def schedule(remote_id):
    current_app.extensions["custos_csrf"]()
    with Session(current_app.extensions["custos_engine"]) as db, db.begin():
        if not is_admin(db, session.get("principal_id")):
            abort(403)
        frequency = request.form.get("frequency")
        if frequency not in FREQUENCIES or not db.get(BackendConfig, remote_id):
            abort(400)
        row = db.get(SyncSchedule, remote_id)
        if row is None:
            row = SyncSchedule(remote_system_id=remote_id)
            db.add(row)
        row.frequency, row.next_run_at = frequency, datetime.now(timezone.utc) + timedelta(seconds=FREQUENCIES[frequency] or 0)
        record(db, "backend.schedule", "updated", actor_id=session["principal_id"], target=remote_id, detail=frequency)
    return redirect(url_for("activity.history"))


@blueprint.post("/admin/backends/<remote_id>/sync")
def sync_now(remote_id):
    current_app.extensions["custos_csrf"]()
    with Session(current_app.extensions["custos_engine"]) as db, db.begin():
        if not is_admin(db, session.get("principal_id")):
            abort(403)
        row = db.get(SyncSchedule, remote_id)
        if row is None or row.last_status == "running":
            abort(409)
        row.next_run_at, row.last_status = datetime.now(timezone.utc), "requested"
        record(db, "backend.sync", "requested", actor_id=session["principal_id"], target=remote_id)
    return redirect(url_for("activity.history"))


@blueprint.post("/admin/operations/<operation_id>/reconcile")
def reconcile(operation_id):
    current_app.extensions["custos_csrf"]()
    with Session(current_app.extensions["custos_engine"]) as db, db.begin():
        if not is_admin(db, session.get("principal_id")):
            abort(403)
        op = db.get(Operation, operation_id)
        reason = request.form.get("reason", "").strip()
        if not op or op.status not in {"accepted", "unknown"} or not 10 <= len(reason) <= 300 or request.form.get("confirm") != "yes":
            abort(400)
        op.status = "reconciled"
        from sqlalchemy import delete
        db.execute(delete(VMOperationLock).where(VMOperationLock.operation_id == op.id))
        record(db, "vm.reconcile", "reconciled", actor_id=session["principal_id"], target=op.vm_id,
               correlation_id=op.id, detail=reason)
    return redirect(url_for("activity.history"))
