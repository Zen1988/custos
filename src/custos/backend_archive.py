"""Transactional archive/restore preserving UUIDs and immutable audit references."""
from datetime import datetime, timezone
import json
from sqlalchemy import DateTime, delete, inspect, select

from custos.audit import record
from custos.backend_health import set_health
from custos.backend_setup import SetupError, cipher, decrypt, discover
from custos.database import (BackendArchive, BackendConfig, BackendHealth, ConsoleSession, Operation,
    RemoteSystem, ResourceGroupVM, SyncSchedule, VM, VMAddress, VMOperationLock)

MODELS = {model.__tablename__: model for model in [RemoteSystem, BackendConfig, SyncSchedule, VM, VMAddress, ResourceGroupVM, Operation, ConsoleSession]}


def serialize(row):
    return {column.key: (getattr(row, column.key).isoformat() if isinstance(getattr(row, column.key), datetime)
                        else getattr(row, column.key)) for column in inspect(type(row)).columns}


def archive(db, remote_id, actor_id):
    remote = db.scalar(select(RemoteSystem).where(RemoteSystem.id == remote_id).with_for_update())
    if not remote:
        raise SetupError("Backend does not exist")
    vms = db.scalars(select(VM).where(VM.remote_system_id == remote_id)).all()
    ids = [vm.id for vm in vms]
    if db.scalar(select(VMOperationLock).where(VMOperationLock.vm_id.in_(ids))) or db.scalar(
            select(Operation).where(Operation.vm_id.in_(ids), Operation.status.in_(["queued", "executing", "accepted", "unknown"]))):
        raise SetupError("Backend has pending or unresolved VM operations; reconcile them before archiving")
    schedule = db.get(SyncSchedule, remote_id)
    if schedule and schedule.last_status == "running":
        raise SetupError("Inventory sync is running; wait for it to complete")
    rows = {"remote_systems": [remote], "backend_configs": [db.get(BackendConfig, remote_id)],
            "sync_schedules": [schedule], "vms": vms,
            "vm_addresses": db.scalars(select(VMAddress).where(VMAddress.vm_id.in_(ids))).all(),
            "resource_group_vms": db.scalars(select(ResourceGroupVM).where(ResourceGroupVM.vm_id.in_(ids))).all(),
            "operations": db.scalars(select(Operation).where(Operation.vm_id.in_(ids))).all(),
            "console_sessions": db.scalars(select(ConsoleSession).where(ConsoleSession.vm_id.in_(ids))).all()}
    payload = {name: [serialize(row) for row in values if row is not None] for name, values in rows.items()}
    saved = BackendArchive(name=remote.name, provider=remote.provider, archived_at=datetime.now(timezone.utc),
                           encrypted_payload=cipher().encrypt(json.dumps(payload).encode()).decode())
    db.add(saved)
    db.flush()
    for model in [ConsoleSession, VMAddress, ResourceGroupVM, Operation]:
        db.execute(delete(model).where(model.vm_id.in_(ids)))
    db.execute(delete(VM).where(VM.remote_system_id == remote_id))
    for model in [BackendHealth, SyncSchedule, BackendConfig]:
        db.execute(delete(model).where(model.remote_system_id == remote_id))
    db.delete(remote)
    record(db, "backend.archive", "succeeded", actor_id=actor_id, target=saved.id,
           detail=f"Archived {len(vms)} VMs; active mappings unavailable")
    return saved.id


def restore(db, archive_id, actor_id):
    saved = db.scalar(select(BackendArchive).where(BackendArchive.id == archive_id).with_for_update())
    if not saved:
        raise SetupError("Archive does not exist")
    try:
        payload = json.loads(cipher().decrypt(saved.encrypted_payload.encode()))
        remote, config = payload["remote_systems"][0], payload["backend_configs"][0]
    except Exception:
        raise SetupError("Archive cannot be decrypted or is incomplete") from None
    report = discover(remote["endpoint"], remote["service_username"], decrypt(config["encrypted_password"]),
                      config["version"], config["trusted_pem"])
    if report["vcenter_uid"] != config["vcenter_uid"]:
        raise SetupError("Provider identity does not match the archived backend")
    visible = {row["uid"] for row in report["vms"]}
    if not set(config["scope"]["vm_uids"]) <= visible:
        raise SetupError("Archived VM scope is not fully visible; restore was not applied")
    for name, model in MODELS.items():
        for values in payload.get(name, []):
            values = dict(values)
            for column in inspect(model).columns:
                if isinstance(column.type, DateTime) and values.get(column.key):
                    values[column.key] = datetime.fromisoformat(values[column.key])
            db.add(model(**values))
        db.flush()
    live = {row["uid"]: row for row in report["vms"]}
    for vm in db.scalars(select(VM).where(VM.remote_system_id == remote["id"])):
        row = live[vm.provider_uid]
        vm.provider_ref = row.get("ref", vm.provider_ref)
        vm.inventory_name = row.get("name", vm.inventory_name)
        vm.power_state = {"poweredOn": "POWERED_ON", "poweredOff": "POWERED_OFF", "suspended": "SUSPENDED"}.get(row.get("state"), "UNKNOWN")
        vm.observed_at = datetime.now(timezone.utc)
    schedule = db.get(SyncSchedule, remote["id"])
    if schedule:
        schedule.next_run_at, schedule.last_status = datetime.now(timezone.utc), "requested"
    set_health(db, remote["id"], True)
    db.delete(saved)
    record(db, "backend.restore", "succeeded", actor_id=actor_id, target=remote["id"],
           detail="Provider identity and VM scope revalidated; original resource IDs and mappings restored")
