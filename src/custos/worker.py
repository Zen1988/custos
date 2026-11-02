"""Single worker process: durable VM queue and recurring scoped inventory refresh."""
import argparse
from datetime import datetime, timedelta, timezone
import os
import time

from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.orm import Session

from custos.audit import record
from custos.authorization import permitted
from custos.backend_setup import SetupError, decrypt, discover, resolve_addresses
from custos.database import BackendConfig, Operation, RemoteSystem, SyncSchedule, VM, VMAddress, VMOperationLock
from custos.vm_actions import execute, observe
from custos.backend_health import available, set_health

FREQUENCIES = {"manual": None, "5min": 300, "hourly": 3600, "daily": 86400, "weekly": 604800}


def run_operation(engine, operation_id):
    with Session(engine) as db, db.begin():
        claimed = db.execute(update(Operation).where(Operation.id == operation_id,
            Operation.status == "queued").values(status="executing")).rowcount
        if not claimed:
            return
        op = db.get(Operation, operation_id)
        record(db, "vm." + op.action, "executing", actor_id=op.actor_id,
               target=op.vm_id, correlation_id=op.id)
    status, provider_identity, failure_detail = "failed", "unavailable", ""
    with Session(engine, expire_on_commit=False) as db:
        op = db.get(Operation, operation_id)
        try:
            vm = db.get(VM, op.vm_id)
            remote = db.get(RemoteSystem, vm.remote_system_id)
            config = db.get(BackendConfig, remote.id)
            provider_identity = remote.service_username + " @ " + remote.name
            if not available(db, remote.id):
                raise SetupError("Backend unavailable; operation was not dispatched")
            if (not permitted(db, op.actor_id, vm.id, "view", inventory_max_age=None)
                or not permitted(db, op.actor_id, vm.id, op.action, inventory_max_age=None)
                or not config or vm.provider_uid not in config.scope["vm_uids"]):
                raise SetupError("Access revoked or VM outside registered scope")
            def task_recorded(task_id):
                with Session(engine) as task_db, task_db.begin():
                    task_db.get(Operation, operation_id).provider_task = task_id
            # End the read transaction before a separate task-record transaction.
            db.commit()
            status = execute(remote, config, vm, op.action, op.id, task_recorded)
        except SetupError as error:
            failure_detail = str(error)
            status = "failed"
        except Exception:
            failure_detail = "Unexpected interruption; inspect provider outcome before reconciliation"
            status = "unknown"
    with Session(engine) as db, db.begin():
        op = db.get(Operation, operation_id)
        op.status = status
        record(db, "vm." + op.action, status, actor_id=op.actor_id, target=op.vm_id,
               correlation_id=op.id, detail="Provider " + provider_identity + "; task " +
               (op.provider_task or "not returned") + ("; " + failure_detail if failure_detail else ""))
        # Ambiguous/guest-accepted actions retain the lock until an admin reconciles outcome.
        if status in {"succeeded", "failed"}:
            db.execute(delete(VMOperationLock).where(VMOperationLock.operation_id == op.id))


def sync_backend(engine, remote_id):
    try:
        with Session(engine) as db:
            remote, config = db.get(RemoteSystem, remote_id), db.get(BackendConfig, remote_id)
            report = discover(remote.endpoint, remote.service_username, decrypt(config.encrypted_password),
                              config.version, config.trusted_pem)
            if report["vcenter_uid"] != config.vcenter_uid:
                raise SetupError("Provider identity changed")
            rows = {r["uid"]: r for r in report["vms"] if r["uid"] in config.scope["vm_uids"]}
            ips = sorted({ip for row in rows.values() for ip in row["ips"]})
            if len(ips) > 1000:
                raise SetupError("IP limit exceeded")
            addresses = resolve_addresses(ips)
            now = datetime.now(timezone.utc)
            for vm in db.scalars(select(VM).where(VM.remote_system_id == remote_id)):
                row = rows.get(vm.provider_uid)
                vm.enabled = row is not None
                if not row:
                    continue
                vm.provider_ref, vm.inventory_name = row["ref"], row["name"]
                vm.power_state = {"poweredOn": "POWERED_ON", "poweredOff": "POWERED_OFF", "suspended": "SUSPENDED"}.get(row["state"], "UNKNOWN")
                vm.tools_status, vm.observed_at = row["tools"], now
                vm.primary_ip = next((ip for ip in row["ips"] if addresses.get(ip)), next(iter(row["ips"]), None))
                vm.dns_name, vm.dns_checked_at = addresses.get(vm.primary_ip), now
                db.execute(delete(VMAddress).where(VMAddress.vm_id == vm.id))
                for ip in row["ips"]:
                    db.add(VMAddress(vm_id=vm.id, ip=ip, dns_name=addresses.get(ip), checked_at=now))
            config.last_sync_at = now
            set_health(db, remote_id, True)
            db.get(SyncSchedule, remote_id).last_status = "succeeded"
            record(db, "backend.sync", "succeeded", target=remote_id, detail=f"Refreshed {len(rows)} scoped VMs")
            db.commit()
    except Exception:
        with Session(engine) as db, db.begin():
            schedule = db.get(SyncSchedule, remote_id)
            if not schedule:
                return
            schedule.last_status = "failed"
            set_health(db, remote_id, False)
            record(db, "backend.sync", "failed", target=remote_id,
                   detail="Check endpoint, certificate, secret key and provider permissions")


def _run_once(engine):
    now = datetime.now(timezone.utc)
    from custos.console_gateway import cleanup
    cleanup(engine)
    from custos.authorization import recent
    from custos.database import BackendHealth
    from custos.login_status import read_status
    with Session(engine) as db:
        for remote in db.scalars(select(RemoteSystem).join(BackendConfig).where(RemoteSystem.enabled.is_(True))):
            health = db.get(BackendHealth, remote.id)
            if health and recent(health.checked_at, now, timedelta(seconds=60)):
                continue
            vm = db.scalar(select(VM).where(VM.remote_system_id == remote.id, VM.enabled.is_(True)))
            healthy = bool(vm and read_status(remote, db.get(BackendConfig, remote.id), [vm]).get(vm.id, "UNKNOWN") != "UNKNOWN")
            previous = health.status if health else None
            set_health(db, remote.id, healthy)
            if previous != ("healthy" if healthy else "unavailable"):
                record(db, "backend.health", "healthy" if healthy else "unavailable", target=remote.id)
        db.commit()
    with Session(engine) as db:
        unresolved = list(db.scalars(select(Operation.id).where(Operation.status.in_(["unknown", "accepted"]))))
    for operation_id in unresolved:
        with Session(engine) as db:
            op = db.get(Operation, operation_id)
            vm = db.get(VM, op.vm_id)
            remote = db.get(RemoteSystem, vm.remote_system_id)
            config = db.get(BackendConfig, remote.id)
            if not remote.enabled or not config:
                continue
            if op.action == "reboot":
                continue
            status = observe(remote, config, vm, op)
            if status:
                op.status = status
                db.execute(delete(VMOperationLock).where(VMOperationLock.operation_id == op.id))
                record(db, "vm." + op.action, status, actor_id=op.actor_id, target=op.vm_id,
                       correlation_id=op.id, detail="Provider completion verified during reconciliation")
                db.commit()
    with Session(engine) as db:
        queued = list(db.scalars(select(Operation.id).where(Operation.status == "queued").order_by(Operation.created_at)))
    for operation_id in queued:
        run_operation(engine, operation_id)
    with Session(engine) as db:
        schedules = list(db.scalars(select(SyncSchedule).join(RemoteSystem).where(
            RemoteSystem.enabled.is_(True), SyncSchedule.next_run_at <= now,
            (SyncSchedule.frequency != "manual") | (SyncSchedule.last_status == "requested"))))
        due = [(s.remote_system_id, s.frequency, s.next_run_at) for s in schedules]
    for remote_id, frequency, expected in due:
        with Session(engine) as db, db.begin():
            claimed = db.execute(update(SyncSchedule).where(SyncSchedule.remote_system_id == remote_id,
                SyncSchedule.next_run_at == expected).values(next_run_at=now + timedelta(seconds=FREQUENCIES[frequency] or 86400),
                                                           last_status="running")).rowcount
            if claimed:
                record(db, "backend.sync", "started", target=remote_id)
        if claimed:
            sync_backend(engine, remote_id)
    from custos.syslog_forwarder import forward_pending
    forward_pending(engine)


def run_once(engine):
    from custos.clustering import worker_leader
    with worker_leader(engine) as leader:
        if not leader:
            return
        # Another live worker cannot own this cycle. Interrupted work is never replayed.
        with Session(engine) as db, db.begin():
            for op in db.scalars(select(Operation).where(Operation.status == "executing")):
                op.status = "unknown"
                record(db, "vm." + op.action, "unknown", actor_id=op.actor_id, target=op.vm_id,
                       correlation_id=op.id, detail="Previous worker lost leadership; reconcile provider outcome")
        _run_once(engine)


def main():
    parser = argparse.ArgumentParser(description="Custos single-process background worker")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    engine = create_engine(os.environ.get("CUSTOS_DATABASE_URL", "sqlite:///custos.db"))
    from custos.rbac import attach
    attach(engine)  # Worker has read-only RBAC credentials, never admin credentials.
    while True:
        run_once(engine)
        if args.once:
            break
        time.sleep(5)


if __name__ == "__main__":
    main()
