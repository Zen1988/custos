"""Read current power state for only the VMs visible to the signing-in user."""
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from sqlalchemy import select
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from custos.audit import record
from custos.authorization import permitted
from custos.backend_setup import decrypt, origin, tls_context
from custos.database import BackendConfig, RemoteSystem, VM


def read_status(remote, config, records):
    if remote.provider == "nutanix":
        from custos.providers.nutanix import read_status as read_nutanix_status
        return read_nutanix_status(remote, config, records)
    result = {vm.id: "UNKNOWN" for vm in records}
    service = None
    try:
        if config is None:
            return result
        parsed = origin(remote.endpoint)
        service = SmartConnect(host=parsed.hostname, port=parsed.port or 443,
            user=remote.service_username, pwd=decrypt(config.encrypted_password),
            sslContext=tls_context(config.trusted_pem), httpConnectionTimeout=10)
        if service.RetrieveContent().about.instanceUuid != config.vcenter_uid:
            return result
        for stored in records:
            try:
                if stored.provider_uid not in config.scope["vm_uids"]:
                    continue
                vm = vim.VirtualMachine(stored.provider_ref, service._stub)
                if vm.config.instanceUuid != stored.provider_uid:
                    continue
                result[stored.id] = {"poweredOn": "POWERED_ON", "poweredOff": "POWERED_OFF",
                    "suspended": "SUSPENDED"}.get(str(vm.runtime.powerState), "UNKNOWN")
            except Exception:
                pass
    except Exception:
        pass  # Do not retain cached green status after a failed live check.
    finally:
        if service:
            try:
                Disconnect(service)
            except Exception:
                pass
    return result


def refresh_user_status(engine, actor_id):
    with Session(engine) as db:
        grouped = {}
        for vm in db.scalars(select(VM).where(VM.enabled.is_(True))):
            if permitted(db, actor_id, vm.id, "view", inventory_max_age=None):
                grouped.setdefault(vm.remote_system_id, []).append(vm)
        for remote_id, records in grouped.items():
            remote = db.get(RemoteSystem, remote_id)
            result = read_status(remote, db.get(BackendConfig, remote_id), records)
            for vm in records:
                vm.power_state = result.get(vm.id, "UNKNOWN")
                if vm.power_state != "UNKNOWN":
                    vm.observed_at = datetime.now(timezone.utc)
            unknown = sum(result.get(vm.id, "UNKNOWN") == "UNKNOWN" for vm in records)
            from custos.backend_health import set_health
            set_health(db, remote_id, unknown == 0)
            record(db, "vm.login_status", "partial" if unknown else "succeeded", actor_id=actor_id,
                   target=remote_id, detail=f"Checked {len(records)} authorized VMs; unavailable {unknown}")
        db.commit()
