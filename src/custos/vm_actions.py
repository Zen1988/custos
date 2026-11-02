"""Allowlisted VM actions executed with the registered shared provider identity."""
import time
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from custos.backend_setup import PRIVILEGES, SetupError, decrypt, origin, tls_context

EXECUTABLE = frozenset({"start", "stop", "reboot", "reset", "snapshot"})


def observe(remote, config, vm_record, operation):
    """Read-only reconciliation. Never infer guest reboot completion from Tools alone."""
    if remote.provider == "nutanix":
        from custos.providers.nutanix import observe as observe_nutanix
        return observe_nutanix(remote, config, vm_record, operation)
    service = None
    try:
        parsed = origin(remote.endpoint)
        service = SmartConnect(host=parsed.hostname, port=parsed.port or 443,
            user=remote.service_username, pwd=decrypt(config.encrypted_password),
            sslContext=tls_context(config.trusted_pem), httpConnectionTimeout=20)
        content = service.RetrieveContent()
        vm = vim.VirtualMachine(vm_record.provider_ref, service._stub)
        if content.about.instanceUuid != config.vcenter_uid or vm.config.instanceUuid != vm_record.provider_uid:
            return None
        if operation.provider_task:
            task = vim.Task(operation.provider_task, service._stub)
            info = task.info
            if not info.entity or info.entity._moId != vm_record.provider_ref:
                return None
            return {"success": "succeeded", "error": "failed"}.get(str(info.state))
        if operation.action == "stop" and str(vm.runtime.powerState) == "poweredOff":
            return "succeeded"
        return None
    except Exception:
        return None
    finally:
        if service:
            try:
                Disconnect(service)
            except Exception:
                pass


def execute(remote, config, vm_record, action, operation_id, task_recorded):
    if remote.provider == "nutanix":
        from custos.providers.nutanix import execute as execute_nutanix
        return execute_nutanix(remote, config, vm_record, action, operation_id, task_recorded)
    if action not in EXECUTABLE:
        raise SetupError("Action is unavailable; console requires the isolated broker")
    parsed = origin(remote.endpoint)
    service = None
    submitted = False
    try:
        service = SmartConnect(host=parsed.hostname, port=parsed.port or 443,
            user=remote.service_username, pwd=decrypt(config.encrypted_password),
            sslContext=tls_context(config.trusted_pem), httpConnectionTimeout=20)
        content = service.RetrieveContent()
        if content.about.instanceUuid != config.vcenter_uid:
            raise SetupError("Provider identity changed")
        vm = vim.VirtualMachine(vm_record.provider_ref, service._stub)
        if vm.config.instanceUuid != vm_record.provider_uid or vm.config.template:
            raise SetupError("VM identity changed or target is a template")
        allowed = content.authorizationManager.HasPrivilegeOnEntity(vm,
            content.sessionManager.currentSession.key, [PRIVILEGES[action]])
        if allowed != [True]:
            raise SetupError("Provider permission was revoked")
        state = str(vm.runtime.powerState)
        if action == "start" and state != "poweredOff":
            raise SetupError("Start requires a powered-off VM")
        if action in {"stop", "reboot", "reset"} and state != "poweredOn":
            raise SetupError("This action requires a powered-on VM")
        if action in {"stop", "reboot"} and str(vm.guest.toolsRunningStatus) != "guestToolsRunning":
            raise SetupError("VMware Tools must be running for graceful shutdown/reboot")
        if action == "snapshot":
            def count(nodes):
                return sum(1 + count(n.childSnapshotList or []) for n in nodes)
            if vm.snapshot and count(vm.snapshot.rootSnapshotList or []) >= 3:
                raise SetupError("Snapshot limit reached (3); administrator cleanup is required")
        submitted = True  # Failures from here can have ambiguous provider outcomes.
        if action == "stop":
            vm.ShutdownGuest()
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if str(vm.runtime.powerState) == "poweredOff":
                    return "succeeded"
                time.sleep(1)
            return "unknown"
        if action == "reboot":
            vm.RebootGuest()
            return "accepted"
        if action == "start":
            task = vm.PowerOnVM_Task()
        elif action == "reset":
            task = vm.ResetVM_Task()
        else:
            task = vm.CreateSnapshot_Task(name="custos-" + operation_id,
                description="Requested through Custos; correlation " + operation_id, memory=False, quiesce=False)
        task_recorded(task._moId)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            task_state = str(task.info.state)
            if task_state == "success":
                return "succeeded"
            if task_state == "error":
                return "failed"
            time.sleep(1)
        return "unknown"
    except SetupError:
        raise
    except Exception:
        if submitted:
            return "unknown"
        raise SetupError("Provider connection or validation failed") from None
    finally:
        if service:
            try:
                Disconnect(service)
            except Exception:
                pass
