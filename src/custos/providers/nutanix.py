"""Prism Central AHV v4.0 adapter. No Prism Element/ESXi fallback."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import time
from urllib.parse import quote
from uuid import UUID

import requests
from requests.adapters import HTTPAdapter

from custos.backend_setup import SetupError, decrypt, origin, tls_context

VMS = "/api/vmm/v4.0/ahv/config/vms"
RECOVERY = "/api/dataprotection/v4.0/config/recovery-points"
TASKS = "/api/prism/v4.0/config/tasks/"
ACTIONS = {"start": "power-on", "stop": "guest-shutdown", "reboot": "guest-reboot", "reset": "reset"}


class ProviderDenied(SetupError):
    pass


class TLSAdapter(HTTPAdapter):
    def __init__(self, pem=None):
        self.context = tls_context(pem)
        super().__init__(max_retries=0)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.context
        return super().init_poolmanager(*args, **kwargs)


class Client:
    def __init__(self, endpoint, username, password, pem=None):
        origin(endpoint)
        self.endpoint = endpoint.rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = (username, password)
        self.session.mount("https://", TLSAdapter(pem))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def request(self, method, path, **kwargs):
        try:
            response = self.session.request(method, self.endpoint + path, timeout=(10, 20),
                                            allow_redirects=False, verify=True, **kwargs)
            if response.status_code in {401, 403}:
                raise ProviderDenied("Nutanix rejected the account or the required operation permission")
            if not 200 <= response.status_code < 300:
                raise SetupError(f"Nutanix API returned HTTP {response.status_code}")
            return response
        except requests.RequestException:
            raise SetupError("Nutanix API connection failed; verify TLS, endpoint and connectivity") from None

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs).json()

    def list(self, path, params=None):
        result, seen = [], set()
        for page in range(41):
            response = self.get(path, params={"$page": page, "$limit": 100, **(params or {})})
            rows = response.get("data")
            if not isinstance(rows, list):
                raise SetupError("Nutanix returned an invalid inventory page")
            for row in rows:
                identifier = row.get("extId")
                if not identifier or identifier in seen:
                    raise SetupError("Nutanix returned duplicate or missing resource identities")
                seen.add(identifier)
            result.extend(rows)
            if len(result) > 4000:
                raise SetupError("Nutanix inventory exceeds the 4000-resource limit")
            total = response.get("metadata", {}).get("totalAvailableResults")
            if not rows or (isinstance(total, int) and len(result) >= total):
                return result
        raise SetupError("Nutanix pagination did not complete")

    def identity(self):
        rows = self.get("/api/prism/v4.0/config/domain-managers").get("data", [])
        if not isinstance(rows, list) or len(rows) != 1 or not rows[0].get("extId"):
            raise SetupError("Cannot establish a unique Prism Central identity; grant domain-manager read access")
        return rows[0]["extId"]

    def vm(self, uid):
        return self.request("GET", VMS + "/" + str(UUID(uid)))

    def task_result(self, task_id, vm_uid):
        task = self.get(TASKS + quote(task_id, safe=""))["data"]
        # A task must refer to the intended VM; unrelated task IDs never release a lock.
        # task_id comes only from the authenticated mutation response and is persisted
        # against the operation; recovery tasks may list recovery points, not VM entities.
        return {"SUCCEEDED": "succeeded", "FAILED": "failed", "CANCELED": "failed"}.get(task.get("status"))


def normalized(vm):
    uid = str(UUID(vm["extId"]))
    addresses = set()
    for nic in vm.get("nics", []):
        network = nic.get("networkInfo", {})
        learned = network.get("ipv4Info", {}).get("learnedIpAddresses", [])
        config = network.get("ipv4Config", {})
        candidates = learned + config.get("secondaryIpAddressList", [])
        if config.get("ipAddress"):
            candidates.append(config["ipAddress"])
        for candidate in candidates:
            try:
                ip = ip_address(candidate["value"] if isinstance(candidate, dict) else candidate)
                if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast):
                    addresses.add(str(ip))
            except (ValueError, KeyError, TypeError):
                pass
    tools = vm.get("guestTools") or {}
    return {"uid": uid, "ref": uid, "name": vm["name"],
        "state": {"ON": "poweredOn", "OFF": "poweredOff", "PAUSED": "suspended"}.get(vm.get("powerState"), "unknown"),
        "ips": sorted(addresses), "tools": "NGT_READY" if tools.get("isReachable") else "UNKNOWN",
        "capabilities": {"view": True, **{a: None for a in ["console", "start", "stop", "reboot", "reset", "snapshot"]}}}


def discover(endpoint, username, password, version, pem=None):
    if version != "Nutanix AHV v4.0":
        raise SetupError("Select Nutanix AHV v4.0 for Prism Central")
    try:
        with Client(endpoint, username, password, pem) as client:
            identity = client.identity()
            rows = [normalized(vm) for vm in client.list(VMS)]
            return {"version": "Prism Central AHV API v4.0", "vcenter_uid": "nutanix:" + identity, "vms": rows}
    except SetupError:
        raise
    except (ValueError, KeyError, TypeError):
        raise SetupError("Unsupported or incomplete Nutanix v4.0 response") from None


def client_for(remote, config):
    return Client(remote.endpoint, remote.service_username, decrypt(config.encrypted_password), config.trusted_pem)


def verify_identity(client, config):
    if "nutanix:" + client.identity() != config.vcenter_uid:
        raise SetupError("Prism Central identity changed")


def read_status(remote, config, records):
    result = {vm.id: "UNKNOWN" for vm in records}
    try:
        with client_for(remote, config) as client:
            verify_identity(client, config)
            for record in records:
                if record.provider_uid not in config.scope["vm_uids"]:
                    continue
                row = client.vm(record.provider_uid).json()["data"]
                if row["extId"] == record.provider_uid:
                    result[record.id] = {"ON": "POWERED_ON", "OFF": "POWERED_OFF", "PAUSED": "SUSPENDED"}.get(row.get("powerState"), "UNKNOWN")
    except Exception:
        pass
    return result


def execute(remote, config, vm_record, action, operation_id, task_recorded):
    submitted = False
    try:
        with client_for(remote, config) as client:
            verify_identity(client, config)
            response = client.vm(vm_record.provider_uid)
            row = response.json()["data"]
            if row["extId"] != vm_record.provider_uid or vm_record.provider_ref != vm_record.provider_uid or row.get("isAgentVm"):
                raise SetupError("Nutanix VM identity changed or target is an infrastructure agent VM")
            if action not in set(ACTIONS) | {"snapshot"}:
                raise SetupError("Unsupported Nutanix action")
            if action == "start" and row.get("powerState") != "OFF":
                raise SetupError("Start requires a powered-off VM")
            if action in {"stop", "reboot", "reset"} and row.get("powerState") != "ON":
                raise SetupError("Action requires a powered-on VM")
            if action in {"stop", "reboot"} and not (row.get("guestTools") or {}).get("isReachable"):
                raise SetupError("Reachable Nutanix Guest Tools are required; no hard-action fallback is allowed")
            headers = {"Ntnx-Request-Id": operation_id}
            if action == "snapshot":
                points = [point for point in client.list(RECOVERY) if any(
                    vm.get("vmExtId") == vm_record.provider_uid for vm in point.get("vmRecoveryPoints", []))]
                if len(points) >= 3:
                    raise SetupError("Snapshot/recovery-point limit reached (3)")
                body = {"name": "custos-" + operation_id, "recoveryPointType": "CRASH_CONSISTENT",
                    "expirationTime": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
                    "vmRecoveryPoints": [{"vmExtId": vm_record.provider_uid}]}
                path = RECOVERY
            else:
                etag = response.headers.get("ETag")
                if not etag:
                    raise SetupError("Nutanix did not supply an ETag; action was not submitted")
                headers["If-Match"] = etag
                path = VMS + "/" + str(UUID(vm_record.provider_uid)) + "/$actions/" + ACTIONS[action]
                body = {} if action in {"stop", "reboot"} else None
            submitted = True
            response = client.request("POST", path, headers=headers, json=body)
            task_id = response.json().get("data", {}).get("extId")
            if not task_id:
                return "unknown"
            task_recorded(task_id)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                status = client.task_result(task_id, vm_record.provider_uid)
                if status:
                    if status == "succeeded" and action == "reboot":
                        return "accepted"  # NGT task acceptance is not guest completion evidence.
                    if status == "succeeded" and action == "stop" and client.vm(vm_record.provider_uid).json()["data"].get("powerState") != "OFF":
                        time.sleep(1)
                        continue
                    return status
                time.sleep(1)
            return "unknown"
    except ProviderDenied:
        raise
    except SetupError:
        if submitted:
            return "unknown"
        raise
    except Exception:
        if submitted:
            return "unknown"
        raise SetupError("Nutanix action validation failed") from None


def observe(remote, config, vm_record, operation):
    try:
        with client_for(remote, config) as client:
            verify_identity(client, config)
            if operation.action == "reboot":
                return None
            status = client.task_result(operation.provider_task, vm_record.provider_uid) if operation.provider_task else None
            if operation.action == "stop" and status != "failed":
                return "succeeded" if client.vm(vm_record.provider_uid).json()["data"].get("powerState") == "OFF" else None
            return status
    except Exception:
        return None
