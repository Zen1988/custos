"""Provider console authorization material stays in broker memory, never browser JSON."""
import json
from urllib.parse import quote, urlsplit
import time
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

from custos.backend_setup import SetupError, decrypt, origin, tls_context


def allowed_host(url):
    import os
    parsed = urlsplit(url)
    allowed = {host.strip().lower() for host in os.environ.get("CUSTOS_CONSOLE_ALLOWED_HOSTS", "").split(",") if host.strip()}
    if parsed.scheme != "wss" or not parsed.hostname or parsed.hostname.lower() not in allowed or parsed.username or parsed.password or parsed.fragment:
        raise SetupError("Console destination is not in the server's management-host allowlist")
    origin("https://" + parsed.netloc)
    return url


def vmware_ticket(remote, config, stored):
    parsed = origin(remote.endpoint)
    service = None
    try:
        service = SmartConnect(host=parsed.hostname, port=parsed.port or 443, user=remote.service_username,
            pwd=decrypt(config.encrypted_password), sslContext=tls_context(config.trusted_pem), httpConnectionTimeout=20)
        content = service.RetrieveContent()
        if content.about.instanceUuid != config.vcenter_uid:
            raise SetupError("Provider identity changed")
        vm = vim.VirtualMachine(stored.provider_ref, service._stub)
        if vm.config.instanceUuid != stored.provider_uid or str(vm.runtime.powerState) != "poweredOn":
            raise SetupError("Console requires the mapped VM to be powered on")
        ticket = vm.AcquireTicket("webmks")
        if not ticket.host or not ticket.ticket:
            raise SetupError("vCenter returned incomplete console connection material")
        host = ticket.host
        if ":" in host and not host.startswith("["):
            host = "[" + host + "]"
        url = f"wss://{host}:{ticket.port or 443}/ticket/{quote(ticket.ticket, safe='')}"
        return {"url": allowed_host(url), "headers": {}, "protocol": "webmks"}
    except SetupError:
        raise
    except Exception:
        raise SetupError("VMware console ticket acquisition failed") from None
    finally:
        if service:
            try:
                Disconnect(service)
            except Exception:
                pass


def nutanix_ticket(remote, config, stored, request_id):
    from custos.providers.nutanix import client_for, verify_identity, VMS, TASKS
    with client_for(remote, config) as client:
        verify_identity(client, config)
        vm_response = client.vm(stored.provider_uid)
        vm = vm_response.json()["data"]
        if vm.get("extId") != stored.provider_uid or vm.get("powerState") != "ON":
            raise SetupError("Console requires the mapped VM to be powered on")
        # Capability-gated: 404 on older v4.0 endpoints is an explicit unsupported result.
        import os
        api_version = os.environ.get("CUSTOS_NUTANIX_CONSOLE_API_VERSION", "v4.2")
        if api_version not in {"v4.0", "v4.2"}:
            raise SetupError("Unsupported Nutanix console API version")
        console_path = VMS.replace("v4.0", api_version)
        response = client.request("POST", console_path + "/" + quote(stored.provider_uid, safe="") + "/$actions/generate-console-token",
                                  headers={"Ntnx-Request-Id": request_id})
        task = response.json()["data"]["extId"]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            data = client.get(TASKS + quote(task, safe=""))["data"]
            if data.get("status") == "SUCCEEDED":
                details = data.get("completionDetails") or {}
                # v4 completion details carry a serialized result. Require documented fields.
                if isinstance(details, str):
                    details = json.loads(details)
                if "WsUri" not in details or "VmConsoleToken" not in details:
                    raise SetupError("Unsupported Nutanix console completion schema; no token was exposed")
                path = details["WsUri"]
                expected = "/console/launch/" + stored.provider_uid
                if "/" + path.lstrip("/") != expected:
                    raise SetupError("Unexpected Nutanix console route")
                url = remote.endpoint.replace("https://", "wss://", 1).rstrip("/") + expected
                url += "?VmConsoleToken=" + quote(details["VmConsoleToken"], safe="")
                # Provider account remains server-side during the WebSocket handshake.
                import requests
                cookie = client.session.prepare_request(requests.Request("GET", url.replace("wss://", "https://", 1))).headers.get("Cookie")
                if not cookie:
                    raise SetupError("Prism did not issue a console authentication cookie; this deployment needs a supported session-authentication flow")
                return {"url": allowed_host(url), "headers": {"Cookie": cookie}, "protocol": "vnc"}
            if data.get("status") in {"FAILED", "CANCELED"}:
                raise SetupError("Nutanix console token request failed")
            time.sleep(1)
    raise SetupError("Nutanix console token request timed out")


def acquire(remote, config, vm, request_id):
    if remote.provider == "vcenter":
        return vmware_ticket(remote, config, vm)
    if remote.provider == "nutanix":
        return nutanix_ticket(remote, config, vm, request_id)
    raise SetupError("Unsupported console provider")
