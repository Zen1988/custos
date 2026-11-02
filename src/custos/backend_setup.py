"""vCenter onboarding primitives: encrypted secrets, explicit TLS trust and discovery."""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import os
import socket
import ssl
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
import dns.resolver
import dns.reversename
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


class SetupError(Exception):
    pass


def cipher():
    try:
        return Fernet(os.environ["CUSTOS_ENCRYPTION_KEY"].encode())
    except (KeyError, ValueError):
        raise SetupError("Configure a valid CUSTOS_ENCRYPTION_KEY outside the database before storing credentials") from None


def encrypt(password):
    if not password or len(password) > 1024:
        raise SetupError("A backend password is required (maximum 1024 characters)")
    return cipher().encrypt(password.encode()).decode()


def decrypt(value):
    try:
        return cipher().decrypt(value.encode()).decode()
    except InvalidToken:
        raise SetupError("The backend secret cannot be decrypted with the configured key") from None


def origin(endpoint):
    parsed = urlsplit(endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise SetupError("Enter an HTTPS origin, for example https://vcenter.example.com")
    if parsed.hostname.lower() in {"localhost", "metadata.google.internal"}:
        raise SetupError("A remote hypervisor endpoint is required")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    if any(ipaddress.ip_address(item[4][0]).is_loopback or
           ipaddress.ip_address(item[4][0]).is_link_local or
           ipaddress.ip_address(item[4][0]).is_unspecified or
           ipaddress.ip_address(item[4][0]).is_multicast for item in addresses):
        raise SetupError("Loopback, link-local and metadata endpoints are not allowed")
    return parsed


def tls_context(pem=None):
    context = ssl.create_default_context()
    if pem:
        context.load_verify_locations(cadata=pem)
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def certificate_test(endpoint):
    parsed = origin(endpoint)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
            with tls_context().wrap_socket(sock, server_hostname=parsed.hostname):
                return {"trusted": True}
    except ssl.SSLCertVerificationError:
        # Inspection only: never send credentials on this connection.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as secure:
                der = secure.getpeercert(binary_form=True)
        certificate = x509.load_der_x509_certificate(der)
        return {"trusted": False, "pem": ssl.DER_cert_to_PEM_cert(der),
                "fingerprint": hashlib.sha256(der).hexdigest(),
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "expires": certificate.not_valid_after_utc.isoformat()}


PRIVILEGES = {"view": "System.View", "console": "VirtualMachine.Interact.ConsoleInteract",
    "start": "VirtualMachine.Interact.PowerOn", "stop": "VirtualMachine.Interact.PowerOff",
    "reboot": "VirtualMachine.Interact.Reset", "reset": "VirtualMachine.Interact.Reset",
    "snapshot": "VirtualMachine.State.CreateSnapshot"}


def discover(endpoint, username, password, version, pem=None):
    if version == "Nutanix AHV v4.0":
        from custos.providers.nutanix import discover as discover_nutanix
        return discover_nutanix(endpoint, username, password, version, pem)
    parsed = origin(endpoint)
    service, view = None, None
    try:
        service = SmartConnect(host=parsed.hostname, port=parsed.port or 443, user=username,
            pwd=password, sslContext=tls_context(pem), httpConnectionTimeout=20)
        content = service.RetrieveContent()
        actual = content.about.version
        if not ((version == "8.0 U3" and actual.startswith("8.0.3")) or
                (version == "9.x" and actual.startswith("9."))):
            raise SetupError("Detected vCenter version does not match the selected version")
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        objects = list(view.view)
        if len(objects) > 4000:
            raise SetupError("Inventory exceeds the initial 4000 VM onboarding limit")
        rows = []
        session_id = content.sessionManager.currentSession.key
        for vm in objects:
            if vm.config is None or not vm.config.instanceUuid:
                raise SetupError("A visible VM has no readable instance UUID; check read privileges")
            required = sorted(set(PRIVILEGES.values()) | {"System.Read"})
            permissions = content.authorizationManager.HasPrivilegeOnEntity(vm, session_id, required)
            if len(permissions) != len(required):
                raise SetupError("vCenter returned an incomplete privilege report")
            effective = dict(zip(required, permissions))
            capabilities = {action: bool(effective[privilege]) for action, privilege in PRIVILEGES.items()}
            capabilities["view"] = capabilities["view"] and bool(effective["System.Read"])
            ips = set()
            addresses = [address for nic in vm.guest.net or [] for address in nic.ipAddress or []]
            if vm.guest.ipAddress:
                addresses.append(vm.guest.ipAddress)
            for address in addresses:
                try:
                    ip = ipaddress.ip_address(address)
                    if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast):
                        ips.add(str(ip))
                except ValueError:
                    pass
            rows.append({"uid": vm.config.instanceUuid, "ref": vm._moId, "name": vm.name,
                "state": str(vm.runtime.powerState), "tools": str(vm.guest.toolsRunningStatus or "UNKNOWN"),
                "ips": sorted(ips), "capabilities": capabilities})
        if len({r["uid"] for r in rows}) != len(rows):
            raise SetupError("Duplicate VM UUIDs were returned; resolve inventory identity conflicts")
        return {"version": actual, "vcenter_uid": content.about.instanceUuid, "vms": rows}
    except SetupError:
        raise
    except Exception:
        raise SetupError("vCenter API test failed; check certificate, credentials, connectivity and permissions") from None
    finally:
        if view is not None:
            try:
                view.Destroy()
            except Exception:
                pass
        if service is not None:
            try:
                Disconnect(service)
            except Exception:
                pass


def resolve_addresses(ips):
    def resolve(address):
        resolver = dns.resolver.Resolver()
        name = None
        try:
            ptr = resolver.resolve(dns.reversename.from_address(address), "PTR", lifetime=2)
            candidate = str(ptr[0]).rstrip(".")
            kind = "AAAA" if ipaddress.ip_address(address).version == 6 else "A"
            answers = resolver.resolve(candidate, kind, lifetime=2)
            if address in {str(ipaddress.ip_address(str(answer))) for answer in answers}:
                name = candidate
        except (dns.exception.DNSException, ValueError, OSError):
            pass
        return address, name
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(resolve, ips))
