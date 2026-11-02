"""Admin-only backend onboarding. Draft credentials are encrypted server-side."""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for
from sqlalchemy import select
from sqlalchemy.orm import Session

from custos.authorization import recent
from custos.backend_setup import (SetupError, certificate_test, decrypt, discover, encrypt,
                                  origin, resolve_addresses, tls_context)
from custos.database import (AdminRole, BackendConfig, BackendDraft, Directory, LocalCredential,
                             Principal, RemoteSystem, SyncSchedule, Tenant, VM, VMAddress)

blueprint = Blueprint("backend", __name__)


def is_admin(db, principal_id):
    user = db.get(Principal, principal_id) if principal_id else None
    from custos.rbac import administrator
    if not user or not user.enabled or user.kind != "user" or not administrator(db, user):
        return False
    if user.directory_id:
        directory = db.get(Directory, user.directory_id)
        return bool(directory and directory.enabled and recent(directory.last_success_at,
            datetime.now(timezone.utc), timedelta(minutes=15)))
    return db.get(LocalCredential, principal_id) is not None


@blueprint.route("/admin/backends/setup", methods=["GET", "POST"])
def setup():
    engine = current_app.extensions["custos_engine"]
    error, completed = None, False
    with Session(engine) as db, db.begin():
        admin_id = session.get("principal_id")
        if not is_admin(db, admin_id):
            abort(403)
        draft_id = session.get("backend_draft")
        draft = db.get(BackendDraft, draft_id) if draft_id else None
        if draft and (draft.admin_id != admin_id or not recent(draft.created_at,
                datetime.now(timezone.utc), timedelta(minutes=30))):
            db.delete(draft) if draft.admin_id == admin_id else None
            draft = None
        if draft is None:
            draft = BackendDraft(admin_id=admin_id, created_at=datetime.now(timezone.utc), stage="connection", data={})
            db.add(draft)
            db.flush()
            session["backend_draft"] = draft.id
        if request.method == "POST":
            current_app.extensions["custos_csrf"]()
            try:
                action = request.form.get("action")
                data = dict(draft.data)
                if action == "restart":
                    draft.data, draft.stage = {}, "connection"
                elif action == "connect" and draft.stage == "connection":
                    version = request.form.get("version")
                    provider = request.form.get("provider", "vcenter")
                    if (provider == "vcenter" and version not in {"8.0 U3", "9.x"}) or (provider == "nutanix" and version != "Nutanix AHV v4.0") or provider not in {"vcenter", "nutanix"}:
                        raise SetupError("Select the matching provider and supported API version")
                    endpoint = request.form.get("endpoint", "").strip().rstrip("/")
                    report = certificate_test(endpoint)
                    data = {"endpoint": endpoint, "version": version, "provider": provider,
                            "name": request.form.get("name", "").strip(), "certificate": report}
                    if not data["name"]:
                        raise SetupError("A backend name is required")
                    draft.data = data
                    draft.stage = "credentials" if report["trusted"] else "certificate"
                elif action == "trust" and draft.stage == "certificate":
                    if request.form.get("accept") != "yes":
                        raise SetupError("Explicitly accept the displayed certificate to continue")
                    # Reconnect using only this accepted certificate plus normal hostname/expiry checks.
                    import socket
                    parsed = origin(data["endpoint"])
                    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
                        with tls_context(data["certificate"]["pem"]).wrap_socket(sock, server_hostname=parsed.hostname):
                            pass
                    draft.stage = "credentials"
                elif action == "api" and draft.stage == "credentials":
                    username = request.form.get("username", "").strip()
                    if not username:
                        raise SetupError("A service account username is required")
                    encrypted = encrypt(request.form.get("password", ""))
                    report = discover(data["endpoint"], username, decrypt(encrypted), data["version"],
                                      data["certificate"].get("pem"))
                    if not report["vms"]:
                        raise SetupError("No VMs are visible; check service account read scope")
                    data.update(username=username, secret=encrypted, report=report)
                    draft.data, draft.stage = data, "scope"
                elif action == "credentials" and draft.stage == "scope":
                    data.pop("secret", None)
                    data.pop("report", None)
                    draft.data, draft.stage = data, "credentials"
                elif action == "sync" and draft.stage == "scope":
                    from custos.worker import FREQUENCIES
                    frequency = request.form.get("frequency", "hourly")
                    if frequency not in FREQUENCIES:
                        raise SetupError("Select a supported sync schedule")
                    selected = set(request.form.getlist("vm"))
                    tenant_id = request.form.get("tenant")
                    if not selected or len(selected) > 200:
                        raise SetupError("Select between 1 and 200 VMs for this initial sync")
                    tenant = db.get(Tenant, tenant_id) if tenant_id else None
                    if tenant is None:
                        raise SetupError("Select an existing tenant or create one below")
                    if request.form.get("accept") != "yes":
                        raise SetupError("Accept the capability report and encrypted credential storage")
                    report = discover(data["endpoint"], data["username"], decrypt(data["secret"]),
                                      data["version"], data["certificate"].get("pem"))
                    if report["vcenter_uid"] != data["report"]["vcenter_uid"]:
                        raise SetupError("vCenter identity changed; restart onboarding")
                    rows = [row for row in report["vms"] if row["uid"] in selected]
                    if len(rows) != len(selected):
                        raise SetupError("Selected VMs changed or became inaccessible; test API again")
                    if data.get("provider") == "nutanix":
                        if request.form.get("privilege_ack") != "yes":
                            raise SetupError("Nutanix action privileges are unverified. Confirm the Prism account role and scope before accepting")
                        if not all(row["capabilities"]["view"] for row in rows):
                            raise SetupError("Nutanix inventory read privilege is missing")
                    elif any(set(row["capabilities"]) != {"view", "console", "start", "stop", "reboot", "reset", "snapshot"}
                           or not all(row["capabilities"].values()) for row in rows):
                        raise SetupError("Insufficient privileges on selected VMs. Grant the missing privileges shown in the report")
                    remote = RemoteSystem(name=data["name"], provider=data.get("provider", "vcenter"), endpoint=data["endpoint"],
                                          service_username=data["username"], credential_ref="pending", enabled=True)
                    # A vCenter instance is registered once to prevent accidental duplicate mappings.
                    if db.scalar(select(BackendConfig).where(BackendConfig.vcenter_uid == report["vcenter_uid"])):
                        raise SetupError("This vCenter is already configured")
                    ips = sorted({ip for row in rows for ip in row["ips"]})
                    if len(ips) > 1000:
                        raise SetupError("Select a smaller scope: initial sync supports at most 1000 IP addresses")
                    addresses = resolve_addresses(ips)
                    now = datetime.now(timezone.utc)
                    db.add(remote)
                    db.flush()
                    from custos.backend_health import set_health
                    set_health(db, remote.id, True)
                    if remote.provider == "nutanix":
                        from custos.audit import record
                        record(db, "nutanix.privilege_ack", "accepted", actor_id=admin_id, target=remote.id,
                               detail="Admin attested Prism role/scope; inventory read verified, action privileges unverified")
                    remote.credential_ref = "encrypted-db:" + remote.id
                    db.add(SyncSchedule(remote_system_id=remote.id, frequency=frequency,
                        next_run_at=now + timedelta(seconds=FREQUENCIES[frequency] or 0), last_status="succeeded"))
                    db.add(BackendConfig(remote_system_id=remote.id, version=data["version"], vcenter_uid=report["vcenter_uid"],
                        encrypted_password=data["secret"], trusted_pem=data["certificate"].get("pem"),
                        scope={"vm_uids": sorted(selected), "vcenter_uid": report["vcenter_uid"]}, last_sync_at=now))
                    for row in rows:
                        primary = next((ip for ip in row["ips"] if addresses.get(ip)), next(iter(row["ips"]), None))
                        vm = VM(tenant_id=tenant.id, remote_system_id=remote.id, provider_uid=row["uid"],
                            provider_ref=row["ref"], inventory_name=row["name"], primary_ip=primary,
                            dns_name=addresses.get(primary), dns_checked_at=now,
                            power_state={"poweredOn": "POWERED_ON", "poweredOff": "POWERED_OFF", "suspended": "SUSPENDED"}.get(row["state"], "UNKNOWN"),
                            tools_status=row["tools"], observed_at=now, tags={})
                        db.add(vm)
                        db.flush()
                        for ip in row["ips"]:
                            db.add(VMAddress(vm_id=vm.id, ip=ip, dns_name=addresses.get(ip), checked_at=now))
                    db.delete(draft)
                    session.pop("backend_draft", None)
                    completed = True
                elif action == "tenant" and draft.stage == "scope":
                    name = request.form.get("tenant_name", "").strip()
                    if not name or len(name) > 200:
                        raise SetupError("Enter a tenant name of 1 to 200 characters")
                    db.add(Tenant(name=name))
                    db.flush()
                else:
                    raise SetupError("This wizard step is no longer current; reload the page")
            except SetupError as failure:
                error = str(failure)
            except (OSError, ValueError):
                error = "Connection or certificate verification failed. Check hostname, expiry, trust and network connectivity"
        if completed:
            return render_template("backend_complete.html")
        return render_template("backend_setup.html", draft=draft, error=error,
            tenants=db.scalars(select(Tenant)).all(), csrf=session["csrf"]), 400 if error else 200
