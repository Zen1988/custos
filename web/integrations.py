from flask import Blueprint, abort, current_app, render_template, request, session
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from custos.audit import record
from custos.backend_archive import archive, restore
from custos.backend_health import set_health
from custos.backend_setup import SetupError, certificate_test, decrypt, discover, encrypt, origin, tls_context
from custos.database import BackendArchive, BackendConfig, BackendDraft, BackendHealth, RemoteSystem
from web.backend_wizard import is_admin

blueprint = Blueprint("integrations", __name__)


@blueprint.route("/admin/integrations", methods=["GET", "POST"])
def manage():
    error = None
    with Session(current_app.extensions["custos_engine"]) as db, db.begin():
        actor = session.get("principal_id")
        if not is_admin(db, actor):
            abort(403)
        if request.method == "POST":
            current_app.extensions["custos_csrf"]()
            try:
                action = request.form.get("action")
                if action == "restore":
                    restore(db, request.form.get("archive_id"), actor)
                else:
                    remote = db.scalar(select(RemoteSystem).where(RemoteSystem.id == request.form.get("remote_id")).with_for_update())
                    if not remote:
                        raise SetupError("Backend not found")
                    if action == "archive":
                        if request.form.get("confirm") != "yes":
                            raise SetupError("Confirm archiving the backend and VM inventory")
                        archive(db, remote.id, actor)
                    elif action in {"test", "update"}:
                        config = db.get(BackendConfig, remote.id)
                        if not config:
                            raise SetupError("Backend configuration missing")
                        username = request.form.get("username", "").strip() or remote.service_username
                        endpoint = request.form.get("endpoint", "").strip().rstrip("/") or remote.endpoint
                        ciphertext = encrypt(request.form["password"]) if request.form.get("password") else config.encrypted_password
                        report = discover(endpoint, username, decrypt(ciphertext), config.version, config.trusted_pem)
                        if report["vcenter_uid"] != config.vcenter_uid:
                            raise SetupError("Provider identity changed")
                        rows = [row for row in report["vms"] if row["uid"] in config.scope["vm_uids"]]
                        if {row["uid"] for row in rows} != set(config.scope["vm_uids"]):
                            raise SetupError("The account cannot see the full mapped VM scope")
                        if remote.provider == "vcenter" and any(not all(row["capabilities"].values()) for row in rows):
                            raise SetupError("Required vCenter operator privileges are missing")
                        if action == "update":
                            if remote.provider == "nutanix" and request.form.get("privilege_ack") != "yes":
                                raise SetupError("Confirm Nutanix role verification in Prism; action permissions cannot be preflight-verified")
                            remote.service_username, config.encrypted_password = username, ciphertext
                            remote.endpoint = endpoint
                        if action == "update" or (endpoint == remote.endpoint and username == remote.service_username and ciphertext == config.encrypted_password):
                            set_health(db, remote.id, True)
                        record(db, "backend." + action, "succeeded", actor_id=actor, target=remote.id,
                               detail="API account verified; encrypted credential updated" if action == "update" else "API connection verified")
                    elif action == "certificate":
                        endpoint = request.form.get("endpoint", "").strip().rstrip("/") or remote.endpoint
                        report = certificate_test(endpoint)
                        if report["trusted"]:
                            raise SetupError("The endpoint certificate is already trusted; use Test and save to update API access")
                        db.add(BackendDraft(admin_id=actor, created_at=datetime.now(timezone.utc), stage="integration-trust",
                            data={"remote_id": remote.id, "endpoint": endpoint, "certificate": report}))
                        record(db, "backend.certificate_inspect", "succeeded", actor_id=actor, target=remote.id)
                    elif action == "trust":
                        from custos.authorization import recent
                        candidate = db.get(BackendDraft, request.form.get("candidate_id"))
                        if not candidate or candidate.admin_id != actor or candidate.stage != "integration-trust" or candidate.data["remote_id"] != remote.id or not recent(candidate.created_at, datetime.now(timezone.utc), timedelta(minutes=30)) or request.form.get("confirm") != "yes":
                            raise SetupError("Certificate approval expired or was not explicitly confirmed")
                        import socket
                        parsed = origin(candidate.data["endpoint"])
                        pem = candidate.data["certificate"]["pem"]
                        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
                            with tls_context(pem).wrap_socket(sock, server_hostname=parsed.hostname):
                                pass
                        config = db.get(BackendConfig, remote.id)
                        config.trusted_pem, remote.endpoint = pem, candidate.data["endpoint"]
                        set_health(db, remote.id, False)
                        db.delete(candidate)
                        record(db, "backend.certificate_trust", "succeeded", actor_id=actor, target=remote.id,
                               detail="Backend-specific trust updated; API revalidation required before actions are enabled")
                    else:
                        raise SetupError("Unknown integration action")
            except SetupError as failure:
                error = str(failure)
                if request.form.get("action") == "test" and request.form.get("remote_id") and db.get(RemoteSystem, request.form["remote_id"]):
                    set_health(db, request.form["remote_id"], False)
                record(db, "backend.manage", "failed", actor_id=actor, detail=error)
            except (OSError, ValueError):
                error = "Connection or certificate validation failed; verify endpoint, hostname and validity"
                record(db, "backend.manage", "failed", actor_id=actor, detail=error)
        rows = [(remote, db.get(BackendHealth, remote.id)) for remote in db.scalars(select(RemoteSystem))]
        return render_template("integrations.html", integrations=rows,
            archives=db.scalars(select(BackendArchive)).all(), candidates=db.scalars(select(BackendDraft).where(
                BackendDraft.admin_id == actor, BackendDraft.stage == "integration-trust")).all(),
            error=error, csrf=session["csrf"]), 400 if error else 200
