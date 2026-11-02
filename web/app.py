"""Local/directory credential login and a permission-filtered VM workspace."""
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from custos.database import AuthSession, Directory, LocalCredential, Operation, Principal, RemoteSystem, Tenant, VM, VMOperationLock
from custos.authorization import ACTIONS, permitted, recent
from custos.directory_auth import authenticate_directory
from custos.local_identity import authenticate_local
from custos.login_status import refresh_user_status


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get("CUSTOS_SESSION_SECRET"),
        DATABASE_URL=os.environ.get("CUSTOS_DATABASE_URL", "sqlite:///custos.db"),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=True,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15), MAX_CONTENT_LENGTH=16384)
    if config:
        app.config.update(config)
    if not app.config["SECRET_KEY"]:
        raise ValueError("Set CUSTOS_SESSION_SECRET to a persistent random secret")
    engine = create_engine(app.config["DATABASE_URL"])
    from custos.clustering import require_cluster_database
    require_cluster_database(engine)
    if not app.config.get("TESTING") or app.config.get("RBAC_DATABASE_URL"):
        from custos.rbac import attach
        attach(engine, read_url=app.config.get("RBAC_DATABASE_URL"),
               write_url=app.config.get("RBAC_ADMIN_DATABASE_URL") or os.environ.get("CUSTOS_RBAC_ADMIN_DATABASE_URL"),
               key=app.config.get("RBAC_KEY"))
    app.extensions["custos_engine"] = engine

    def csrf():
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(token.encode(), request.form.get("csrf", "").encode()):
            abort(400)

    app.extensions["custos_csrf"] = csrf
    from web.backend_wizard import blueprint, is_admin
    app.register_blueprint(blueprint)
    from web.activity import blueprint as activity_blueprint
    app.register_blueprint(activity_blueprint)
    from web.resource_groups import blueprint as resource_blueprint
    app.register_blueprint(resource_blueprint)
    from web.role_mappings import blueprint as role_blueprint
    app.register_blueprint(role_blueprint)
    from web.integrations import blueprint as integrations_blueprint
    app.register_blueprint(integrations_blueprint)
    from web.console import blueprint as console_blueprint
    app.register_blueprint(console_blueprint)
    from web.setup_guide import blueprint as guide_blueprint
    app.register_blueprint(guide_blueprint)

    @app.before_request
    def audit_actor():
        g.audit_actor = session.get("principal_id")
        if session.get("login_id"):
            with Session(engine) as db:
                auth = db.get(AuthSession, session["login_id"])
                expiry = auth.expires_at.replace(tzinfo=timezone.utc) if auth and auth.expires_at.tzinfo is None else (auth.expires_at if auth else None)
                if not auth or auth.revoked or expiry <= datetime.now(timezone.utc):
                    session.clear()

    @app.after_request
    def headers(response):
        if request.endpoint != "static":
            from custos.audit import record
            actor = session.get("principal_id") or getattr(g, "audit_actor", None)
            event = "http." + request.method.lower() + "." + (request.endpoint or "unknown")
            if request.endpoint == "login" and request.method == "POST":
                event = "auth.login"
            elif request.endpoint == "logout":
                event = "auth.logout"
            elif request.endpoint == "backend.setup" and request.method == "POST":
                action = request.form.get("action", "")
                event = "backend." + (action if action in {"connect", "trust", "api", "sync", "tenant", "restart", "credentials"} else "invalid")
            with Session(engine) as audit_db, audit_db.begin():
                record(audit_db, event, "ok" if response.status_code < 400 else "denied" if response.status_code in {401,403} else "failed",
                    actor_id=actor, actor_name=(request.form.get("username", "")[:200] if event == "auth.login" and response.status_code >= 400 else None),
                    target=request.path[:200], source_ip=request.remote_addr, detail=f"HTTP {response.status_code}")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.route("/login", methods=["GET", "POST"])
    @app.route("/login/directory/<directory_id>", methods=["GET", "POST"])
    def login(directory_id=None):
        error = None
        if request.method == "POST":
            csrf()
            with Session(engine) as db:
                username, password = request.form.get("username", ""), request.form.get("password", "")
                user = (authenticate_directory(db, directory_id, username, password) if directory_id
                        else authenticate_local(db, username, password))
                if user:
                    user_id = user.id
                    session.clear()
                    session.permanent = True
                    session["principal_id"] = user_id
                    session["csrf"] = secrets.token_urlsafe(32)
                    auth = AuthSession(principal_id=user_id, expires_at=datetime.now(timezone.utc) + timedelta(minutes=15))
                    db.add(auth)
                    db.commit()
                    session["login_id"] = auth.id
                    db.close()
                    refresh_user_status(engine, user_id)
                    return redirect(url_for("index"))
            error = "Invalid username or password"
        session.setdefault("csrf", secrets.token_urlsafe(32))
        return render_template("login.html", error=error, csrf=session["csrf"], directory_id=directory_id), 401 if error else 200

    @app.post("/logout")
    def logout():
        csrf()
        if session.get("login_id"):
            with Session(engine) as db, db.begin():
                auth = db.get(AuthSession, session["login_id"])
                if auth:
                    auth.revoked = True
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        with Session(engine) as db:
            user_id = session.get("principal_id")
            user = db.get(Principal, user_id) if user_id else None
            valid = bool(user and user.enabled and user.kind == "user")
            if valid and user.directory_id:
                from datetime import datetime, timezone
                directory = db.get(Directory, user.directory_id)
                valid = bool(directory and directory.enabled and recent(directory.last_success_at,
                    datetime.now(timezone.utc), timedelta(minutes=15)))
            elif valid:
                valid = db.get(LocalCredential, user.id) is not None
            if not valid:
                session.clear()
                return redirect(url_for("login"))
            admin = is_admin(db, user.id)
            if admin and db.scalar(select(RemoteSystem.id).where(RemoteSystem.enabled.is_(True))) is None:
                return redirect(url_for("backend.setup"))
            vms = []
            backend_failures = set()
            for vm in db.scalars(select(VM).where(VM.enabled.is_(True))):
                if not permitted(db, user.id, vm.id, "view", inventory_max_age=None):
                    continue
                remote = db.get(RemoteSystem, vm.remote_system_id)
                tenant = db.get(Tenant, vm.tenant_id)
                lock = db.get(VMOperationLock, vm.id)
                from custos.backend_health import available
                backend_available = available(db, remote.id)
                if not backend_available:
                    backend_failures.add(remote.name)
                operation = db.get(Operation, lock.operation_id) if lock else None
                vms.append({"id": vm.id, "name": vm.dns_name or vm.inventory_name,
                    "ip": vm.primary_ip, "state": vm.power_state if backend_available else "UNKNOWN", "provider": remote.provider,
                    "tenant": tenant.name, "observed_at": vm.observed_at,
                    "locked": bool(lock) or not backend_available, "lock_text": "Backend unavailable" if not backend_available else ((operation.action + " · " + operation.status) if operation else "Available"),
                    "console_allowed": permitted(db, user.id, vm.id, "console", inventory_max_age=None),
                    "actions": sorted(a for a in ACTIONS - {"view", "console"} if permitted(db, user.id, vm.id, a, inventory_max_age=None))})
            return render_template("index.html", vms=vms, display_name=user.display_name, csrf=session["csrf"], admin=admin,
                                   idempotency_key=secrets.token_urlsafe(24), backend_failures=sorted(backend_failures))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=8080, debug=False)
