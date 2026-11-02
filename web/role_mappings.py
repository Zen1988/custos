from flask import Blueprint, abort, current_app, render_template, request, session
from sqlalchemy import select
from sqlalchemy.orm import Session
from custos.audit import record
from custos.database import Principal, ResourceGroup
from custos.rbac import RbacError, snapshot_group
from web.backend_wizard import is_admin

blueprint = Blueprint("roles", __name__)


@blueprint.route("/admin/role-mappings", methods=["GET", "POST"])
def mappings():
    engine = current_app.extensions["custos_engine"]
    error = None
    with Session(engine) as db:
        if not is_admin(db, session.get("principal_id")):
            abort(403)
        store = getattr(engine, "custos_rbac_store", None)
        if store is None:
            return "Isolated RBAC must be configured before managing role mappings", 503
        if request.method == "POST":
            current_app.extensions["custos_csrf"]()
            try:
                action = request.form.get("action")
                target = request.form.get("binding_id") if action == "remove" else request.form.get("subject")
                # Durable intent record precedes the independently committed RBAC mutation.
                record(db, "rbac." + ("remove" if action == "remove" else "assign"), "requested",
                       actor_id=session["principal_id"], target=target)
                db.commit()
                if action == "remove":
                    store.remove(target)
                elif action == "assign":
                    principal = db.get(Principal, target)
                    role = request.form.get("role")
                    group = db.get(ResourceGroup, request.form.get("resource_group")) if role != "admin" else None
                    if not principal or not principal.enabled or principal.kind not in {"user", "group"}:
                        raise RbacError("Select an enabled user or user group")
                    if role != "admin" and (not group or not group.enabled):
                        raise RbacError("Select an enabled resource group")
                    target = store.add(principal.id, principal.kind, role, snapshot_group(db, group) if group else None)
                else:
                    raise RbacError("Unknown role mapping action")
                record(db, "rbac." + ("remove" if action == "remove" else "assign"), "succeeded",
                       actor_id=session["principal_id"], target=target)
                db.commit()
            except RbacError as failure:
                error = str(failure)
                record(db, "rbac.change", "failed", actor_id=session["principal_id"])
                db.commit()
        try:
            policies = store.policies()
        except RbacError as failure:
            policies, error = [], str(failure)
        principals = db.scalars(select(Principal).where(Principal.enabled.is_(True))).all()
        names = {p.id:p.display_name for p in principals}
        groups = db.scalars(select(ResourceGroup).where(ResourceGroup.enabled.is_(True))).all()
        return render_template("role_mappings.html", policies=policies, principals=principals, names=names,
            groups=groups, group_names={g.id:g.name for g in groups},
            error=error, csrf=session["csrf"], writable=store.writer is not None), 400 if error else 200
