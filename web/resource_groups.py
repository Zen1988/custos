import json
from flask import Blueprint, abort, current_app, render_template, request, session
from sqlalchemy import select
from sqlalchemy.orm import Session

from custos.audit import record
from custos.database import ResourceGroup, ResourceGroupVM, Tenant, VM, VMAddress
from custos.resource_rules import matches, validate_rule
from web.backend_wizard import is_admin

blueprint = Blueprint("resources", __name__)


@blueprint.route("/admin/resource-groups", methods=["GET", "POST"])
def groups():
    error, preview, success = None, None, None
    with Session(current_app.extensions["custos_engine"]) as db, db.begin():
        if not is_admin(db, session.get("principal_id")):
            abort(403)
        if request.method == "POST":
            current_app.extensions["custos_csrf"]()
            try:
                tenant_id, mode = request.form.get("tenant"), request.form.get("mode")
                name = request.form.get("name", "").strip()
                if not db.get(Tenant, tenant_id) or mode not in {"static", "dynamic"} or not 1 <= len(name) <= 200:
                    raise ValueError("Select a tenant, group mode and name")
                candidates = db.scalars(select(VM).where(VM.tenant_id == tenant_id, VM.enabled.is_(True))).all()
                rule = {}
                if mode == "dynamic":
                    text = request.form.get("rule", "").strip()
                    if text:
                        rule = json.loads(text)
                    else:
                        rule = {key: request.form[key].strip() for key in ["name_regex", "subnet", "remote_system_id"] if request.form.get(key, "").strip()}
                        if request.form.get("range_start") or request.form.get("range_end"):
                            rule["ip_range"] = {"start": request.form.get("range_start", "").strip(), "end": request.form.get("range_end", "").strip()}
                    validate_rule(rule)
                    selected = [vm for vm in candidates if matches(rule, vm,
                        db.scalars(select(VMAddress.ip).where(VMAddress.vm_id == vm.id)).all())]
                else:
                    ids = set(request.form.getlist("vm"))
                    selected = [vm for vm in candidates if vm.id in ids]
                    if not ids or len(selected) != len(ids):
                        raise ValueError("Select at least one enabled VM from the selected tenant")
                action = request.form.get("action")
                if action == "preview":
                    preview = selected
                elif action == "create":
                    group = ResourceGroup(tenant_id=tenant_id, name=name, mode=mode, rule=rule)
                    db.add(group)
                    db.flush()
                    if mode == "static":
                        for vm in selected:
                            db.add(ResourceGroupVM(group_id=group.id, vm_id=vm.id, tenant_id=tenant_id))
                    record(db, "resource_group.create", "succeeded", actor_id=session["principal_id"], target=group.id,
                           detail=f"{mode}; {len(selected)} current members")
                    success = "Resource group created. Assign grants separately to allow user or group access."
                else:
                    raise ValueError("Unknown resource group action")
            except (ValueError, TypeError) as failure:
                error = str(failure)
        group_list = db.scalars(select(ResourceGroup)).all()
        member_counts = {}
        for group in group_list:
            if group.mode == "static":
                member_counts[group.id] = len(db.scalars(select(ResourceGroupVM).where(ResourceGroupVM.group_id == group.id)).all())
            else:
                member_counts[group.id] = sum(matches(group.rule, vm, db.scalars(select(VMAddress.ip).where(VMAddress.vm_id == vm.id)).all())
                    for vm in db.scalars(select(VM).where(VM.tenant_id == group.tenant_id, VM.enabled.is_(True))))
        return render_template("resource_groups.html", groups=group_list, counts=member_counts,
            tenants=db.scalars(select(Tenant)).all(), vms=db.scalars(select(VM).where(VM.enabled.is_(True))).all(),
            error=error, success=success, preview=preview, csrf=session["csrf"]), 400 if error else 200
