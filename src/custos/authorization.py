"""Deny-by-default DB authorization; call again immediately before execution."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from custos.database import (Directory, Grant, GroupMember, LocalCredential, Principal, RemoteSystem,
                             ResourceGroup, ResourceGroupVM, TenantMember, VM, VMAddress)
from custos.resource_rules import matches

ACTIONS = frozenset({"view", "console", "start", "stop", "reboot", "reset", "snapshot"})


def recent(value, now, max_age):
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return timedelta(0) <= now - value <= max_age


def permitted(session, user_id, vm_id, action, *, now=None,
              directory_max_age=timedelta(minutes=15), inventory_max_age=timedelta(minutes=5)):
    if action not in ACTIONS:
        return False
    now = now or datetime.now(timezone.utc)
    user = session.get(Principal, user_id)
    vm = session.get(VM, vm_id)
    if not user or user.kind != "user" or not user.enabled or not vm or not vm.enabled:
        return False
    remote = session.get(RemoteSystem, vm.remote_system_id)
    if user.directory_id is None:
        if session.get(LocalCredential, user.id) is None:
            return False
    else:
        directory = session.get(Directory, user.directory_id)
        if not directory or not directory.enabled or not recent(directory.last_success_at, now, directory_max_age):
            return False
    if not remote or not remote.enabled or (inventory_max_age is not None and not recent(vm.observed_at, now, inventory_max_age)):
        return False
    from custos.rbac import administrator, allows
    if getattr(session.get_bind(), "custos_rbac_store", None) is not None:
        return allows(session, user, vm, action)
    if administrator(session, user):
        return True
    principals = {user.id}
    groups = session.scalars(select(Principal).join(GroupMember, GroupMember.group_id == Principal.id)
                             .where(GroupMember.user_id == user.id, Principal.kind == "group",
                                    Principal.enabled.is_(True), Principal.directory_id == user.directory_id))
    principals.update(group.id for group in groups)
    membership = session.scalar(select(TenantMember).where(
        TenantMember.tenant_id == vm.tenant_id, TenantMember.principal_id.in_(principals)))
    if membership is None:
        return False
    grants = session.scalars(select(Grant).where(Grant.tenant_id == vm.tenant_id,
                            Grant.principal_id.in_(principals), Grant.action == action,
                            Grant.enabled.is_(True)))
    for grant in grants:
        group = session.get(ResourceGroup, grant.group_id)
        if not group or not group.enabled or group.tenant_id != vm.tenant_id:
            continue
        if group.mode == "dynamic":
            addresses = session.scalars(select(VMAddress.ip).where(VMAddress.vm_id == vm.id)).all() if isinstance(group.rule, dict) and set(group.rule) & {"ip_range", "subnet"} else []
            if matches(group.rule, vm, addresses):
                return True
        if group.mode == "static" and session.get(ResourceGroupVM, (group.id, vm.id)):
            return True
    return False
