"""Isolated encrypted role bindings. Inventory credentials cannot write RBAC."""
import json
import os
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String, create_engine, select
from sqlalchemy.engine import make_url
from pathlib import Path
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class RbacBase(DeclarativeBase):
    pass


class RoleBinding(RbacBase):
    __tablename__ = "role_bindings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    encrypted_policy: Mapped[str] = mapped_column(String(200000))


class RbacError(Exception):
    pass


class RbacStore:
    def __init__(self, read_url, write_url, key):
        try:
            if key == os.environ.get("CUSTOS_ENCRYPTION_KEY"):
                raise ValueError()
            self.cipher = Fernet(key.encode())
        except (ValueError, AttributeError):
            raise RbacError("Set an independent CUSTOS_RBAC_KEY; do not reuse the backend secret key") from None
        self.reader = create_engine(read_url)
        self.writer = create_engine(write_url) if write_url else None

    def initialize(self):
        if not self.writer:
            raise RbacError("RBAC administration connection is not configured")
        RbacBase.metadata.create_all(self.writer)

    def policies(self):
        try:
            with Session(self.reader) as db:
                result = []
                for row in db.scalars(select(RoleBinding)):
                    policy = json.loads(self.cipher.decrypt(row.encrypted_policy.encode()))
                    # Binding IDs are authenticated too, so ciphertext cannot be moved to another row.
                    if policy["id"] != row.id or policy["role"] not in {"readonly", "operator", "admin"}:
                        raise RbacError("Invalid RBAC policy")
                    result.append(policy)
                return result
        except Exception:
            raise RbacError("RBAC store unavailable or policy integrity check failed") from None

    def add(self, subject_id, subject_kind, role, resource_group=None):
        if not self.writer or role not in {"readonly", "operator", "admin"} or subject_kind not in {"user", "group"}:
            raise RbacError("Invalid role binding or RBAC write access unavailable")
        if role != "admin" and not resource_group:
            raise RbacError("Read-only/operator roles require a resource group")
        identifier = str(uuid4())
        policy = {"id": identifier, "subject_id": subject_id, "subject_kind": subject_kind,
                  "role": role, "resource_group": resource_group}
        with Session(self.writer) as db, db.begin():
            db.add(RoleBinding(id=identifier, encrypted_policy=self.cipher.encrypt(json.dumps(policy).encode()).decode()))
        return identifier

    def remove(self, identifier):
        if not self.writer:
            raise RbacError("RBAC write access unavailable")
        with Session(self.writer) as db, db.begin():
            row = db.get(RoleBinding, identifier)
            if row:
                db.delete(row)


def attach(engine, *, read_url=None, write_url=None, key=None):
    read_url = read_url or os.environ.get("CUSTOS_RBAC_DATABASE_URL", "sqlite:///custos-rbac.db")
    if os.environ.get("CUSTOS_CLUSTER_MODE", "").lower() in {"1", "true"} and make_url(read_url).get_backend_name() != "postgresql":
        raise RbacError("Cluster mode requires PostgreSQL for the RBAC database too")
    def location(url):
        parsed = make_url(url)
        if parsed.get_backend_name() == "sqlite":
            return ("sqlite", str(Path(parsed.database or ":memory:").resolve()).casefold())
        return (parsed.get_backend_name(), parsed.host, parsed.port, parsed.database)
    for value in [read_url, write_url]:
        if not value:
            continue
        if location(value) == location(engine.url):
            raise RbacError("RBAC must use a separate database from inventory")
        parsed = make_url(value)
        if parsed.get_backend_name() != "sqlite" and parsed.username == engine.url.username:
            raise RbacError("RBAC requires a database identity different from the inventory identity")
    if write_url:
        if location(read_url) != location(write_url):
            raise RbacError("RBAC reader and administrator must connect to the same RBAC database")
        if make_url(read_url).get_backend_name() != "sqlite" and make_url(read_url).username == make_url(write_url).username:
            raise RbacError("Use different RBAC reader and administrator database identities")
    store = RbacStore(read_url, write_url, key or os.environ.get("CUSTOS_RBAC_KEY"))
    engine.custos_rbac_store = store
    return store


def subject_ids(db, user):
    from custos.database import GroupMember, Principal
    groups = db.scalars(select(Principal).join(GroupMember, GroupMember.group_id == Principal.id).where(
        GroupMember.user_id == user.id, Principal.kind == "group", Principal.enabled.is_(True),
        Principal.directory_id == user.directory_id))
    return {(user.id, "user")} | {(group.id, "group") for group in groups}


def administrator(db, user):
    store = getattr(db.get_bind(), "custos_rbac_store", None)
    if store is None:
        from custos.database import AdminRole
        return db.get(AdminRole, user.id) is not None  # Legacy test/bootstrap only.
    try:
        subjects = subject_ids(db, user)
        return any(p["role"] == "admin" and (p["subject_id"], p["subject_kind"]) in subjects for p in store.policies())
    except (RbacError, KeyError, TypeError):
        return False


def snapshot_group(db, group):
    from custos.database import ResourceGroupVM
    return {"id": group.id, "tenant_id": group.tenant_id, "mode": group.mode,
            "rule": group.rule, "vm_ids": list(db.scalars(select(ResourceGroupVM.vm_id).where(ResourceGroupVM.group_id == group.id)))}


def allows(db, user, vm, action):
    from custos.database import VMAddress
    from custos.resource_rules import matches
    store = db.get_bind().custos_rbac_store
    try:
        subjects = subject_ids(db, user)
        for policy in store.policies():
            if (policy["subject_id"], policy["subject_kind"]) not in subjects:
                continue
            if policy["role"] == "admin":
                return True
            if policy["role"] == "readonly" and action != "view":
                continue
            group = policy["resource_group"]
            if group["tenant_id"] != vm.tenant_id:
                continue
            if group["mode"] == "static" and vm.id in group["vm_ids"]:
                return True
            if group["mode"] == "dynamic" and matches(group["rule"], vm,
                    db.scalars(select(VMAddress.ip).where(VMAddress.vm_id == vm.id)).all()):
                return True
        return False
    except (RbacError, KeyError, TypeError):
        return False
