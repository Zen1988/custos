"""Initial relational model; production schema deployment requires migrations."""
from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, ForeignKeyConstraint, JSON, String, UniqueConstraint, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid():
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))


class RemoteSystem(Base):
    __tablename__ = "remote_systems"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(30), default="vcenter")
    endpoint: Mapped[str] = mapped_column(String(500))
    service_username: Mapped[str] = mapped_column(String(200))
    credential_ref: Mapped[str] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Directory(Base):
    __tablename__ = "directories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    endpoint: Mapped[str] = mapped_column(String(500))
    base_dn: Mapped[str] = mapped_column(String(500))
    credential_ref: Mapped[str] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (UniqueConstraint("directory_id", "external_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    directory_id: Mapped[str | None] = mapped_column(ForeignKey("directories.id"))
    external_id: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(10))  # user or group
    display_name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class LocalCredential(Base):
    __tablename__ = "local_credentials"
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)
    username: Mapped[str] = mapped_column(String(200), unique=True)
    password_hash: Mapped[str] = mapped_column(String(500))


class DirectorySyncConfig(Base):
    __tablename__ = "directory_sync_configs"
    directory_id: Mapped[str] = mapped_column(ForeignKey("directories.id"), primary_key=True)
    bind_username: Mapped[str] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(10))  # ad or ldap
    user_filter: Mapped[str] = mapped_column(String(4000))
    group_filter: Mapped[str] = mapped_column(String(4000))
    ca_bundle: Mapped[str | None] = mapped_column(String(500))
    max_entries: Mapped[int] = mapped_column(default=10000)


class GroupMember(Base):
    __tablename__ = "group_members"
    group_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)


class TenantMember(Base):
    __tablename__ = "tenant_members"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)


class VM(Base):
    __tablename__ = "vms"
    __table_args__ = (UniqueConstraint("remote_system_id", "provider_uid"),
                      UniqueConstraint("remote_system_id", "provider_ref"),
                      UniqueConstraint("id", "tenant_id"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    remote_system_id: Mapped[str] = mapped_column(ForeignKey("remote_systems.id"))
    provider_uid: Mapped[str] = mapped_column(String(200))  # vCenter config.instanceUuid
    provider_ref: Mapped[str] = mapped_column(String(200))  # e.g. vm-123
    inventory_name: Mapped[str] = mapped_column(String(200))
    primary_ip: Mapped[str | None] = mapped_column(String(45))
    dns_name: Mapped[str | None] = mapped_column(String(253))
    dns_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    power_state: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    tools_status: Mapped[str] = mapped_column(String(50), default="UNKNOWN")
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ResourceGroup(Base):
    __tablename__ = "resource_groups"
    __table_args__ = (UniqueConstraint("id", "tenant_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(10))  # static or dynamic
    rule: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ResourceGroupVM(Base):
    __tablename__ = "resource_group_vms"
    __table_args__ = (
        ForeignKeyConstraint(["group_id", "tenant_id"], ["resource_groups.id", "resource_groups.tenant_id"]),
        ForeignKeyConstraint(["vm_id", "tenant_id"], ["vms.id", "vms.tenant_id"]),
    )
    group_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vm_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))


class Grant(Base):
    __tablename__ = "grants"
    __table_args__ = (ForeignKeyConstraint(["group_id", "tenant_id"],
                                          ["resource_groups.id", "resource_groups.tenant_id"]),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    group_id: Mapped[str] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(30))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AdminRole(Base):
    __tablename__ = "admin_roles"
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), primary_key=True)


class BackendConfig(Base):
    __tablename__ = "backend_configs"
    remote_system_id: Mapped[str] = mapped_column(ForeignKey("remote_systems.id"), primary_key=True)
    version: Mapped[str] = mapped_column(String(30))
    vcenter_uid: Mapped[str] = mapped_column(String(200), unique=True)
    encrypted_password: Mapped[str] = mapped_column(String(4000))
    trusted_pem: Mapped[str | None] = mapped_column(String(10000))
    scope: Mapped[dict] = mapped_column(JSON)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackendDraft(Base):
    __tablename__ = "backend_drafts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    admin_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stage: Mapped[str] = mapped_column(String(20))
    data: Mapped[dict] = mapped_column(JSON)


class VMAddress(Base):
    __tablename__ = "vm_addresses"
    vm_id: Mapped[str] = mapped_column(ForeignKey("vms.id"), primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    dns_name: Mapped[str | None] = mapped_column(String(253))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SyncSchedule(Base):
    __tablename__ = "sync_schedules"
    remote_system_id: Mapped[str] = mapped_column(ForeignKey("remote_systems.id"), primary_key=True)
    frequency: Mapped[str] = mapped_column(String(20))
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(30), default="ready")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor_id: Mapped[str | None] = mapped_column(String(36))
    actor_name: Mapped[str] = mapped_column(String(200))
    event: Mapped[str] = mapped_column(String(100))
    target: Mapped[str | None] = mapped_column(String(200))
    outcome: Mapped[str] = mapped_column(String(30))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    correlation_id: Mapped[str | None] = mapped_column(String(36))
    detail: Mapped[str] = mapped_column(String(500), default="")


class Operation(Base):
    __tablename__ = "operations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    vm_id: Mapped[str] = mapped_column(ForeignKey("vms.id"))
    action: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    provider_task: Mapped[str | None] = mapped_column(String(200))
    idempotency_key: Mapped[str] = mapped_column(String(100), unique=True)


class VMOperationLock(Base):
    __tablename__ = "vm_operation_locks"
    vm_id: Mapped[str] = mapped_column(ForeignKey("vms.id"), primary_key=True)
    operation_id: Mapped[str] = mapped_column(ForeignKey("operations.id"), unique=True)


class BackendHealth(Base):
    __tablename__ = "backend_health"
    remote_system_id: Mapped[str] = mapped_column(ForeignKey("remote_systems.id"), primary_key=True)
    status: Mapped[str] = mapped_column(String(20))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BackendArchive(Base):
    __tablename__ = "backend_archives"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(30))
    archived_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    encrypted_payload: Mapped[str] = mapped_column(String)


class SyslogOutbox(Base):
    __tablename__ = "syslog_outbox"
    event_id: Mapped[str] = mapped_column(ForeignKey("audit_events.id"), primary_key=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(default=0)
    retry_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConsoleSession(Base):
    __tablename__ = "console_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    vm_id: Mapped[str] = mapped_column(ForeignKey("vms.id"))
    operation_id: Mapped[str] = mapped_column(ForeignKey("operations.id"))
    state: Mapped[str] = mapped_column(String(20), default="issued")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    login_id: Mapped[str] = mapped_column(String(36))


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


@event.listens_for(AuditEvent, "after_insert")
def enqueue_syslog(mapper, connection, target):
    connection.execute(SyslogOutbox.__table__.insert().values(event_id=target.id,
        attempts=0, retry_at=target.occurred_at))


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def immutable_audit(mapper, connection, target):
    raise ValueError("Audit records are append-only")
