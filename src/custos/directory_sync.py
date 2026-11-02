"""Scoped read-only LDAP import into Custos. No provider access is granted here."""
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
import ssl
from urllib.parse import urlsplit
from uuid import UUID

from ldap3 import Server, Connection, Tls, SUBTREE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import delete, select

from custos.database import Directory, DirectorySyncConfig, GroupMember, Principal


class SyncError(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    external_id: str
    kind: str
    display_name: str


@dataclass(frozen=True)
class Snapshot:
    identities: tuple[Identity, ...]
    memberships: frozenset[tuple[str, str]]  # group external ID, user external ID


def validate(directory, config):
    parsed = urlsplit(directory.endpoint)
    if (parsed.scheme not in {"ldaps", "ldap"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise SyncError("Directory endpoint must be an ldap/ldaps origin; ldap requires StartTLS")
    if (not directory.enabled or not directory.base_dn or not config.bind_username
            or config.kind not in {"ad", "ldap"} or not 1 <= config.max_entries <= 100000):
        raise SyncError("Invalid or disabled directory sync configuration")
    for value in [config.user_filter, config.group_filter]:
        if not value or not value.startswith("(") or not value.endswith(")"):
            raise SyncError("Explicit parenthesized user and group filters are required")
    if not directory.credential_ref.startswith("env:") or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", directory.credential_ref[4:]):
        raise SyncError("Credential reference must be env:VARIABLE_NAME")
    return parsed


def fetch_snapshot(directory, config):
    parsed = validate(directory, config)
    password = os.environ.get(directory.credential_ref[4:])
    if not password:
        raise SyncError("Directory bind secret is missing from the configured environment variable")
    connection = None
    try:
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=config.ca_bundle,
                  valid_names=[parsed.hostname])
        server = Server(parsed.hostname, port=parsed.port or (636 if parsed.scheme == "ldaps" else 389),
                        use_ssl=parsed.scheme == "ldaps", tls=tls, connect_timeout=10)
        connection = Connection(server, user=config.bind_username, password=password,
            auto_bind=AUTO_BIND_NO_TLS if parsed.scheme == "ldaps" else AUTO_BIND_TLS_BEFORE_BIND,
            read_only=True, auto_referrals=False, raise_exceptions=True, receive_timeout=30)

        def search(query, attributes):
            rows, cookie, seen = [], None, set()
            while True:
                connection.search(directory.base_dn, query, search_scope=SUBTREE,
                    attributes=attributes, paged_size=500, paged_cookie=cookie, time_limit=30)
                if connection.result.get("result") != 0:
                    raise SyncError("Directory search did not complete successfully")
                for row in connection.response:
                    if row["type"] != "searchResEntry":
                        raise SyncError("Directory search returned a referral or incomplete result")
                    if any(";range=" in key.lower() for key in row.get("raw_attributes", {})):
                        raise SyncError("Ranged LDAP attributes require a narrower scope")
                    rows.append(row)
                if len(rows) > config.max_entries:
                    raise SyncError("Directory search exceeded the configured entry limit")
                control = connection.result.get("controls", {}).get("1.2.840.113556.1.4.319")
                if control is None:
                    raise SyncError("Directory server must support paged search")
                cookie = control["value"]["cookie"]
                if not cookie:
                    return rows
                if cookie in seen:
                    raise SyncError("Directory server repeated a paging cookie")
                seen.add(cookie)

        id_attr = "objectGUID" if config.kind == "ad" else "entryUUID"

        def values(row, attribute):
            return next((v for k, v in row["raw_attributes"].items() if k.lower() == attribute.lower()), [])

        def identity(row, kind):
            raw = values(row, id_attr)
            if len(raw) != 1:
                raise SyncError("Directory entry is missing its immutable ID")
            external = str(UUID(bytes_le=raw[0])) if config.kind == "ad" else str(UUID(raw[0].decode()))
            name = values(row, "displayName") or values(row, "cn")
            return Identity(external, kind, name[0].decode() if name else row["dn"])

        user_class = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" if config.kind == "ad" else "(objectClass=inetOrgPerson)"
        group_class = "(objectClass=group)" if config.kind == "ad" else "(objectClass=groupOfNames)"
        user_query = f"(&{user_class}{config.user_filter})"
        users = search(user_query, [id_attr, "displayName", "cn"])
        group_attrs = [id_attr, "displayName", "cn"]
        if config.kind == "ldap":
            group_attrs.append("member")
        groups = search(f"(&{group_class}{config.group_filter})", group_attrs)
        user_ids = {row["dn"].casefold(): identity(row, "user").external_id for row in users}
        identities = [identity(row, "user") for row in users]
        memberships = set()
        for row in groups:
            group = identity(row, "group")
            identities.append(group)
            if config.kind == "ad":
                dn = escape_filter_chars(row["dn"])
                members = search(f"(&{user_query}(memberOf:1.2.840.113556.1.4.1941:={dn}))", [id_attr, "cn"])
                for member in members:
                    user = identity(member, "user")
                    if user.external_id not in user_ids.values():
                        raise SyncError("Directory membership changed during sync; retry")
                    memberships.add((group.external_id, user.external_id))
            else:
                for dn in values(row, "member"):
                    user = user_ids.get(dn.decode().casefold())
                    if user:
                        memberships.add((group.external_id, user))
        if len(identities) > config.max_entries:
            raise SyncError("Directory scope exceeded the configured total entry limit")
        return Snapshot(tuple(identities), frozenset(memberships))
    except (LDAPException, OSError, ValueError, KeyError, TypeError):
        raise SyncError("LDAP sync failed; check TLS trust, bind credentials, filters and directory schema") from None
    finally:
        if connection is not None:
            try:
                connection.unbind()
            except LDAPException:
                pass


def apply_snapshot(session, directory_id, snapshot, *, allow_empty=False):
    """Caller owns the transaction. Snapshot is validated before any mutation."""
    directory = session.get(Directory, directory_id)
    if directory is None or not directory.enabled:
        raise SyncError("Directory is missing or disabled")
    identities = {item.external_id: item for item in snapshot.identities}
    if len(identities) != len(snapshot.identities) or any(i.kind not in {"user", "group"} for i in identities.values()):
        raise SyncError("Duplicate or invalid directory identities")
    if not identities and not allow_empty:
        raise SyncError("Empty scope requires --allow-empty to disable all imported identities")
    for group, user in snapshot.memberships:
        if (group not in identities or user not in identities or identities[group].kind != "group"
                or identities[user].kind != "user"):
            raise SyncError("Invalid snapshot membership")
    existing = {p.external_id: p for p in session.scalars(select(Principal).where(Principal.directory_id == directory_id))}
    if any(key in existing and existing[key].kind != item.kind for key, item in identities.items()):
        raise SyncError("Directory identity changed type")
    for key, principal in existing.items():
        principal.enabled = key in identities
    for key, item in identities.items():
        if key not in existing:
            existing[key] = Principal(directory_id=directory_id, external_id=key,
                                      kind=item.kind, display_name=item.display_name)
            session.add(existing[key])
        existing[key].display_name = item.display_name
        existing[key].enabled = True
    session.flush()
    ids = [p.id for p in existing.values()]
    if ids:
        session.execute(delete(GroupMember).where(
            GroupMember.group_id.in_(ids) | GroupMember.user_id.in_(ids)))
    for group, user in snapshot.memberships:
        session.add(GroupMember(group_id=existing[group].id, user_id=existing[user].id))
    directory.last_success_at = datetime.now(timezone.utc)
    return {"users": sum(i.kind == "user" for i in identities.values()),
            "groups": sum(i.kind == "group" for i in identities.values()),
            "memberships": len(snapshot.memberships),
            "disabled": sum(key not in identities for key in existing)}
