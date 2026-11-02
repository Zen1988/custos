"""Validate injected credentials against LDAP, then map the verified immutable ID."""
from datetime import datetime, timedelta, timezone
import os
import ssl
from uuid import UUID

from ldap3 import Server, Connection, Tls, SUBTREE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import select

from custos.authorization import recent
from custos.database import Directory, DirectorySyncConfig, Principal
from custos.directory_sync import SyncError, validate


def authenticate_directory(db, directory_id, username, password):
    if not username or not password or len(username) > 200 or len(password) > 1024:
        return None  # Never allow an empty password to become an anonymous bind.
    directory = db.get(Directory, directory_id)
    config = db.get(DirectorySyncConfig, directory_id)
    if not directory or not config or not directory.enabled or not recent(
            directory.last_success_at, datetime.now(timezone.utc), timedelta(minutes=15)):
        return None
    connections = []
    try:
        parsed = validate(directory, config)
        secret = os.environ.get(directory.credential_ref[4:])
        if not secret:
            return None
        server = Server(parsed.hostname, port=parsed.port or (636 if parsed.scheme == "ldaps" else 389),
            use_ssl=parsed.scheme == "ldaps", connect_timeout=10,
            tls=Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=config.ca_bundle, valid_names=[parsed.hostname]))

        def bind(user, credential):
            connection = Connection(server, user=user, password=credential, read_only=True,
                auto_referrals=False, raise_exceptions=True, receive_timeout=30,
                auto_bind=AUTO_BIND_NO_TLS if parsed.scheme == "ldaps" else AUTO_BIND_TLS_BEFORE_BIND)
            connections.append(connection)
            return connection

        lookup = bind(config.bind_username, secret)
        escaped = escape_filter_chars(username)
        if config.kind == "ad":
            # Use UPN or sAMAccountName; the configured directory selects the domain.
            account = f"(|(userPrincipalName={escaped})(sAMAccountName={escaped}))"
            user_class = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            id_attribute = "objectGUID"
        else:
            account = f"(uid={escaped})"
            user_class = "(objectClass=inetOrgPerson)"
            id_attribute = "entryUUID"
        lookup.search(directory.base_dn, f"(&{user_class}{config.user_filter}{account})",
                      search_scope=SUBTREE, attributes=[id_attribute], size_limit=2, time_limit=15)
        if lookup.result.get("result") != 0 or len(lookup.response) != 1:
            return None
        row = lookup.response[0]
        if row.get("type") != "searchResEntry":
            return None
        raw = next(v for k, v in row["raw_attributes"].items() if k.lower() == id_attribute.lower())
        if len(raw) != 1:
            return None
        external = str(UUID(bytes_le=raw[0])) if config.kind == "ad" else str(UUID(raw[0].decode()))
        principal = db.scalar(select(Principal).where(Principal.directory_id == directory_id,
            Principal.external_id == external, Principal.kind == "user", Principal.enabled.is_(True)))
        if principal is None:
            return None
        verified = bind(row["dn"], password)
        return principal if verified.bound else None
    except (LDAPException, SyncError, OSError, ValueError, KeyError, TypeError, StopIteration):
        return None
    finally:
        for connection in reversed(connections):
            try:
                connection.unbind()
            except LDAPException:
                pass
