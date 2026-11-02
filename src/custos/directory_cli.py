"""Trusted operator CLI for configuring and running scoped identity imports."""
import argparse
import getpass
import json
import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from custos.database import Base, Directory, DirectorySyncConfig
from custos.directory_sync import SyncError, apply_snapshot, fetch_snapshot, validate
from custos.rbac import RbacError


def main():
    parser = argparse.ArgumentParser(description="Custos scoped LDAP/AD identity import")
    parser.add_argument("--database", default=os.environ.get("CUSTOS_DATABASE_URL", "sqlite:///custos.db"), help="SQLAlchemy database URL; defaults to CUSTOS_DATABASE_URL")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db", help="Create tables in a new local development database")
    local = commands.add_parser("local-user-create", help="Create a local account without granting resource access")
    local.add_argument("username")
    local.add_argument("--display-name", required=True)
    local.add_argument("--admin", action="store_true", help="Grant Custos administration to this new local user")
    configure = commands.add_parser("configure", help="Create/update a directory from JSON")
    configure.add_argument("file", type=Path)
    for name in ("preview", "sync"):
        command = commands.add_parser(name)
        command.add_argument("directory_id")
        command.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()
    try:
        engine = create_engine(args.database)
        if engine.dialect.name == "sqlite":
            event.listen(engine, "connect", lambda c, _: c.execute("PRAGMA foreign_keys=ON"))
        if args.command == "init-db":
            Base.metadata.create_all(engine)
            print("Database tables initialized; existing schemas are not migrated.")
            return 0
        with Session(engine) as session, session.begin():
            if args.command == "local-user-create":
                from custos.local_identity import create_local_user
                password = getpass.getpass("New local password: ")
                if password != getpass.getpass("Confirm password: "):
                    raise SyncError("Passwords do not match")
                user = create_local_user(session, args.username, args.display_name, password)
                if args.admin:
                    from custos.rbac import attach
                    store = attach(engine, write_url=os.environ.get("CUSTOS_RBAC_ADMIN_DATABASE_URL"))
                    store.add(user.id, "user", "admin")
                from custos.audit import record
                record(session, "identity.local_create", "succeeded", target=user.id,
                       actor_name="operator-cli", detail="Custos admin" if args.admin else "Local user")
                result = {"principal_id": user.id, "source": "local"}
            elif args.command == "configure":
                data = json.loads(args.file.read_text(encoding="utf-8"))
                allowed = {"id", "name", "endpoint", "base_dn", "credential_ref", "bind_username",
                           "kind", "user_filter", "group_filter", "ca_bundle", "max_entries"}
                if set(data) - allowed:
                    raise SyncError("Unknown directory configuration fields")
                directory = Directory(id=data["id"], name=data["name"], endpoint=data["endpoint"],
                    base_dn=data["base_dn"], credential_ref=data["credential_ref"], enabled=True)
                config = DirectorySyncConfig(directory_id=data["id"], bind_username=data["bind_username"],
                    kind=data["kind"], user_filter=data["user_filter"], group_filter=data["group_filter"],
                    ca_bundle=data.get("ca_bundle"), max_entries=data.get("max_entries", 10000))
                validate(directory, config)
                session.merge(directory)
                session.flush()
                session.merge(config)
                # Changed scope/connection must be synced before old grants can be used.
                session.get(Directory, data["id"]).last_success_at = None
                from custos.audit import record
                record(session, "directory.configure", "succeeded", target=data["id"], actor_name="operator-cli")
                print(json.dumps({"directory_id": data["id"], "configured": True}))
                return 0
            else:
                result = run_import(session, args)
        if args.command in {"sync", "local-user-create"}:
            print(json.dumps({**result, "applied": True}))
        return 0
    except (SyncError, RbacError, OSError, ValueError, KeyError, TypeError) as error:
        message = str(error) if isinstance(error, (SyncError, RbacError, ValueError)) else "Invalid configuration or unavailable configuration file"
        parser.exit(1, message + "\n")
    except SQLAlchemyError:
        parser.exit(1, "Database operation failed; no changes were committed\n")


def run_import(session, args):
    from sqlalchemy import select
    directory = session.scalar(select(Directory).where(Directory.id == args.directory_id).with_for_update())
    config = session.get(DirectorySyncConfig, args.directory_id)
    if directory is None or config is None:
        raise SyncError("Directory is not configured")
    snapshot = fetch_snapshot(directory, config)
    if args.command == "preview":
        print(json.dumps({"directory_id": directory.id,
            "users": sum(i.kind == "user" for i in snapshot.identities),
            "groups": sum(i.kind == "group" for i in snapshot.identities),
            "memberships": len(snapshot.memberships), "applied": False}))
        return None
    result = apply_snapshot(session, directory.id, snapshot, allow_empty=args.allow_empty)
    from custos.audit import record
    record(session, "directory.sync", "succeeded", target=directory.id, actor_name="operator-cli",
           detail=f"Users {result['users']}; groups {result['groups']}; disabled {result['disabled']}")
    session.flush()
    return result


if __name__ == "__main__":
    main()
