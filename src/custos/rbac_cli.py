"""Trusted deployment bootstrap for the separate RBAC database."""
import argparse
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from custos.database import Principal
from custos.rbac import RbacError, attach


def main():
    parser = argparse.ArgumentParser(description="Custos isolated RBAC bootstrap")
    parser.add_argument("command", choices=["init", "grant-admin"])
    parser.add_argument("principal_id", nargs="?")
    args = parser.parse_args()
    engine = create_engine(os.environ.get("CUSTOS_DATABASE_URL", "sqlite:///custos.db"))
    try:
        store = attach(engine, write_url=os.environ.get("CUSTOS_RBAC_ADMIN_DATABASE_URL"))
        if args.command == "init":
            store.initialize()
        else:
            with Session(engine) as db:
                user = db.get(Principal, args.principal_id) if args.principal_id else None
                if not user or not user.enabled or user.kind not in {"user", "group"}:
                    raise RbacError("Specify an enabled principal ID")
                from custos.audit import record
                record(db, "rbac.bootstrap", "requested", actor_name="deployment-cli", target=user.id)
                db.commit()
                identifier = store.add(user.id, user.kind, "admin")
                record(db, "rbac.bootstrap", "succeeded", actor_name="deployment-cli", target=identifier)
                db.commit()
        print("RBAC configuration saved")
    except RbacError as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
