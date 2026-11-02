"""PostgreSQL worker leadership; no mutation replay after leader loss."""
from contextlib import contextmanager
import os
from sqlalchemy import text


def require_cluster_database(engine):
    if os.environ.get("CUSTOS_CLUSTER_MODE", "").lower() in {"1", "true"} and engine.dialect.name != "postgresql":
        raise ValueError("Cluster mode requires PostgreSQL; SQLite cannot serve a multi-node Custos deployment")


@contextmanager
def worker_leader(engine):
    require_cluster_database(engine)
    if engine.dialect.name != "postgresql":
        yield True
        return
    # Session-level lock is held on a dedicated live connection for the complete cycle.
    with engine.connect() as connection:
        acquired = bool(connection.execute(text("SELECT pg_try_advisory_lock(7219134052841)")).scalar())
        try:
            yield acquired
        finally:
            if acquired:
                connection.execute(text("SELECT pg_advisory_unlock(7219134052841)"))
