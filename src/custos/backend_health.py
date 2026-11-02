from datetime import datetime, timezone
from custos.database import BackendHealth


def set_health(db, remote_id, healthy):
    row = db.get(BackendHealth, remote_id)
    if row is None:
        row = BackendHealth(remote_system_id=remote_id)
        db.add(row)
    row.status, row.checked_at = "healthy" if healthy else "unavailable", datetime.now(timezone.utc)


def available(db, remote_id):
    from custos.authorization import recent
    from datetime import timedelta
    row = db.get(BackendHealth, remote_id)
    return bool(row and row.status == "healthy" and recent(row.checked_at,
                datetime.now(timezone.utc), timedelta(minutes=2)))
