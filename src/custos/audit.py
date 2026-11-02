"""Structured audit records. Never pass credentials, cookies or raw provider errors."""
from datetime import datetime, timezone
from custos.database import AuditEvent, Principal


def record(db, event, outcome, *, actor_id=None, actor_name=None, target=None,
           source_ip=None, correlation_id=None, detail=""):
    user = db.get(Principal, actor_id) if actor_id else None
    db.add(AuditEvent(occurred_at=datetime.now(timezone.utc), actor_id=actor_id,
        actor_name=(actor_name or (user.display_name if user else "system"))[:200],
        event=event[:100], target=target, outcome=outcome[:30], source_ip=source_ip,
        correlation_id=correlation_id, detail=detail[:500]))
