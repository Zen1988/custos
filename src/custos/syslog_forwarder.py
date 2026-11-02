"""RFC 5424 events; RFC 6587 octet framing over TCP/TLS, durable retry outbox."""
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import ssl

from sqlalchemy import select
from sqlalchemy.orm import Session
from custos.database import AuditEvent, SyslogOutbox


def format_event(event, hostname=None):
    timestamp = event.occurred_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    stamp = timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    hostname = hostname or socket.gethostname()
    hostname = "".join(c if 33 <= ord(c) <= 126 and c != " " else "_" for c in hostname)[:255] or "-"
    severity = 3 if event.outcome in {"failed", "unknown", "unavailable"} else 4 if event.outcome == "denied" else 6
    # No vendor enterprise number is invented. Portable JSON is carried in UTF-8 MSG.
    header = f"<{16 * 8 + severity}>1 {stamp} {hostname} custos - AUDIT - "
    body = {"event_id": event.id, "actor_id": event.actor_id, "actor_name": event.actor_name,
        "event": event.event, "target": event.target, "outcome": event.outcome,
        "source_ip": event.source_ip, "correlation_id": event.correlation_id, "detail": event.detail}
    return (header + "\ufeff" + json.dumps(body, ensure_ascii=False, separators=(",", ":"))).encode("utf-8")


def send(payload):
    host = os.environ.get("CUSTOS_SYSLOG_HOST")
    transport = os.environ.get("CUSTOS_SYSLOG_TRANSPORT", "tls")
    if not host or transport not in {"tls", "tcp", "udp"}:
        raise ValueError("Configure a syslog host and tls/tcp/udp transport")
    port = int(os.environ.get("CUSTOS_SYSLOG_PORT", "6514" if transport == "tls" else "514"))
    if transport == "udp":
        address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(address[0], socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            if len(payload) > 65507:
                raise ValueError("Syslog event exceeds UDP payload limit")
            client.sendto(payload, address[4])
        return
    frame = str(len(payload)).encode("ascii") + b" " + payload
    with socket.create_connection((host, port), timeout=5) as client:
        if transport == "tls":
            context = ssl.create_default_context(cafile=os.environ.get("CUSTOS_SYSLOG_CA_BUNDLE"))
            certificate = os.environ.get("CUSTOS_SYSLOG_CLIENT_CERT")
            if certificate:
                context.load_cert_chain(certificate, os.environ.get("CUSTOS_SYSLOG_CLIENT_KEY"))
            with context.wrap_socket(client, server_hostname=host) as secured:
                secured.sendall(frame)
        else:
            client.sendall(frame)


def forward_pending(engine, limit=100):
    if not os.environ.get("CUSTOS_SYSLOG_HOST"):
        return 0
    now, delivered = datetime.now(timezone.utc), 0
    with Session(engine) as db:
        pending = db.scalars(select(SyslogOutbox).where(SyslogOutbox.delivered_at.is_(None),
            SyslogOutbox.retry_at <= now).order_by(SyslogOutbox.retry_at, SyslogOutbox.event_id).limit(limit)).all()
        for row in pending:
            event = db.get(AuditEvent, row.event_id)
            row.attempts += 1
            try:
                send(format_event(event))
                row.delivered_at = datetime.now(timezone.utc)
                delivered += 1
            except Exception:
                row.retry_at = now + timedelta(seconds=min(3600, 5 * 2 ** min(row.attempts, 10)))
                db.commit()
                break  # Do not spend minutes retrying a dead receiver in one cycle.
            db.commit()
    return delivered
