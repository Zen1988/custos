from datetime import datetime, timezone
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from custos.audit import record
from custos.database import AuditEvent, Base, SyslogOutbox
from custos.syslog_forwarder import format_event, forward_pending, send


class SyslogTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)
        self.addCleanup(self.engine.dispose)

    def test_rfc5424_unicode_and_log_injection_escaping(self):
        event = SimpleNamespace(id="event-1", occurred_at=datetime(2026,11,2,2,3,4,tzinfo=timezone.utc),
            actor_id="u", actor_name="用户\nforged", event="vm.start", target="vm", outcome="denied",
            source_ip="192.0.2.1", correlation_id="op", detail="No password included")
        message = format_event(event, "host with spaces")
        self.assertTrue(message.startswith(b"<132>1 2026-11-02T02:03:04.000Z host_with_spaces custos - AUDIT - "))
        self.assertIn(b"\xef\xbb\xbf", message)
        self.assertNotIn(b"\n", message)
        self.assertIn("用户".encode(), message)

    def test_outbox_is_atomic_with_local_audit(self):
        with Session(self.engine) as db:
            record(db, "test", "ok")
            db.flush()
            self.assertIsNotNone(db.scalar(select(SyslogOutbox)))
            db.rollback()
            self.assertIsNone(db.scalar(select(SyslogOutbox)))
            self.assertIsNone(db.scalar(select(AuditEvent)))

    @patch.dict(os.environ, {"CUSTOS_SYSLOG_HOST": "logger.test"})
    def test_failed_delivery_retained_and_success_marked(self):
        with Session(self.engine) as db, db.begin():
            record(db, "test", "ok")
        with patch("custos.syslog_forwarder.send", side_effect=OSError):
            self.assertEqual(forward_pending(self.engine), 0)
        with Session(self.engine) as db, db.begin():
            row = db.scalar(select(SyslogOutbox))
            self.assertEqual(row.attempts, 1)
            self.assertIsNone(row.delivered_at)
            row.retry_at = datetime(2000,1,1,tzinfo=timezone.utc)
        with patch("custos.syslog_forwarder.send"):
            self.assertEqual(forward_pending(self.engine), 1)
        with Session(self.engine) as db:
            self.assertIsNotNone(db.scalar(select(SyslogOutbox)).delivered_at)

    @patch.dict(os.environ, {"CUSTOS_SYSLOG_HOST": "logger.test", "CUSTOS_SYSLOG_TRANSPORT": "tcp"})
    @patch("custos.syslog_forwarder.socket.create_connection")
    def test_tcp_frames_bytes_not_character_count(self, connection):
        message = "用户".encode()
        send(message)
        connection.return_value.__enter__.return_value.sendall.assert_called_once_with(b"6 " + message)
