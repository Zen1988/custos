from datetime import datetime, timezone
import os
import ssl
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from custos.database import Base, Directory, DirectorySyncConfig, GroupMember, LocalCredential, Principal
from custos.directory_sync import Identity, Snapshot, SyncError, apply_snapshot, fetch_snapshot
from custos.local_identity import authenticate_local, create_local_user


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.db.close)
        self.directory = Directory(id="ad", name="AD", endpoint="ldaps://ad.test", base_dn="dc=test",
                                   credential_ref="env:TEST_BIND_PASSWORD", enabled=True)
        self.db.add(self.directory)
        self.db.commit()

    def snapshot(self):
        return Snapshot((Identity("user", "user", "Alice"), Identity("group", "group", "Team")),
                        frozenset({("group", "user")}))

    def test_upsert_rename_and_membership_revocation(self):
        apply_snapshot(self.db, "ad", self.snapshot())
        self.db.commit()
        principal = self.db.scalar(select(Principal).where(Principal.external_id == "user"))
        original_id = principal.id
        apply_snapshot(self.db, "ad", Snapshot((Identity("user", "user", "Renamed"),), frozenset()))
        self.db.commit()
        self.assertEqual(principal.id, original_id)
        self.assertEqual(principal.display_name, "Renamed")
        self.assertEqual(list(self.db.scalars(select(GroupMember))), [])
        self.assertFalse(self.db.scalar(select(Principal).where(Principal.external_id == "group")).enabled)

    def test_empty_guard_and_transaction_rollback(self):
        apply_snapshot(self.db, "ad", self.snapshot())
        self.db.commit()
        with self.assertRaises(SyncError):
            apply_snapshot(self.db, "ad", Snapshot((), frozenset()))
        self.db.rollback()
        apply_snapshot(self.db, "ad", Snapshot((), frozenset()), allow_empty=True)
        self.db.rollback()
        self.assertTrue(all(p.enabled for p in self.db.scalars(select(Principal))))

    def test_local_auth_and_directory_sync_isolation(self):
        user = create_local_user(self.db, "Admin", "Local Admin", "a long test password")
        self.db.commit()
        credential = self.db.get(LocalCredential, user.id)
        self.assertNotIn("a long test password", credential.password_hash)
        self.assertEqual(authenticate_local(self.db, "ADMIN", "a long test password").id, user.id)
        self.assertIsNone(authenticate_local(self.db, "admin", "incorrect"))
        self.assertIsNone(authenticate_local(self.db, "unknown", "a long test password"))
        apply_snapshot(self.db, "ad", self.snapshot())
        self.db.commit()
        self.assertTrue(user.enabled)
        user.enabled = False
        self.assertIsNone(authenticate_local(self.db, "admin", "a long test password"))

    def test_invalid_membership_rejected_before_writes(self):
        with self.assertRaises(SyncError):
            apply_snapshot(self.db, "ad", Snapshot(self.snapshot().identities,
                                                   frozenset({("missing", "user")})))
        self.assertEqual(list(self.db.scalars(select(Principal))), [])

    def config(self):
        return DirectorySyncConfig(directory_id="ad", bind_username="svc@test", kind="ad",
                                   user_filter="(sAMAccountName=alice)", group_filter="(cn=Team)", max_entries=100)

    def entry(self, number, dn, name):
        return {"type": "searchResEntry", "dn": dn, "raw_attributes": {
            "objectGUID": [UUID(int=number).bytes_le], "cn": [name.encode()]}}

    @patch.dict(os.environ, {"TEST_BIND_PASSWORD": "private-password"})
    @patch("custos.directory_sync.Tls")
    @patch("custos.directory_sync.Server")
    @patch("custos.directory_sync.Connection")
    def test_scoped_queries_and_tls(self, connection_factory, server, tls):
        connection = connection_factory.return_value
        user = self.entry(1, "cn=Alice,dc=test", "Alice")
        group = self.entry(2, "cn=Team,dc=test", "Team")
        pages = iter([[user], [group], [user]])
        def search(*args, **kwargs):
            connection.response = next(pages)
            connection.result = {"result": 0, "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b""}}}}
        connection.search.side_effect = search
        result = fetch_snapshot(self.directory, self.config())
        self.assertEqual(len(result.identities), 2)
        self.assertEqual(len(result.memberships), 1)
        self.assertEqual(tls.call_args.kwargs["validate"], ssl.CERT_REQUIRED)
        self.assertFalse(connection_factory.call_args.kwargs["auto_referrals"])
        self.assertTrue(connection_factory.call_args.kwargs["read_only"])
        for call in connection.search.call_args_list:
            self.assertIn("dc=test", call.args)
        self.assertIn("sAMAccountName=alice", connection.search.call_args_list[2].args[1])
        connection.unbind.assert_called_once()

    @patch.dict(os.environ, {"TEST_BIND_PASSWORD": "private-password"})
    @patch("custos.directory_sync.Connection")
    def test_failed_search_never_publishes(self, factory):
        factory.return_value.result = {"result": 4}
        with self.assertRaises(SyncError):
            fetch_snapshot(self.directory, self.config())
        self.assertIsNone(self.directory.last_success_at)

    def test_insecure_origin_rejected(self):
        self.directory.endpoint = "http://ad.test"
        with self.assertRaises(SyncError):
            fetch_snapshot(self.directory, self.config())
