from datetime import datetime, timedelta, timezone
import os
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from ldap3.core.exceptions import LDAPBindError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from custos.database import Base, Directory, DirectorySyncConfig, Principal
from custos.directory_auth import authenticate_directory


class DirectoryAuthTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        self.db = Session(engine)
        self.addCleanup(engine.dispose)
        self.addCleanup(self.db.close)
        self.directory = Directory(id="ad", name="AD", endpoint="ldaps://ad.test",
            base_dn="dc=test", credential_ref="env:TEST_AD_SECRET", last_success_at=datetime.now(timezone.utc))
        self.db.add(self.directory)
        self.db.flush()
        self.db.add(DirectorySyncConfig(directory_id="ad", bind_username="sync@test", kind="ad",
            user_filter="(memberOf=cn=Custos,dc=test)", group_filter="(cn=Custos)", max_entries=100))
        self.user = Principal(id="user", directory_id="ad", external_id=str(UUID(int=1)),
                              kind="user", display_name="Alice")
        self.db.add(self.user)
        self.db.commit()

    def lookup(self):
        return Mock(result={"result": 0}, response=[{"type": "searchResEntry",
            "dn": "cn=Alice,dc=test", "raw_attributes": {"objectGUID": [UUID(int=1).bytes_le]}}])

    @patch.dict(os.environ, {"TEST_AD_SECRET": "sync-secret"})
    @patch("custos.directory_auth.Connection")
    def test_verified_guid_mapping_and_escaped_scope(self, factory):
        lookup, verified = self.lookup(), Mock(bound=True)
        factory.side_effect = [lookup, verified]
        result = authenticate_directory(self.db, "ad", "alice*)(uid=*)", "injected-password")
        self.assertEqual(result.id, "user")
        query = lookup.search.call_args.args[1]
        self.assertIn("memberOf=cn=Custos", query)
        self.assertIn(r"alice\2a\29\28uid=\2a\29", query)
        self.assertEqual(factory.call_args.kwargs["user"], "cn=Alice,dc=test")
        self.assertEqual(factory.call_args.kwargs["password"], "injected-password")
        lookup.unbind.assert_called_once()
        verified.unbind.assert_called_once()

    @patch.dict(os.environ, {"TEST_AD_SECRET": "sync-secret"})
    @patch("custos.directory_auth.Connection")
    def test_wrong_password_does_not_authenticate(self, factory):
        factory.side_effect = [self.lookup(), LDAPBindError("private provider message")]
        self.assertIsNone(authenticate_directory(self.db, "ad", "alice", "wrong"))

    @patch("custos.directory_auth.Connection")
    def test_blank_password_and_stale_sync_do_not_bind(self, factory):
        self.assertIsNone(authenticate_directory(self.db, "ad", "alice", ""))
        self.directory.last_success_at = datetime.now(timezone.utc) - timedelta(hours=1)
        self.assertIsNone(authenticate_directory(self.db, "ad", "alice", "password"))
        factory.assert_not_called()

    @patch.dict(os.environ, {"TEST_AD_SECRET": "sync-secret"})
    @patch("custos.directory_auth.Connection")
    def test_unsynced_or_disabled_user_denied(self, factory):
        self.user.enabled = False
        factory.return_value = self.lookup()
        self.assertIsNone(authenticate_directory(self.db, "ad", "alice", "password"))
        self.assertEqual(factory.call_count, 1)
