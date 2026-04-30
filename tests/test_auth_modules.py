"""Unit tests for the split auth modules."""
import time
import unittest

from sentinel.web.auth_roles import Role, has_permission
from sentinel.web.auth_password import hash_password, verify_password
from sentinel.web.auth_models import User
from sentinel.web.auth_store import UserStore


class TestRoles(unittest.TestCase):
    def test_admin_has_all_permissions(self):
        for perm in ("scan", "artifact", "users:read", "users:write", "config:write"):
            self.assertTrue(has_permission(Role.ADMIN, perm))

    def test_readonly_limited(self):
        self.assertFalse(has_permission(Role.READONLY, "scan"))
        self.assertTrue(has_permission(Role.READONLY, "config:read"))

    def test_unknown_permission_false(self):
        self.assertFalse(has_permission(Role.ADMIN, "nonexistent:perm"))


class TestPassword(unittest.TestCase):
    def test_roundtrip(self):
        hashed, salt = hash_password("correct-horse-battery-staple")
        self.assertTrue(verify_password("correct-horse-battery-staple", hashed, salt))
        self.assertFalse(verify_password("wrong-password", hashed, salt))

    def test_unique_salt(self):
        _, s1 = hash_password("same")
        _, s2 = hash_password("same")
        self.assertNotEqual(s1, s2)


class TestUserStore(unittest.TestCase):
    def setUp(self):
        import os
        os.environ["SENTINEL_PASSWORD"] = "AdminPass123"
        os.environ["SENTINEL_USER"] = "admin"
        self.store = UserStore()

    def test_admin_seeded(self):
        user = self.store.get_by_username("admin")
        self.assertIsNotNone(user)
        self.assertEqual(user.role, Role.ADMIN)

    def test_verify_correct(self):
        user = self.store.verify("admin", "AdminPass123")
        self.assertIsNotNone(user)

    def test_verify_wrong(self):
        self.assertIsNone(self.store.verify("admin", "wrongpass"))

    def test_create_and_delete(self):
        user = self.store.create_user("alice", "AlicePass123", Role.ANALYST)
        self.assertIsNotNone(self.store.get_by_id(user.id))
        self.assertTrue(self.store.delete_user(user.id))
        self.assertIsNone(self.store.get_by_id(user.id))

    def test_duplicate_username_raises(self):
        self.store.create_user("bob", "BobPass123", Role.READONLY)
        with self.assertRaises(ValueError):
            self.store.create_user("bob", "BobPass456", Role.READONLY)

    def test_short_password_raises(self):
        with self.assertRaises(ValueError):
            self.store.create_user("charlie", "short", Role.ANALYST)

    def test_update_password(self):
        user = self.store.create_user("dave", "DavePass123", Role.ANALYST)
        self.store.update_password(user.id, "NewDavePass456")
        self.assertIsNotNone(self.store.verify("dave", "NewDavePass456"))
        self.assertIsNone(self.store.verify("dave", "DavePass123"))

    def test_update_role(self):
        user = self.store.create_user("eve", "EvePass123", Role.READONLY)
        self.store.update_role(user.id, Role.ANALYST)
        self.assertEqual(self.store.get_by_id(user.id).role, Role.ANALYST)


class TestTokens(unittest.TestCase):
    def _make_state(self):
        class FakeState:
            valid_tokens = {}
        return FakeState()

    def test_issue_and_lookup(self):
        from sentinel.web.auth_tokens import issue_token, lookup_token
        state = self._make_state()
        token = issue_token(state, "user-123", ttl=3600)
        self.assertEqual(lookup_token(state, token), "user-123")

    def test_expired_token(self):
        from sentinel.web.auth_tokens import issue_token, lookup_token
        state = self._make_state()
        token = issue_token(state, "user-456", ttl=-1)  # already expired
        self.assertIsNone(lookup_token(state, token))

    def test_revoke_all(self):
        from sentinel.web.auth_tokens import issue_token, revoke_all_for_user, lookup_token
        state = self._make_state()
        t1 = issue_token(state, "u1", 3600)
        t2 = issue_token(state, "u1", 3600)
        revoke_all_for_user(state, "u1")
        self.assertIsNone(lookup_token(state, t1))
        self.assertIsNone(lookup_token(state, t2))
