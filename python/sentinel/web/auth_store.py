"""In-memory user store with optional admin seeding from env."""
from __future__ import annotations

import os
import re
import uuid
from typing import Optional

from sentinel.web.auth_models import User
from sentinel.web.auth_password import hash_password, verify_password
from sentinel.web.auth_roles import Role

# Allowlist: alphanumeric, underscore, hyphen only — prevents log injection and special-char attacks
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_MIN_PASSWORD_LEN = 8


def _validate_password(password: str) -> None:
    """Enforce password strength: min 8 chars, upper+lower+digit."""
    if len(password) < _MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LEN} characters")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")


class UserStore:
    """Thread-safe in-memory user store."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}   # id -> User
        self._by_name: dict[str, str] = {}  # username -> id
        self._seed_admin()

    # ── Seeding ────────────────────────────────────────────────

    def _seed_admin(self) -> None:
        username = os.environ.get("SENTINEL_USER", "admin")
        password = os.environ.get("SENTINEL_PASSWORD", "")
        if not password or username in self._by_name:
            return
        self.create_user(username, password, Role.ADMIN)

    # ── CRUD ───────────────────────────────────────────────────

    def create_user(self, username: str, password: str, role: Role = Role.ANALYST) -> User:
        if not _USERNAME_RE.match(username):
            raise ValueError("Username must be 1–64 alphanumeric/underscore/hyphen characters")
        _validate_password(password)
        if username in self._by_name:
            raise ValueError(f"User '{username}' already exists")
        hashed, salt = hash_password(password)
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=hashed,
            salt=salt,
            role=role,
        )
        self._users[user.id] = user
        self._by_name[username] = user.id
        return user

    def verify(self, username: str, password: str) -> Optional[User]:
        uid = self._by_name.get(username)
        if not uid:
            return None
        user = self._users.get(uid)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password, user.salt):
            return None
        import time as _t
        user.last_login = _t.time()
        return user

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)

    def get_by_username(self, username: str) -> Optional[User]:
        uid = self._by_name.get(username)
        return self._users.get(uid) if uid else None

    def list_users(self) -> list[User]:
        return list(self._users.values())

    def delete_user(self, user_id: str) -> bool:
        user = self._users.pop(user_id, None)
        if user:
            self._by_name.pop(user.username, None)
            return True
        return False

    def update_password(self, user_id: str, new_password: str) -> bool:
        user = self._users.get(user_id)
        if not user:
            return False
        _validate_password(new_password)
        user.hashed_password, user.salt = hash_password(new_password)
        return True

    def update_role(self, user_id: str, role: Role) -> bool:
        user = self._users.get(user_id)
        if not user:
            return False
        user.role = role
        return True
