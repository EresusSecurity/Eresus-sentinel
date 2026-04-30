"""User dataclass — single source of truth for user records."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from sentinel.web.auth_roles import Role, has_permission


@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    salt: str
    role: Role
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    is_active: bool = True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role.value,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "is_active": self.is_active,
        }

    def has_permission(self, permission: str) -> bool:
        return self.is_active and has_permission(self.role, permission)
