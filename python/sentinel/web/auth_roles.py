"""Role enum and permission sets for Sentinel RBAC."""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


# Which permissions each role grants
ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset({
        "scan", "artifact",
        "users:read", "users:write",
        "config:read", "config:write",
    }),
    Role.ANALYST: frozenset({
        "scan", "artifact",
        "config:read",
    }),
    Role.READONLY: frozenset({
        "config:read",
    }),
}


def has_permission(role: Role, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
