"""FastAPI auth guards — extract and validate the current user."""
from __future__ import annotations

from fastapi import HTTPException, Request

from sentinel.web.auth_models import User
from sentinel.web.auth_roles import Role
from sentinel.web.auth_tokens import lookup_token


def get_current_user(request: Request) -> User:
    """Extract authenticated User from Bearer token. Raises 401/403."""
    state = request.app.state.sentinel_state  # type: ignore[attr-defined]
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required",
                            headers={"WWW-Authenticate": "Bearer"})
    token = auth[7:]
    user_id = lookup_token(state, token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    user = state.user_store.get_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User account inactive")
    return user


def require_admin(request: Request) -> User:
    user = get_current_user(request)
    if user.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def require_permission(permission: str):
    """Factory: returns a guard that checks a specific permission."""
    def _guard(request: Request) -> User:
        user = get_current_user(request)
        if not user.has_permission(permission):
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return user
    return _guard
