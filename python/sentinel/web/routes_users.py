"""User management routes — admin-only CRUD for /api/users."""

from fastapi import APIRouter, HTTPException, Request

from sentinel.web.auth_guards import get_current_user, require_admin
from sentinel.web.auth_roles import Role
from sentinel.web.auth_tokens import revoke_all_for_user
from sentinel.web.state import AppState

router = APIRouter(prefix="/api/users", tags=["users"])

_state: AppState = None  # type: ignore[assignment]


def init(state: AppState):
    global _state
    _state = state


def _attach(request: Request) -> None:
    """Attach state to app.state so guards can find it."""
    request.app.state.sentinel_state = _state


@router.get("")
async def list_users(request: Request):
    _attach(request)
    require_admin(request)
    return [u.to_dict() for u in _state.user_store.list_users()]


@router.post("")
async def create_user(request: Request):
    _attach(request)
    require_admin(request)
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    username = str(data.get("username", ""))[:64]
    password = str(data.get("password", ""))[:512]
    role_str = str(data.get("role", Role.ANALYST.value))

    try:
        role = Role(role_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown role: {role_str!r}")

    try:
        user = _state.user_store.create_user(username, password, role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return user.to_dict()


@router.delete("/{user_id}")
async def delete_user(user_id: str, request: Request):
    _attach(request)
    admin = require_admin(request)
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if not _state.user_store.delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    revoke_all_for_user(_state, user_id)
    return {"ok": True}


@router.put("/{user_id}/password")
async def change_password(user_id: str, request: Request):
    _attach(request)
    requester = get_current_user(request)
    if requester.id != user_id and requester.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Forbidden")

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    new_password = str(data.get("password", ""))[:512]
    try:
        ok = _state.user_store.update_password(user_id, new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not ok:
        raise HTTPException(status_code=404, detail="User not found")

    revoke_all_for_user(_state, user_id)  # force re-login
    return {"ok": True}


@router.put("/{user_id}/role")
async def change_role(user_id: str, request: Request):
    _attach(request)
    require_admin(request)

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    role_str = str(data.get("role", ""))
    try:
        role = Role(role_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown role: {role_str!r}")

    if not _state.user_store.update_role(user_id, role):
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}
