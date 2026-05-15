import os
import time

from fastapi import APIRouter, HTTPException, Request

from sentinel.web.auth_guards import get_current_user
from sentinel.web.auth_roles import Role
from sentinel.web.auth_tokens import issue_token, revoke_token
from sentinel.web.state import LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW, TOKEN_TTL, AppState

router = APIRouter(prefix="/api/auth", tags=["auth"])

_state: AppState = None


def init(state: AppState):
    global _state
    _state = state


def _signup_enabled() -> bool:
    return os.environ.get("SENTINEL_ALLOW_SIGNUP", "").strip().lower() in {"1", "true", "yes", "on"}


@router.post("/login")
async def login(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = _state.login_attempts.get(client_ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Retry after {LOGIN_WINDOW}s.",
        )
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    username = str(data.get("username", ""))[:64]
    password = str(data.get("password", ""))[:512]

    user = _state.user_store.verify(username, password)
    if user is None:
        attempts.append(now)
        _state.login_attempts[client_ip] = attempts
        raise HTTPException(status_code=401, detail="Invalid credentials")

    _state.login_attempts.pop(client_ip, None)
    token = issue_token(_state, user.id, TOKEN_TTL)
    return {
        "token": token,
        "user": user.username,
        "role": user.role.value,
        "expires_in": int(TOKEN_TTL),
    }


@router.post("/signup")
async def signup(request: Request):
    if not _signup_enabled():
        raise HTTPException(status_code=403, detail="Signup is disabled")
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    username = str(data.get("username", ""))[:64]
    password = str(data.get("password", ""))[:512]
    role = Role.ADMIN if _state.user_store.user_count() == 0 else Role.ANALYST
    try:
        user = _state.user_store.create_user(username, password, role)
    except ValueError as exc:
        message = str(exc)
        if "already exists" in message:
            raise HTTPException(status_code=409, detail=message)
        raise HTTPException(status_code=400, detail=message)

    token = issue_token(_state, user.id, TOKEN_TTL)
    return {
        "token": token,
        "user": user.username,
        "role": user.role.value,
        "expires_in": int(TOKEN_TTL),
    }


@router.post("/logout")
async def logout(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        revoke_token(_state, auth[7:])
    return {"ok": True}


@router.get("/me")
async def whoami(request: Request):
    request.app.state.sentinel_state = _state
    user = get_current_user(request)
    return user.to_dict()
