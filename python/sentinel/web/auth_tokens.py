"""Token issuance, lookup and revocation — operates on AppState.valid_tokens."""
from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sentinel.web.state import AppState

TOKEN_BYTES = 32  # 64-char hex token


def issue_token(state: "AppState", user_id: str, ttl: float) -> str:
    """Generate a new token and store (user_id, expiry) in state."""
    token = secrets.token_hex(TOKEN_BYTES)
    state.valid_tokens[token] = (user_id, time.time() + ttl)
    return token


def lookup_token(state: "AppState", token: str) -> Optional[str]:
    """Return user_id if token is valid, else None. Prunes expired entry."""
    entry = state.valid_tokens.get(token)
    if entry is None:
        return None
    user_id, expiry = entry
    if time.time() > expiry:
        state.valid_tokens.pop(token, None)
        return None
    return user_id


def revoke_token(state: "AppState", token: str) -> None:
    state.valid_tokens.pop(token, None)


def revoke_all_for_user(state: "AppState", user_id: str) -> int:
    """Remove every token belonging to user_id. Returns count removed."""
    victims = [t for t, (uid, _) in state.valid_tokens.items() if uid == user_id]
    for t in victims:
        state.valid_tokens.pop(t, None)
    return len(victims)
