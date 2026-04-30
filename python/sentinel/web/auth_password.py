"""Password hashing and verification — PBKDF2-HMAC-SHA256."""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 260_000
_DK_LEN = 32


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (hashed_hex, salt_hex). Generate salt when not given."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=_ITERATIONS,
        dklen=_DK_LEN,
    )
    return dk.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, hashed)
