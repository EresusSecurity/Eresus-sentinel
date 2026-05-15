"""Security middleware for the Sentinel dashboard."""

import time
from contextlib import suppress

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel.web.api_errors import api_error_payload
from sentinel.web.state import RATE_LIMIT_BURST, RATE_LIMIT_RPS

# ── Token Bucket Rate Limiter ──────────────────────────────────

class TokenBucketRateLimiter:
    """Per-IP token bucket rate limiter."""

    def __init__(self, rate: float = RATE_LIMIT_RPS, burst: int = RATE_LIMIT_BURST):
        self.rate = rate
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(ip, (float(self.burst), now))
        elapsed = now - last
        tokens = min(self.burst, tokens + elapsed * self.rate)
        if tokens >= 1.0:
            self._buckets[ip] = (tokens - 1.0, now)
            return True
        self._buckets[ip] = (tokens, now)
        return False

    def cleanup(self, max_age: float = 300):
        now = time.monotonic()
        self._buckets = {
            ip: (t, ts) for ip, (t, ts) in self._buckets.items()
            if now - ts < max_age
        }


# Shared instance
rate_limiter = TokenBucketRateLimiter()
_last_cleanup = time.monotonic()


# ── Security Headers ───────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        is_https = _is_https_request(request)
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'"
        )
        if is_https:
            csp += "; upgrade-insecure-requests"
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        with suppress(KeyError):
            del response.headers["server"]
        return response


def _is_https_request(request: Request) -> bool:
    """Return true for direct HTTPS or trusted HTTPS proxy headers."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return request.url.scheme == "https" or forwarded_proto.split(",", 1)[0].strip() == "https"


# ── Rate Limit ─────────────────────────────────────────────────

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        global _last_cleanup
        if request.url.path.startswith("/assets/"):
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.allow(client_ip):
            return JSONResponse(
                status_code=429,
                content=api_error_payload(
                    "rate_limit_exceeded",
                    "Rate limit exceeded. Try again later.",
                    429,
                ),
                headers={"Retry-After": "1"},
            )
        now = time.monotonic()
        if now - _last_cleanup > 300:
            rate_limiter.cleanup()
            _last_cleanup = now
        return await call_next(request)


# ── Auth ───────────────────────────────────────────────────────

_PUBLIC_PATHS = {
    "/api/auth/login",
    "/api/auth/signup",
    "/api/health",
    "/health",
    "/api/docs",
    "/api/openapi.json",
}


def create_auth_middleware(state):
    """Create auth middleware that closes over AppState."""
    from sentinel.web.auth_tokens import lookup_token

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            path = request.url.path
            if path.startswith("/assets/") or path in _PUBLIC_PATHS:
                return await call_next(request)
            if path == "/" or not path.startswith("/api/"):
                return await call_next(request)
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return JSONResponse(
                    status_code=401,
                    content=api_error_payload("auth_required", "Authentication required", 401),
                    headers={"WWW-Authenticate": "Bearer"},
                )
            token = auth[7:]
            user_id = lookup_token(state, token)
            if user_id is None:
                return JSONResponse(
                    status_code=401,
                    content=api_error_payload("invalid_token", "Invalid or expired token", 401),
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Attach state so route guards can resolve the user
            request.app.state.sentinel_state = state
            return await call_next(request)

    return AuthMiddleware
