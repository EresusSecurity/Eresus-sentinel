"""Stable API error envelope helpers for dashboard routes and middleware."""

from __future__ import annotations

from typing import Any

API_ERROR_SCHEMA_VERSION = "api.error.v1"


def api_error_payload(
    code: str,
    message: str,
    status_code: int,
    *,
    request_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": API_ERROR_SCHEMA_VERSION,
        "detail": message,
        "error": {
            "code": code,
            "message": message,
            "status": status_code,
        },
    }
    if request_id:
        payload["error"]["request_id"] = request_id
    if extra:
        payload["error"].update(extra)
    return payload
