"""AIBOM report sender — HTTP delivery with exponential backoff.

Ships a completed AI Bill of Materials (AIBOM) report to a remote ingestion
endpoint with retry semantics and optional TLS verification.

Ported and extended from the reference ``aibom`` project
(``src/aibom/report_sender.py``).

Usage::

    from sentinel.aibom.report_sender import post_report_with_retries

    payload = {"format": "spdx", "sbomVersion": "2.3", "components": [...]}
    status_code = post_report_with_retries(
        url="https://ingestion.example.com/aibom",
        payload=payload,
        api_key="<tenant-api-key>",
    )
"""

from __future__ import annotations

import logging
import math
import random
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# HTTP status codes that warrant an automatic retry
RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

# Auth header used by the Cisco AI Defense tenant API
_AUTH_HEADER = "x-cisco-ai-defense-tenant-api-key"


def post_report_with_retries(
    url: str,
    payload: dict[str, Any],
    *,
    api_key: str = "",
    verify_tls: bool = True,
    timeout_seconds: float = 30.0,
    max_attempts: int = 5,
    base_backoff: float = 1.0,
    max_backoff: float = 30.0,
    extra_headers: Optional[dict[str, str]] = None,
    logger_: Optional[logging.Logger] = None,
) -> int:
    """POST *payload* to *url* with exponential back-off retry.

    Args:
        url: Remote ingestion endpoint URL.
        payload: Dictionary that will be serialised to JSON.
        api_key: Tenant API key placed in ``x-cisco-ai-defense-tenant-api-key``.
            Falls back to ``SENTINEL_AIBOM_API_KEY`` environment variable.
        verify_tls: Set to ``False`` to disable TLS certificate verification
            (not recommended in production).
        timeout_seconds: Per-request connect+read timeout.
        max_attempts: Maximum number of POST attempts before giving up.
        base_backoff: Initial backoff duration in seconds.
        max_backoff: Maximum cap on backoff duration in seconds.
        extra_headers: Additional HTTP headers merged into every request.
        logger_: Optional logger override (defaults to module logger).

    Returns:
        The HTTP status code from the last response.

    Raises:
        RuntimeError: If ``httpx`` is not installed.
        ValueError: If *url* is empty.
        Exception: Network or TLS errors from the final attempt are re-raised.
    """
    import os

    try:
        import httpx  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError("httpx is required: pip install httpx") from exc

    log = logger_ or logger

    if not url:
        raise ValueError("url must not be empty")

    resolved_key = api_key or os.environ.get("SENTINEL_AIBOM_API_KEY", "")

    headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if resolved_key:
        headers[_AUTH_HEADER] = resolved_key
    if extra_headers:
        headers.update(extra_headers)

    last_status: int = 0
    last_exc: Optional[Exception] = None

    for attempt in range(1, max_attempts + 1):
        try:
            resp = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout_seconds,
                verify=verify_tls,
            )
            last_status = resp.status_code
            last_exc = None

            if resp.is_success:
                log.info("AIBOM report delivered (attempt %d, HTTP %d)", attempt, last_status)
                return last_status

            if last_status not in RETRYABLE_STATUS_CODES:
                log.error(
                    "AIBOM delivery failed (attempt %d, HTTP %d — non-retryable): %s",
                    attempt,
                    last_status,
                    resp.text[:200],
                )
                return last_status

            log.warning(
                "AIBOM delivery got HTTP %d (attempt %d/%d), will retry",
                last_status,
                attempt,
                max_attempts,
            )

            if attempt < max_attempts:
                wait = _backoff_seconds(
                    attempt=attempt,
                    base=base_backoff,
                    cap=max_backoff,
                    retry_after=_parse_retry_after(resp),
                )
                log.debug("Waiting %.2fs before retry", wait)
                time.sleep(wait)

        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            log.warning("AIBOM delivery network error (attempt %d/%d): %s", attempt, max_attempts, exc)
            if attempt < max_attempts:
                wait = _backoff_seconds(attempt=attempt, base=base_backoff, cap=max_backoff)
                time.sleep(wait)

    if last_exc is not None:
        raise last_exc

    log.error("AIBOM delivery failed after %d attempts (last HTTP %d)", max_attempts, last_status)
    return last_status


async def post_report_async(
    url: str,
    payload: dict[str, Any],
    *,
    api_key: str = "",
    verify_tls: bool = True,
    timeout_seconds: float = 30.0,
    extra_headers: Optional[dict[str, str]] = None,
) -> int:
    """Async variant — fire-and-forget without retry logic.

    For full retry semantics in async code, wrap in an ``asyncio.Task`` and
    call ``post_report_with_retries`` in a thread pool executor.
    """
    import os

    try:
        import httpx  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError("httpx is required: pip install httpx") from exc

    resolved_key = api_key or os.environ.get("SENTINEL_AIBOM_API_KEY", "")

    headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if resolved_key:
        headers[_AUTH_HEADER] = resolved_key
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(verify=verify_tls, timeout=timeout_seconds) as client:
        resp = await client.post(url, json=payload, headers=headers)
        return resp.status_code


# ── helpers ──────────────────────────────────────────────────────────


def _backoff_seconds(
    attempt: int,
    base: float = 1.0,
    cap: float = 30.0,
    retry_after: Optional[float] = None,
) -> float:
    """Exponential backoff with full jitter, optionally honouring Retry-After."""
    if retry_after is not None and retry_after > 0:
        return min(retry_after, cap)
    ceiling = min(cap, base * math.pow(2.0, attempt - 1))
    return random.uniform(0, ceiling)  # noqa: S311  (non-cryptographic)


def _parse_retry_after(response: Any) -> Optional[float]:
    """Extract numeric seconds from a Retry-After header, if present."""
    value = getattr(getattr(response, "headers", None), "get", lambda *a: None)("Retry-After")
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None
