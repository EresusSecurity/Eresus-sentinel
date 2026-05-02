"""Shared network timeout and retry contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetryConfig:
    timeout_seconds: float = 15.0
    max_retries: int = 2
    backoff_seconds: float = 0.25
    retry_statuses: tuple[int, ...] = (408, 429, 500, 502, 503, 504)

    def delay_for_attempt(self, attempt: int) -> float:
        """Return exponential backoff delay for a zero-based attempt."""
        if attempt <= 0:
            return 0.0
        return self.backoff_seconds * (2 ** (attempt - 1))

    def should_retry_status(self, status_code: int, attempt: int) -> bool:
        """Return whether an HTTP status should be retried for this attempt."""
        return attempt < self.max_retries and status_code in self.retry_statuses


DEFAULT_RETRY_CONFIG = RetryConfig()
