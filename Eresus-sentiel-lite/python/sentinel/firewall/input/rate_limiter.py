"""
Eresus Sentinel — Rate Limiter Scanner (Input)

Implements token-bucket + sliding-window rate limiting to prevent:
  - Request flooding
  - Token exhaustion
  - Cost overruns
  - Denial-of-service attacks

Features:
  - Per-user and global rate limiting
  - Request-based and token-based limits
  - Burst tolerance via multiplier
  - Configurable token estimation function
  - Sliding window (60 seconds default)
  - Hard block for violations
  - Usage tracking and reporting

Configurable rate limiting for LLM requests.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


@dataclass
class _BucketState:
    tokens: float = 0.0
    request_count: int = 0
    window_start: float = 0.0
    last_refill: float = 0.0


class RateLimiterScanner(InputScanner):
    """Token-bucket + sliding-window rate limiter for abuse protection."""

    def __init__(
        self,
        max_requests_per_minute: int = 60,
        max_tokens_per_minute: int = 100_000,
        burst_multiplier: float = 1.5,
        per_user: bool = True,
        estimate_tokens_fn=None,
    ):
        self._max_rpm = max_requests_per_minute
        self._max_tpm = max_tokens_per_minute
        self._burst_multiplier = burst_multiplier
        self._per_user = per_user
        self._estimate_tokens = estimate_tokens_fn or self._default_estimate
        self._buckets: dict[str, _BucketState] = defaultdict(_BucketState)
        self._global = _BucketState()

    @staticmethod
    def _default_estimate(text: str) -> int:
        return max(1, len(text) // 4)

    def scan(self, prompt: str, user_id: str = "__global__") -> ScanResult:
        if not prompt.strip():
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        now = time.monotonic()
        bucket = self._buckets[user_id] if self._per_user else self._global
        estimated_tokens = self._estimate_tokens(prompt)

        # Reset window if expired
        if now - bucket.window_start >= 60.0:
            bucket.request_count = 0
            bucket.tokens = 0.0
            bucket.window_start = now

        bucket.request_count += 1
        bucket.tokens += estimated_tokens

        findings = []
        risk = 0.0

        # Check request rate
        burst_rpm = int(self._max_rpm * self._burst_multiplier)
        if bucket.request_count > burst_rpm:
            risk = 1.0
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-080",
                title="Request rate limit exceeded (hard block)",
                description=f"{bucket.request_count} requests in window (burst limit: {burst_rpm})",
                severity=Severity.HIGH,
                target="<request>",
                evidence=f"RPM: {bucket.request_count}/{burst_rpm}",
                cwe_ids=["CWE-770"],
                tags=["rate_limit", "abuse"],
            ))
        elif bucket.request_count > self._max_rpm:
            risk = 0.7
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-081",
                title="Request rate limit exceeded (soft)",
                description=f"{bucket.request_count} requests in window (limit: {self._max_rpm})",
                severity=Severity.MEDIUM,
                target="<request>",
                evidence=f"RPM: {bucket.request_count}/{self._max_rpm}",
                cwe_ids=["CWE-770"],
                tags=["rate_limit"],
            ))

        # Check token rate
        if bucket.tokens > self._max_tpm * self._burst_multiplier:
            risk = max(risk, 1.0)
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-082",
                title="Token rate limit exceeded",
                description=f"{int(bucket.tokens)} tokens in window (limit: {self._max_tpm})",
                severity=Severity.HIGH,
                target="<request>",
                evidence=f"TPM: {int(bucket.tokens)}/{self._max_tpm}",
                cwe_ids=["CWE-770"],
                tags=["rate_limit", "token_budget"],
            ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        action = ScanAction.BLOCK if risk >= 1.0 else ScanAction.WARN
        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=risk,
            findings=findings,
        )

    def get_usage(self, user_id: str = "__global__") -> dict:
        bucket = self._buckets.get(user_id, self._global)
        return {
            "requests": bucket.request_count,
            "tokens": int(bucket.tokens),
            "max_rpm": self._max_rpm,
            "max_tpm": self._max_tpm,
        }

    def reset(self, user_id: Optional[str] = None) -> None:
        if user_id:
            self._buckets.pop(user_id, None)
        else:
            self._buckets.clear()
            self._global = _BucketState()
