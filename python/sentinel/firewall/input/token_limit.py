"""
Eresus Sentinel — Token Limit Scanner.

Enforces maximum token limits on input prompts to prevent:
  - Denial of service via extremely long prompts
  - Context window exhaustion attacks
  - Cost amplification attacks
"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


def _estimate_tokens(text: str) -> int:
    """
    Estimate token count using whitespace + punctuation heuristic.
    Approximates ~1.3 tokens per word for English text.
    """
    words = text.split()
    word_count = len(words)
    punct_count = sum(1 for c in text if c in '.,;:!?()[]{}"-\'')
    return int(word_count * 1.3 + punct_count * 0.5)


class TokenLimitScanner(InputScanner):
    """
    Enforces maximum token count on input prompts.

    Uses a fast heuristic token estimator (no tokenizer dependency).
    For exact counting, set use_tiktoken=True if tiktoken is installed.
    """

    def __init__(
        self,
        max_tokens: int = 4096,
        warn_tokens: int = 0,
        encoding: str = "cl100k_base",
    ):
        """
        Args:
            max_tokens: Maximum allowed tokens (block above this).
            warn_tokens: Warning threshold (0 = disabled).
            encoding: tiktoken encoding name (only used if tiktoken available).
        """
        self._max_tokens = max_tokens
        self._warn_tokens = warn_tokens or int(max_tokens * 0.8)
        self._encoder = None

        try:
            import sys
            # tiktoken 0.12.0 segfaults on Python 3.14 (SIGSEGV in CoreBPE.__new__)
            if sys.version_info >= (3, 14):
                raise ImportError("tiktoken crashes on Python 3.14+")
            import tiktoken
            self._encoder = tiktoken.get_encoding(encoding)
        except (ImportError, Exception):
            pass

    def _count_tokens(self, text: str) -> int:
        """Count tokens using tiktoken or heuristic fallback."""
        if self._encoder:
            return len(self._encoder.encode(text))
        return _estimate_tokens(text)

    def scan(self, prompt: str) -> ScanResult:
        if not prompt:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        token_count = self._count_tokens(prompt)

        if token_count > self._max_tokens:
            finding = Finding.firewall_input(
                rule_id="FIREWALL-INPUT-090",
                title=f"Token limit exceeded: {token_count}/{self._max_tokens}",
                description=(
                    f"Input contains approximately {token_count} tokens, "
                    f"exceeding the maximum allowed limit of {self._max_tokens}. "
                    f"This may indicate a denial-of-service or context "
                    f"exhaustion attack."
                ),
                severity=Severity.HIGH,
                confidence=0.95,
                target="<prompt>",
                evidence=f"Tokens: {token_count}, Limit: {self._max_tokens}",
                cwe_ids=["CWE-400"],
                tags=["owasp:llm04", "category:dos"],
                remediation=(
                    f"Reduce input to under {self._max_tokens} tokens."
                ),
            )
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.BLOCK,
                risk_score=0.95,
                findings=[finding],
            )

        if token_count > self._warn_tokens:
            finding = Finding.firewall_input(
                rule_id="FIREWALL-INPUT-091",
                title=f"Token count high: {token_count}/{self._max_tokens}",
                description=(
                    f"Input contains approximately {token_count} tokens, "
                    f"approaching the limit of {self._max_tokens}."
                ),
                severity=Severity.LOW,
                confidence=0.7,
                target="<prompt>",
                evidence=f"Tokens: {token_count}, Warn: {self._warn_tokens}",
                cwe_ids=["CWE-400"],
                tags=["owasp:llm04", "category:dos-warning"],
                remediation="Consider shortening the input.",
            )
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.WARN,
                risk_score=0.4,
                findings=[finding],
            )

        return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)
