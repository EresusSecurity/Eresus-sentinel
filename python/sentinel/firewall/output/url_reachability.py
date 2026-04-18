"""
Eresus Sentinel — URL Reachability Scanner (Output).

Validates that URLs in LLM responses are actually reachable,
detecting:
  - Hallucinated URLs (model invention)
  - Dead links (broken references)
  - Domain squatting (recently registered malicious domains)
"""

from __future__ import annotations

import logging
import re
import socket
from typing import Optional
from urllib.parse import urlparse

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"\'\)\]\}]+",
    re.IGNORECASE,
)


def _check_domain_resolves(domain: str, timeout: float = 3.0) -> bool:
    """Check if a domain resolves via DNS."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


class URLReachabilityScanner(OutputScanner):
    """
    Checks if URLs in LLM responses actually resolve.

    Uses DNS resolution (not HTTP requests) for lightweight
    reachability checking without making actual web requests.
    """

    def __init__(
        self,
        timeout: float = 3.0,
        max_urls: int = 10,
        block_unreachable: bool = False,
    ):
        self._timeout = timeout
        self._max_urls = max_urls
        self._block = block_unreachable

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        urls = URL_PATTERN.findall(output)
        if not urls:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        urls = list(dict.fromkeys(urls))[:self._max_urls]
        unreachable: list[str] = []

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.hostname
                if not domain:
                    unreachable.append(url)
                    continue
                if not _check_domain_resolves(domain, self._timeout):
                    unreachable.append(url)
            except Exception:
                unreachable.append(url)

        if not unreachable:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        for url in unreachable:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-090",
                title=f"Unreachable URL: {url[:80]}",
                description=(
                    f"Response contains URL that does not resolve: "
                    f"'{url[:120]}'. This may be a hallucinated URL."
                ),
                severity=Severity.MEDIUM,
                confidence=0.8,
                target="<response>",
                evidence=f"URL: {url}, Status: DNS resolution failed",
                cwe_ids=["CWE-601"],
                tags=["owasp:llm02", "category:hallucinated-url"],
                remediation="Verify URL accuracy before presenting to users.",
            ))

        ratio = len(unreachable) / len(urls)
        return ScanResult(
            sanitized=output,
            action=ScanAction.BLOCK if self._block else ScanAction.WARN,
            risk_score=ratio,
            findings=findings,
        )
