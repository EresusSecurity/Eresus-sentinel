"""
Eresus Sentinel — Agent Outbound Request Validator.

Validates URLs and domains in agent tool calls to prevent:
  - Weaponized agents as DoS proxies/bots
  - Data exfiltration via outbound requests
  - SSRF (Server-Side Request Forgery) via tool calls
  - Scanning/reconnaissance of remote hosts
  - Access to internal/private network resources

Research basis:
  "Security of AI Agents" (arXiv:2406.08689v2)
  - §3.3.2: AI agents can be weaponized for remote attacks via jailbreak
  - §4.2: Sandbox must restrict both local and remote resource access
  - Agents following LLM-generated actions behave like human users,
    making DDoS/scraping hard to detect

Validation layers:
  1. Domain allowlist/denylist enforcement
  2. Private/internal IP detection (RFC1918, loopback, link-local)
  3. SSRF pattern detection (cloud metadata, internal services)
  4. Rate-based anomaly detection (burst requests to same host)
  5. Suspicious port/protocol detection
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── SSRF targets (cloud metadata endpoints) ─────────────────────────

SSRF_TARGETS = [
    # AWS
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    # Azure
    "169.254.169.254",
    # GCP
    "metadata.google.internal",
    "computeMetadata",
    # DigitalOcean
    "169.254.169.254",
    # Alibaba Cloud
    "100.100.100.200",
    # Oracle Cloud
    "169.254.169.254",
    # Generic
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "[::1]",
]

# ── Suspicious ports ────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# ── Dangerous URL schemes ───────────────────────────────────────────

DANGEROUS_SCHEMES = {
    "file": "Local file access",
    "gopher": "Protocol smuggling",
    "dict": "Dictionary service probing",
    "ftp": "FTP access",
    "ldap": "LDAP query",
    "tftp": "TFTP access",
    "jar": "Java archive access",
}


@dataclass
class OutboundRequest:
    """Represents a parsed outbound request from an agent tool call."""
    url: str
    domain: str = ""
    ip: str = ""
    port: int = 0
    scheme: str = ""
    path: str = ""
    tool_name: str = ""
    timestamp: float = 0.0


@dataclass
class ValidationResult:
    """Result of outbound request validation."""
    allowed: bool = True
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    reason: str = ""


class OutboundValidator:
    """
    Validates outbound URLs/domains in agent tool calls.

    Prevents weaponization of AI agents as attack proxies by enforcing:
    - Domain allowlists/denylists
    - Private network blocking
    - SSRF detection
    - Rate limiting per host
    - Protocol/port restrictions
    """

    def __init__(
        self,
        allowed_domains: list[str] | None = None,
        denied_domains: list[str] | None = None,
        block_private: bool = True,
        max_requests_per_host: int = 20,
        window_seconds: int = 60,
    ):
        self._allowed = set(allowed_domains) if allowed_domains else None
        self._denied = set(denied_domains or [])
        self._block_private = block_private
        self._max_per_host = max_requests_per_host
        self._window = window_seconds
        self._request_log: dict[str, list[float]] = defaultdict(list)

    def validate_url(
        self, url: str, tool_name: str = "", source: str = "<agent>"
    ) -> ValidationResult:
        """Validate a single outbound URL from an agent tool call."""
        result = ValidationResult()
        findings: list[Finding] = []

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            findings.append(Finding.agent_mcp(
                rule_id="AGENT-OUT-001",
                title="Malformed outbound URL",
                description=f"Agent tool '{tool_name}' produced a malformed URL: {url[:200]}",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"url={url[:200]}, tool={tool_name}",
            ))
            result.allowed = False
            result.findings = findings
            result.reason = "malformed_url"
            return result

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        port = parsed.port or 0
        path = parsed.path or ""

        # ── Check 1: Dangerous schemes ──
        if scheme in DANGEROUS_SCHEMES:
            findings.append(Finding.agent_mcp(
                rule_id="AGENT-OUT-010",
                title=f"Dangerous URL scheme: {scheme}://",
                description=(
                    f"Agent tool '{tool_name}' is making a request with "
                    f"scheme '{scheme}' ({DANGEROUS_SCHEMES[scheme]}). "
                    f"This can be used for SSRF, protocol smuggling, or "
                    f"local resource access."
                ),
                severity=Severity.CRITICAL,
                target=source,
                evidence=f"scheme={scheme}, url={url[:200]}, tool={tool_name}",
                cwe_ids=["CWE-918"],
            ))
            result.allowed = False
            result.risk_score = 1.0

        # ── Check 2: SSRF targets ──
        for ssrf in SSRF_TARGETS:
            if ssrf in hostname or ssrf in url:
                findings.append(Finding.agent_mcp(
                    rule_id="AGENT-OUT-020",
                    title=f"SSRF target detected: {ssrf}",
                    description=(
                        f"Agent tool '{tool_name}' is targeting '{ssrf}' "
                        f"which is a cloud metadata / internal service endpoint. "
                        f"This is a Server-Side Request Forgery (SSRF) attack."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"ssrf_target={ssrf}, url={url[:200]}, tool={tool_name}",
                    cwe_ids=["CWE-918"],
                ))
                result.allowed = False
                result.risk_score = 1.0
                break

        # ── Check 3: Private IP detection ──
        if self._block_private and hostname:
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    findings.append(Finding.agent_mcp(
                        rule_id="AGENT-OUT-030",
                        title=f"Private/internal IP access: {hostname}",
                        description=(
                            f"Agent tool '{tool_name}' is accessing private IP "
                            f"'{hostname}'. Internal network access from agent "
                            f"tool calls can be used for lateral movement and "
                            f"infrastructure reconnaissance."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"ip={hostname}, private={ip.is_private}, loopback={ip.is_loopback}",
                        cwe_ids=["CWE-918"],
                    ))
                    result.allowed = False
                    result.risk_score = max(result.risk_score, 0.9)
            except ValueError:
                pass  # Not an IP, hostname — that's fine

        # ── Check 4: Domain denylist ──
        if hostname and self._denied:
            for denied in self._denied:
                if hostname == denied or hostname.endswith(f".{denied}"):
                    findings.append(Finding.agent_mcp(
                        rule_id="AGENT-OUT-040",
                        title=f"Denied domain access: {hostname}",
                        description=(
                            f"Agent tool '{tool_name}' is accessing denied "
                            f"domain '{hostname}' (matched: {denied})."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"domain={hostname}, denied_match={denied}",
                    ))
                    result.allowed = False
                    result.risk_score = max(result.risk_score, 0.8)
                    break

        # ── Check 5: Domain allowlist (if configured) ──
        if hostname and self._allowed is not None:
            allowed = any(
                hostname == a or hostname.endswith(f".{a}")
                for a in self._allowed
            )
            if not allowed:
                findings.append(Finding.agent_mcp(
                    rule_id="AGENT-OUT-041",
                    title=f"Domain not in allowlist: {hostname}",
                    description=(
                        f"Agent tool '{tool_name}' is accessing domain "
                        f"'{hostname}' which is not in the configured allowlist."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"domain={hostname}, allowed={list(self._allowed)[:5]}",
                ))
                result.allowed = False
                result.risk_score = max(result.risk_score, 0.5)

        # ── Check 6: Suspicious port ──
        if port and port in SUSPICIOUS_PORTS:
            findings.append(Finding.agent_mcp(
                rule_id="AGENT-OUT-050",
                title=f"Suspicious port: {port} ({SUSPICIOUS_PORTS[port]})",
                description=(
                    f"Agent tool '{tool_name}' is connecting to port {port} "
                    f"({SUSPICIOUS_PORTS[port]}). Direct access to database "
                    f"and administrative ports from agent tool calls indicates "
                    f"potential reconnaissance or exploitation."
                ),
                severity=Severity.HIGH,
                target=source,
                evidence=f"port={port}, service={SUSPICIOUS_PORTS[port]}, url={url[:200]}",
                cwe_ids=["CWE-200"],
            ))
            result.risk_score = max(result.risk_score, 0.7)

        # ── Check 7: Rate limiting ──
        now = time.time()
        host_key = hostname or url[:50]
        log = self._request_log[host_key]
        log.append(now)
        # Clean old entries
        self._request_log[host_key] = [
            t for t in log if now - t < self._window
        ]
        current_count = len(self._request_log[host_key])

        if current_count > self._max_per_host:
            findings.append(Finding.agent_mcp(
                rule_id="AGENT-OUT-060",
                title=f"Rate limit exceeded for host: {hostname}",
                description=(
                    f"Agent has made {current_count} requests to '{hostname}' "
                    f"in the last {self._window}s (limit: {self._max_per_host}). "
                    f"This pattern is consistent with agent weaponization as a "
                    f"DoS proxy or automated scanner (arXiv:2406.08689v2 §3.3.2)."
                ),
                severity=Severity.HIGH,
                target=source,
                evidence=f"host={hostname}, count={current_count}, window={self._window}s",
                cwe_ids=["CWE-770"],
            ))
            result.allowed = False
            result.risk_score = max(result.risk_score, 0.8)

        # ── Check 8: Path patterns for scanning ──
        scan_patterns = [
            r"/\.env", r"/wp-admin", r"/phpinfo", r"/debug",
            r"/actuator", r"/swagger", r"/.git", r"/api/v\d+/admin",
            r"/shell", r"/cmd", r"/eval", r"/exec",
        ]
        for pat in scan_patterns:
            if re.search(pat, path, re.I):
                findings.append(Finding.agent_mcp(
                    rule_id="AGENT-OUT-070",
                    title=f"Reconnaissance path pattern: {path}",
                    description=(
                        f"Agent tool '{tool_name}' is accessing path '{path}' "
                        f"which matches known reconnaissance/scanning patterns."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"path={path}, pattern={pat}, url={url[:200]}",
                    cwe_ids=["CWE-200"],
                ))
                result.risk_score = max(result.risk_score, 0.7)
                break

        result.findings = findings
        if not result.allowed:
            result.reason = "blocked"
        return result

    def validate_tool_call(
        self, tool_name: str, arguments: dict, source: str = "<agent>"
    ) -> ValidationResult:
        """Validate all URLs found in a tool call's arguments."""
        combined = ValidationResult()
        urls = self._extract_urls(arguments)

        for url in urls:
            r = self.validate_url(url, tool_name=tool_name, source=source)
            combined.findings.extend(r.findings)
            combined.risk_score = max(combined.risk_score, r.risk_score)
            if not r.allowed:
                combined.allowed = False

        return combined

    @staticmethod
    def _extract_urls(obj, depth: int = 0) -> list[str]:
        """Recursively extract URL-like strings from tool arguments."""
        if depth > 10:
            return []
        urls = []
        if isinstance(obj, str):
            # Simple URL detection
            if re.match(r"^https?://", obj, re.I) or "://" in obj:
                urls.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                urls.extend(OutboundValidator._extract_urls(v, depth + 1))
        elif isinstance(obj, list):
            for v in obj:
                urls.extend(OutboundValidator._extract_urls(v, depth + 1))
        return urls

    def reset_rate_limits(self) -> None:
        """Clear rate limit tracking state."""
        self._request_log.clear()
