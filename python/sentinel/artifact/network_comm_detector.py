"""Network communication detector for model artifacts and code."""
from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.finding import Finding, Severity

_URL_RE = re.compile(r"https?://[^\s\"'`]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b")
_SOCKET_RE = re.compile(r"\bsocket\.(?:connect|bind|listen|send|recv)\s*\(")
_HTTP_CLIENT_RE = re.compile(r"\b(?:requests|httpx|urllib|aiohttp|http\.client)\.")
_DNS_RE = re.compile(r"\b(?:socket\.getaddrinfo|socket\.gethostbyname|dns\.resolver)\s*\(")

_SUSPICIOUS_DOMAINS = frozenset({
    "ngrok.io", "serveo.net", "localtunnel.me", "loca.lt",
    "burpcollaborator.net", "interact.sh", "oast.fun",
    "requestbin.com", "webhook.site", "pipedream.net",
})


@dataclass
class NetworkFinding:
    type: str  # "url", "ip", "socket", "http_client", "dns"
    value: str
    file: str
    line: int = 0
    is_suspicious: bool = False


def detect_network_comms(filepath: str, content: str) -> list[NetworkFinding]:
    """Detect network communication patterns in code/config."""
    findings: list[NetworkFinding] = []

    for m in _URL_RE.finditer(content):
        url = m.group(0)
        line = content[:m.start()].count("\n") + 1
        suspicious = any(d in url.lower() for d in _SUSPICIOUS_DOMAINS)
        findings.append(NetworkFinding("url", url, filepath, line, suspicious))

    for m in _IP_RE.finditer(content):
        ip = m.group(0)
        line = content[:m.start()].count("\n") + 1
        findings.append(NetworkFinding("ip", ip, filepath, line, ip.startswith(("10.", "192.168.", "172."))))

    for m in _SOCKET_RE.finditer(content):
        line = content[:m.start()].count("\n") + 1
        findings.append(NetworkFinding("socket", m.group(0), filepath, line, True))

    return findings


def network_findings_to_sentinel(findings: list[NetworkFinding]) -> list[Finding]:
    """Convert network findings to Sentinel Finding objects."""
    results: list[Finding] = []
    for nf in findings:
        if nf.is_suspicious:
            results.append(Finding.artifact(
                rule_id="ARTIFACT-NET-001",
                title="Suspicious network communication",
                description=f"Suspicious network communication: {nf.type} {nf.value[:100]}",
                severity=Severity.HIGH if nf.type == "socket" else Severity.MEDIUM,
                confidence=0.7,
                target=nf.file,
            ))
    return results
