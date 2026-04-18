"""
Known Bad Signatures Detector.

Detects known malicious patterns, exploit signatures, and
dangerous code constructs in model outputs. These are
high-confidence indicators of harmful content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SignatureMatch:
    """A matched bad signature."""
    signature_id: str
    category: str
    matched_text: str
    severity: str
    description: str


# Known bad signatures organized by category
_SIGNATURES: list[tuple[re.Pattern, str, str, str, str]] = [
    # Shell exploits
    (re.compile(r"rm\s+-rf\s+/(?:\s|$|;)"), "KBS-001", "shell_exploit", "CRITICAL", "Recursive root delete"),
    (re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;"), "KBS-002", "shell_exploit", "CRITICAL", "Fork bomb"),
    (re.compile(r"dd\s+if=/dev/(?:zero|random)\s+of=/dev/[sh]d"), "KBS-003", "shell_exploit", "CRITICAL", "Disk overwrite"),
    (re.compile(r"mkfs\.\w+\s+/dev/[sh]d"), "KBS-004", "shell_exploit", "CRITICAL", "Filesystem format"),
    (re.compile(r"chmod\s+-R\s+777\s+/"), "KBS-005", "shell_exploit", "HIGH", "Root permission open"),
    (re.compile(r"wget.*\|\s*(?:bash|sh|zsh)"), "KBS-006", "shell_exploit", "CRITICAL", "Remote code execution"),
    (re.compile(r"curl.*\|\s*(?:bash|sh|zsh)"), "KBS-007", "shell_exploit", "CRITICAL", "Remote code execution"),

    # Reverse shells
    (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/"), "KBS-010", "reverse_shell", "CRITICAL", "Bash reverse shell"),
    (re.compile(r"nc\s+-e\s+/bin/(?:ba)?sh"), "KBS-011", "reverse_shell", "CRITICAL", "Netcat reverse shell"),
    (re.compile(r"python.*socket.*connect.*exec"), "KBS-012", "reverse_shell", "CRITICAL", "Python reverse shell"),
    (re.compile(r"php\s+-r.*fsockopen"), "KBS-013", "reverse_shell", "CRITICAL", "PHP reverse shell"),
    (re.compile(r"ruby.*TCPSocket.*exec"), "KBS-014", "reverse_shell", "CRITICAL", "Ruby reverse shell"),
    (re.compile(r"powershell.*New-Object.*Net\.Sockets"), "KBS-015", "reverse_shell", "CRITICAL", "PowerShell reverse shell"),

    # SQL injection patterns
    (re.compile(r"(?:UNION\s+ALL\s+SELECT|;\s*DROP\s+TABLE|'\s*OR\s+'1'\s*=\s*'1)"), "KBS-020", "sqli", "HIGH", "SQL injection payload"),
    (re.compile(r"(?:SLEEP\s*\(\d+\)|BENCHMARK\s*\(\d+|WAITFOR\s+DELAY)"), "KBS-021", "sqli", "HIGH", "SQL time-based injection"),
    (re.compile(r"(?:LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE)"), "KBS-022", "sqli", "HIGH", "SQL file access"),

    # XSS payloads
    (re.compile(r"<script[^>]*>.*?(?:document\.cookie|localStorage|fetch\s*\()", re.S), "KBS-030", "xss", "HIGH", "XSS cookie/data theft"),
    (re.compile(r"javascript:.*(?:alert|confirm|prompt|eval)\s*\("), "KBS-031", "xss", "MEDIUM", "JavaScript URI injection"),
    (re.compile(r"on(?:error|load|click|mouseover)\s*=\s*['\"].*(?:fetch|XMLHttpRequest)"), "KBS-032", "xss", "HIGH", "XSS event handler exfil"),

    # Credential patterns in output
    (re.compile(r"(?:AKIA|A3T)[0-9A-Z]{16}"), "KBS-040", "credential_leak", "CRITICAL", "AWS access key in output"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), "KBS-041", "credential_leak", "CRITICAL", "Private key in output"),
    (re.compile(r"ghp_[A-Za-z0-9_]{36}"), "KBS-042", "credential_leak", "CRITICAL", "GitHub PAT in output"),
    (re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "KBS-043", "credential_leak", "CRITICAL", "OpenAI key in output"),

    # Malware indicators
    (re.compile(r"(?:mimikatz|meterpreter|cobalt\s*strike|metasploit)"), "KBS-050", "malware", "HIGH", "Known tool reference"),
    (re.compile(r"(?:keylogger|ransomware|cryptominer|botnet)\s+(?:code|script|program)"), "KBS-051", "malware", "HIGH", "Malware generation"),
    (re.compile(r"(?:CVE-\d{4}-\d{4,7})\s+(?:exploit|poc|payload)"), "KBS-052", "malware", "MEDIUM", "CVE exploit code"),

    # Data exfiltration
    (re.compile(r"(?:webhook\.site|requestbin|pipedream|ngrok|burpcollaborator)"), "KBS-060", "exfiltration", "HIGH", "Exfil service URL"),
    (re.compile(r"base64.*(?:curl|wget|fetch)\s+https?://"), "KBS-061", "exfiltration", "HIGH", "Encoded exfiltration"),
]


class KnownBadSignaturesDetector:
    """
    Detect known malicious patterns in model output.

    High-confidence, low false-positive detector for:
      - Shell exploits (rm -rf, fork bombs, disk overwrite)
      - Reverse shells (bash, netcat, python, PHP, Ruby, PowerShell)
      - SQL injection payloads
      - XSS payloads
      - Credential leakage
      - Malware tool references
      - Data exfiltration patterns

    Usage:
        detector = KnownBadSignaturesDetector()
        matches = detector.detect("Model output here...")
        if matches:
            print(f"Found {len(matches)} dangerous signatures!")
    """

    def __init__(self, min_severity: str = "MEDIUM"):
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        self._min_level = severity_order.get(min_severity, 1)
        self._severity_order = severity_order

    def detect(self, text: str) -> list[SignatureMatch]:
        """Scan text for known bad signatures."""
        matches = []
        for pattern, sig_id, category, severity, description in _SIGNATURES:
            if self._severity_order.get(severity, 0) < self._min_level:
                continue
            match = pattern.search(text)
            if match:
                matches.append(SignatureMatch(
                    signature_id=sig_id,
                    category=category,
                    matched_text=match.group(0)[:200],
                    severity=severity,
                    description=description,
                ))
        return matches

    @property
    def signature_count(self) -> int:
        return len(_SIGNATURES)
