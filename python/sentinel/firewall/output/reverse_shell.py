"""Reverse Shell & Backdoor Payload Output Scanner.

Detects reverse shell commands, web shell code, and other backdoor
payloads in LLM-generated output before it reaches the user.

Rule IDs:
  FIREWALL-OUTPUT-010 — Reverse shell command in LLM output
  FIREWALL-OUTPUT-011 — Web shell code in LLM output
  FIREWALL-OUTPUT-012 — Fileless dropper (curl|bash / wget|bash) in output
  FIREWALL-OUTPUT-013 — Encoded backdoor payload in output
"""

from __future__ import annotations

import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

# ---------------------------------------------------------------------------
# Pattern definitions: (compiled_regex, rule_id, title, severity, cwe_ids)
# ---------------------------------------------------------------------------
_REVERSE_SHELL_PATTERNS: tuple[
    tuple[re.Pattern[str], str, str, Severity, list[str]], ...
] = (
    (
        re.compile(r"/dev/(?:tcp|udp)/[0-9a-zA-Z.\-]+/\d{1,5}"),
        "FIREWALL-OUTPUT-010",
        "Reverse shell via /dev/tcp in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)bash\s+-[ic]\s+['\"].*(?:/dev/tcp|/dev/udp)"),
        "FIREWALL-OUTPUT-010",
        "bash -i /dev/tcp reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)(?:nc|ncat|netcat)\b.*-e\s+/bin/(?:bash|sh|zsh|dash)"),
        "FIREWALL-OUTPUT-010",
        "netcat -e shell execution in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"mkfifo\s+/tmp/[a-zA-Z0-9_.\-]+"),
        "FIREWALL-OUTPUT-010",
        "mkfifo named-pipe reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)socat\b.*EXEC:['\"]?/bin/(?:bash|sh)"),
        "FIREWALL-OUTPUT-010",
        "socat PTY reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(
            r"(?i)python[23]?\s+-c\s+['\"].*import\s+socket.*(?:connect|SOCK_STREAM)"
        ),
        "FIREWALL-OUTPUT-010",
        "Python socket reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)perl\s+-e\s+['\"].*use\s+Socket.*connect"),
        "FIREWALL-OUTPUT-010",
        "Perl socket reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)ruby\s+-rsocket\s+-e"),
        "FIREWALL-OUTPUT-010",
        "Ruby -rsocket reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)php\s+-r\s+['\"].*fsockopen"),
        "FIREWALL-OUTPUT-010",
        "PHP fsockopen reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)powershell.*New-Object.*Net\.Sockets\.TCPClient"),
        "FIREWALL-OUTPUT-010",
        "PowerShell TCPClient reverse shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(
            r"(?i)powershell(?:\.exe)?\s+(?:-[Ee]nc(?:odedCommand)?|-[Ee])\s+"
        ),
        "FIREWALL-OUTPUT-013",
        "PowerShell -EncodedCommand obfuscated payload in LLM output",
        Severity.CRITICAL,
        ["CWE-78", "CWE-116"],
    ),
    (
        re.compile(
            r"(?i)IEX\s*\(\s*(?:New-Object|iwr|Invoke-WebRequest).*DownloadString"
        ),
        "FIREWALL-OUTPUT-012",
        "PowerShell IEX DownloadString fileless execution in LLM output",
        Severity.CRITICAL,
        ["CWE-494"],
    ),
)

_DROPPER_PATTERNS: tuple[
    tuple[re.Pattern[str], str, str, Severity, list[str]], ...
] = (
    (
        re.compile(
            r"(?i)curl\s+(?:-[a-zA-Z]+\s+[^\s]+\s+)*https?://[^\s]+\s*\|\s*(?:ba)?sh"
        ),
        "FIREWALL-OUTPUT-012",
        "curl | bash fileless dropper in LLM output",
        Severity.CRITICAL,
        ["CWE-494"],
    ),
    (
        re.compile(
            r"(?i)wget\s+(?:-[a-zA-Z]+\s+[^\s]+\s+)*https?://[^\s]+\s*\|\s*(?:ba)?sh"
        ),
        "FIREWALL-OUTPUT-012",
        "wget | bash fileless dropper in LLM output",
        Severity.CRITICAL,
        ["CWE-494"],
    ),
    (
        re.compile(r"(?i)base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh)"),
        "FIREWALL-OUTPUT-013",
        "base64-decoded payload piped to shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(
            r"(?i)exec\s*\(\s*(?:__import__\s*\(\s*['\"]base64['\"]|base64)\.b64decode"
        ),
        "FIREWALL-OUTPUT-013",
        "Python exec(base64.b64decode) fileless payload in LLM output",
        Severity.CRITICAL,
        ["CWE-94"],
    ),
)

_WEB_SHELL_PATTERNS: tuple[
    tuple[re.Pattern[str], str, str, Severity, list[str]], ...
] = (
    (
        re.compile(
            r"(?i)<\?php.*eval\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|base64_decode)"
        ),
        "FIREWALL-OUTPUT-011",
        "PHP eval web shell in LLM output",
        Severity.CRITICAL,
        ["CWE-94"],
    ),
    (
        re.compile(
            r"(?i)(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)"
        ),
        "FIREWALL-OUTPUT-011",
        "PHP system/exec web shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)eval\s*\(\s*base64_decode\s*\("),
        "FIREWALL-OUTPUT-011",
        "PHP eval(base64_decode) obfuscated shell in LLM output",
        Severity.CRITICAL,
        ["CWE-94"],
    ),
    (
        re.compile(r"(?i)Runtime\.getRuntime\(\)\.exec\s*\("),
        "FIREWALL-OUTPUT-011",
        "JSP Runtime.exec web shell in LLM output",
        Severity.CRITICAL,
        ["CWE-78"],
    ),
    (
        re.compile(r"(?i)<%.*?(?:Eval|Execute|Response\.Write)\s*\(\s*Request\s*\["),
        "FIREWALL-OUTPUT-011",
        "ASP.NET eval/Request shell in LLM output",
        Severity.CRITICAL,
        ["CWE-94"],
    ),
)

# All patterns combined
_ALL_PATTERNS = _REVERSE_SHELL_PATTERNS + _DROPPER_PATTERNS + _WEB_SHELL_PATTERNS


class ReverseShellOutputScanner(OutputScanner):
    """Block LLM responses that contain reverse shell commands, web shell code,
    or fileless dropper payloads.

    This scanner is a hard-block safety layer — any match results in
    ``ScanAction.BLOCK``.
    """

    def scan(self, prompt: str, output: str) -> ScanResult:
        findings: list[Finding] = []

        for pattern, rule_id, title, severity, cwe_ids in _ALL_PATTERNS:
            m = pattern.search(output)
            if m:
                snippet = output[max(0, m.start() - 30): m.end() + 30].replace(
                    "\n", " "
                )
                findings.append(
                    Finding.firewall_output(
                        rule_id=rule_id,
                        title=title,
                        description=(
                            f"LLM generated output containing a backdoor or reverse "
                            f"shell payload. Pattern matched: {pattern.pattern[:80]}"
                        ),
                        severity=severity,
                        target="llm_output",
                        evidence=f"snippet={snippet!r}",
                        tags=["backdoor", "reverse_shell", "output_safety"],
                        cwe_ids=cwe_ids,
                        remediation=(
                            "Block this response. Review the prompt for prompt injection "
                            "that may have caused the model to generate malicious code."
                        ),
                    )
                )

        if findings:
            max_score = max(
                1.0 if f.severity == Severity.CRITICAL else 0.9
                for f in findings
            )
            return ScanResult(
                sanitized="[Response blocked: contains backdoor/reverse shell payload]",
                action=ScanAction.BLOCK,
                risk_score=max_score,
                findings=findings,
            )

        return ScanResult(
            sanitized=output,
            action=ScanAction.PASS,
            risk_score=0.0,
            findings=[],
        )
