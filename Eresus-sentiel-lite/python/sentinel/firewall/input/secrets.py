"""
Eresus Sentinel — Secret Scanner (YAML + detect-secrets)

Two-layer secret detection:
  1. YAML patterns from rules/secret_patterns.yaml (120+ patterns)
  2. detect-secrets library with full plugin suite (optional)

Redaction modes: partial, all, hash.
"""

import hashlib
import re
from enum import Enum
from typing import Any, Dict, List, Optional

from ...finding import Finding, Severity
from ..base import ScanAction, ScanResult, InputScanner
from ...rules import load_secret_patterns


class RedactMode(str, Enum):
    PARTIAL = "partial"
    ALL     = "all"
    HASH    = "hash"


_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# detect-secrets plugin config
_DETECT_SECRETS_CONFIG = {
    "plugins_used": [
        {"name": "AWSKeyDetector"},
        {"name": "ArtifactoryDetector"},
        {"name": "AzureStorageKeyDetector"},
        {"name": "BasicAuthDetector"},
        {"name": "CloudantDetector"},
        {"name": "DiscordBotTokenDetector"},
        {"name": "IbmCloudIamDetector"},
        {"name": "IbmCosHmacDetector"},
        {"name": "JwtTokenDetector"},
        {"name": "MailchimpDetector"},
        {"name": "NpmDetector"},
        {"name": "PrivateKeyDetector"},
        {"name": "SoftlayerDetector"},
        {"name": "SquareOAuthDetector"},
        {"name": "StripeDetector"},
        {"name": "TwilioKeyDetector"},
        {"name": "Base64HighEntropyString", "limit": 4.5},
        {"name": "HexHighEntropyString", "limit": 3.0},
    ]
}


class SecretScanner(InputScanner):
    """Scans text for leaked secrets/credentials.

    Layer 1: YAML patterns (rules/secret_patterns.yaml, 120+ patterns).
    Layer 2: detect-secrets library (optional, 18+ built-in plugins).

    Supports three redaction modes: partial, all, hash.
    """

    scanner_type = "input"

    def __init__(
        self,
        use_detect_secrets: bool = False,
        redact_mode: str = "all",
        extra_patterns: Optional[List[Dict]] = None,
    ):
        self.use_detect_secrets = use_detect_secrets
        self._redact_mode = RedactMode(redact_mode) if isinstance(redact_mode, str) else redact_mode
        self._detect_secrets_available = False

        # Layer 1: YAML patterns
        try:
            self._patterns = load_secret_patterns()
        except FileNotFoundError:
            self._patterns = []

        # Merge runtime extras
        if extra_patterns:
            for p in extra_patterns:
                try:
                    self._patterns.append({
                        "id": p["id"],
                        "pattern": re.compile(p["pattern"]),
                        "description": p.get("description", "Custom pattern"),
                        "severity": p.get("severity", "HIGH"),
                        "tags": p.get("tags", []),
                    })
                except (re.error, KeyError):
                    continue

        # Layer 2: detect-secrets
        if self.use_detect_secrets:
            try:
                from detect_secrets.core.secrets_collection import SecretsCollection  # noqa: F401
                from detect_secrets.settings import transient_settings  # noqa: F401
                self._detect_secrets_available = True
            except ImportError:
                self._detect_secrets_available = False
                self.use_detect_secrets = False

    @property
    def pattern_count(self) -> int:
        """Total number of active YAML patterns."""
        return len(self._patterns)

    def scan(self, text: str) -> ScanResult:
        """Scan text for secrets across both layers."""
        findings: List[Finding] = []
        sanitized = text
        seen_spans: set = set()

        if not text.strip():
            return ScanResult(
                action=ScanAction.PASS,
                findings=[],
                sanitized=text,
                risk_score=0.0,
            )

        # Layer 1: YAML patterns
        for pat_info in self._patterns:
            for match in pat_info["pattern"].finditer(text):
                span = (match.start(), match.end())
                if span in seen_spans:
                    continue
                seen_spans.add(span)

                severity = _SEVERITY_MAP.get(pat_info["severity"], Severity.HIGH)
                secret_value = match.group(1) if match.lastindex else match.group(0)

                findings.append(Finding.firewall_input(
                    rule_id=f"SECRET-{pat_info['id']}",
                    title=f"Secret detected: {pat_info['description']}",
                    description=f"Found {pat_info['description']} in input text.",
                    severity=severity,
                    target="input_text",
                    evidence=self._redact(secret_value),
                    cwe_ids=["CWE-798"],
                ))
                sanitized = sanitized.replace(
                    secret_value,
                    self._redact(secret_value),
                )

        # Layer 2: detect-secrets
        if self.use_detect_secrets and self._detect_secrets_available:
            ds_findings = self._run_detect_secrets(text)
            findings.extend(ds_findings)

        # Determine action
        if not findings:
            action = ScanAction.PASS
            risk_score = 0.0
        elif any(f.severity == Severity.CRITICAL for f in findings):
            action = ScanAction.BLOCK
            risk_score = 1.0
        elif any(f.severity == Severity.HIGH for f in findings):
            action = ScanAction.BLOCK
            risk_score = 0.9
        else:
            action = ScanAction.REDACT
            risk_score = 0.5

        return ScanResult(
            action=action,
            findings=findings,
            sanitized=sanitized,
            risk_score=risk_score,
        )

    def _run_detect_secrets(self, text: str) -> List[Finding]:
        """Run detect-secrets with full plugin suite."""
        import os
        import tempfile
        from detect_secrets.core.secrets_collection import SecretsCollection
        from detect_secrets.settings import transient_settings

        results: List[Finding] = []
        try:
            secrets = SecretsCollection()
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            temp_file.write(text.encode("utf-8"))
            temp_file.close()

            with transient_settings(_DETECT_SECRETS_CONFIG):
                secrets.scan_file(temp_file.name)

            for file in secrets.files:
                for secret in secrets[file]:
                    results.append(Finding.firewall_input(
                        rule_id=f"SECRET-DS-{secret.type}",
                        title=f"Secret via detect-secrets: {secret.type}",
                        description=f"detect-secrets plugin '{secret.type}' found a match.",
                        severity=Severity.HIGH,
                        target="input_text",
                        evidence="[redacted]",
                        cwe_ids=["CWE-798"],
                    ))

            os.remove(temp_file.name)
        except Exception:
            pass

        return results

    def _redact(self, secret: str) -> str:
        """Redact a secret value based on configured mode."""
        if self._redact_mode == RedactMode.ALL:
            return "******"
        elif self._redact_mode == RedactMode.HASH:
            return hashlib.md5(secret.encode()).hexdigest()
        elif self._redact_mode == RedactMode.PARTIAL:
            if len(secret) <= 8:
                return "****"
            return f"{secret[:2]}..{secret[-2:]}"
        return "******"
