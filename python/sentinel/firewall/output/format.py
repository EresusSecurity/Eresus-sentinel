"""
Output Format Enforcer.

Validates LLM outputs against expected schemas and formats:
- JSON schema validation
- Markdown code block detection (code execution risk)
- Function call schema validation
- Output length bounds



"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# Pattern to detect code blocks in markdown
CODE_BLOCK_PATTERN = re.compile(
    r"```(?:python|javascript|js|bash|sh|powershell|cmd|ruby|php|perl)\n"
    r"(.*?)"
    r"```",
    re.DOTALL | re.IGNORECASE,
)

# Dangerous code patterns inside code blocks
DANGEROUS_CODE_PATTERNS = [
    re.compile(r"(?:os\.system|subprocess\.|exec\(|eval\()", re.IGNORECASE),
    re.compile(r"(?:rm\s+-rf|del\s+/[sfq]|format\s+[a-z]:)", re.IGNORECASE),
    re.compile(r"(?:curl|wget)\s+.*\|\s*(?:bash|sh)", re.IGNORECASE),
    re.compile(r"(?:import\s+(?:os|subprocess|shutil|ctypes))", re.IGNORECASE),
    re.compile(r"(?:chmod\s+[0-7]{3,4}|chown\s+)", re.IGNORECASE),
    re.compile(r"(?:nc\s+-[le]|ncat|netcat)", re.IGNORECASE),  # Reverse shells
    re.compile(r"(?:base64\s+-d|openssl\s+enc)", re.IGNORECASE),  # Encoded payloads
]


class FormatEnforcer(OutputScanner):
    """
    Validates LLM outputs against expected format constraints.

    Checks:
    1. JSON schema compliance (when JSON output expected)
    2. Executable code block detection in markdown
    3. Output length bounds
    4. Dangerous code patterns in code blocks
    """

    def __init__(
        self,
        expected_json_schema: Optional[dict] = None,
        max_output_length: int = 100_000,
        detect_code_blocks: bool = True,
        block_dangerous_code: bool = True,
    ):
        self._json_schema = expected_json_schema
        self._max_length = max_output_length
        self._detect_code = detect_code_blocks
        self._block_dangerous = block_dangerous_code

    def scan(self, prompt: str, output: str) -> ScanResult:
        """Validate LLM output format and content safety."""
        if not output:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        findings = []

        # Check output length
        if len(output) > self._max_length:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-005",
                title="Excessive output length",
                description=(
                    f"LLM output is {len(output):,} characters, exceeding the "
                    f"maximum of {self._max_length:,}. This may indicate a "
                    f"generation loop or resource exhaustion attempt."
                ),
                severity=Severity.MEDIUM,
                target="<output>",
                evidence=f"Length: {len(output):,} / {self._max_length:,}",
            ))

        # JSON schema validation
        if self._json_schema:
            json_findings = self._validate_json(output)
            findings.extend(json_findings)

        # Code block detection
        if self._detect_code:
            code_findings = self._check_code_blocks(output)
            findings.extend(code_findings)

        if not findings:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        max_risk = max(
            0.5 if f.severity == Severity.MEDIUM else
            0.8 if f.severity == Severity.HIGH else
            1.0 if f.severity == Severity.CRITICAL else 0.3
            for f in findings
        )

        has_dangerous = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )

        return ScanResult(
            sanitized=output,
            action=ScanAction.BLOCK if has_dangerous else ScanAction.WARN,
            risk_score=max_risk,
            findings=findings,
        )

    def _validate_json(self, output: str) -> list[Finding]:
        """Validate output as JSON against schema."""
        findings = []

        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as e:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-006",
                title="Invalid JSON output",
                description=(
                    f"LLM output was expected to be JSON but failed to parse: {e}"
                ),
                severity=Severity.MEDIUM,
                target="<output>",
                evidence=f"JSON error: {e}, Output prefix: {output[:200]}",
            ))
            return findings

        if self._json_schema:
            try:
                import jsonschema
                jsonschema.validate(parsed, self._json_schema)
            except ImportError:
                logger.debug("jsonschema not installed, skipping schema validation")
            except jsonschema.ValidationError as e:
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-007",
                    title="JSON schema validation failed",
                    description=f"Output JSON does not match expected schema: {e.message}",
                    severity=Severity.LOW,
                    target="<output>",
                    evidence=f"Schema path: {e.json_path}, Error: {e.message}",
                ))

        return findings

    def _check_code_blocks(self, output: str) -> list[Finding]:
        """Detect executable code blocks with dangerous patterns."""
        findings = []

        for match in CODE_BLOCK_PATTERN.finditer(output):
            code_content = match.group(1)

            if self._block_dangerous:
                for pattern in DANGEROUS_CODE_PATTERNS:
                    danger_match = pattern.search(code_content)
                    if danger_match:
                        findings.append(Finding.firewall_output(
                            rule_id="FIREWALL-OUTPUT-008",
                            title="Dangerous code in LLM output",
                            description=(
                                f"LLM response contains a code block with potentially "
                                f"dangerous code: '{danger_match.group()}'. "
                                f"Executing this code could compromise the system."
                            ),
                            severity=Severity.HIGH,
                            target="<output>",
                            evidence=(
                                f"Pattern: {danger_match.group()}, "
                                f"Code block: {code_content[:200]}"
                            ),
                            cwe_ids=["CWE-94"],  # Code Injection
                            remediation=(
                                "Review code blocks in LLM output before execution. "
                                "Never auto-execute LLM-generated code without sandboxing."
                            ),
                        ))
                        break  # One finding per code block

        return findings
