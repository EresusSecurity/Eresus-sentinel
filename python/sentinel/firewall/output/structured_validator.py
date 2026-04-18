"""Structured output validator — JSON, XML, YAML, TOML format validation."""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


class StructuredOutputValidator(OutputScanner):
    """Validates LLM output conforms to expected structured formats."""

    def __init__(
        self,
        expected_format: str = "json",
        schema: Optional[dict] = None,
        strict: bool = False,
    ):
        self._format = expected_format.lower()
        self._schema = schema
        self._strict = strict

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or not output.strip():
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # Extract structured block from output
        extracted = self._extract_block(output)
        if not extracted:
            if self._strict:
                finding = Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-070",
                    title=f"Expected {self._format.upper()} output not found",
                    description="LLM output does not contain valid structured data",
                    severity=Severity.MEDIUM,
                    target="<output>",
                    tags=["format_validation"],
                )
                return ScanResult(
                    sanitized=output, action=ScanAction.WARN, risk_score=0.5, findings=[finding],
                )
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # Validate format
        valid, error = self._validate(extracted)
        if valid:
            # Schema validation (JSON only)
            if self._schema and self._format == "json":
                schema_valid, schema_error = self._validate_schema(extracted)
                if not schema_valid:
                    finding = Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-072",
                        title="Output fails JSON schema validation",
                        description=f"Schema error: {schema_error}",
                        severity=Severity.MEDIUM,
                        target="<output>",
                        evidence=schema_error,
                        tags=["format_validation", "schema"],
                    )
                    return ScanResult(
                        sanitized=output, action=ScanAction.WARN, risk_score=0.4, findings=[finding],
                    )
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        finding = Finding.firewall_output(
            rule_id="FIREWALL-OUTPUT-071",
            title=f"Invalid {self._format.upper()} in output",
            description=f"Parse error: {error}",
            severity=Severity.MEDIUM,
            target="<output>",
            evidence=error,
            tags=["format_validation"],
        )
        action = ScanAction.BLOCK if self._strict else ScanAction.WARN
        return ScanResult(sanitized=output, action=action, risk_score=0.6, findings=[finding])

    def _extract_block(self, text: str) -> Optional[str]:
        """Extract structured data block from markdown fences or raw text."""
        pattern = rf"```(?:{self._format})?\s*\n(.*?)```"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Try raw parse
        text = text.strip()
        if self._format == "json" and (text.startswith("{") or text.startswith("[")):
            return text
        if self._format == "xml" and text.startswith("<"):
            return text
        if self._format == "yaml" and (":" in text.split("\n")[0]):
            return text
        if self._format == "toml" and ("=" in text.split("\n")[0] or text.startswith("[")):
            return text
        return None

    def _validate(self, content: str) -> tuple[bool, str]:
        """Validate content against expected format."""
        try:
            if self._format == "json":
                json.loads(content)
            elif self._format == "xml":
                import xml.etree.ElementTree as ET
                ET.fromstring(content)
            elif self._format == "yaml":
                import yaml
                yaml.safe_load(content)
            elif self._format == "toml":
                import tomllib
                tomllib.loads(content)
            else:
                return False, f"Unsupported format: {self._format}"
            return True, ""
        except Exception as exc:
            return False, str(exc)[:200]

    def _validate_schema(self, content: str) -> tuple[bool, str]:
        """Validate JSON against schema."""
        if not self._schema:
            return True, ""
        try:
            import jsonschema
            data = json.loads(content)
            jsonschema.validate(data, self._schema)
            return True, ""
        except ImportError:
            logger.info("jsonschema not installed, skipping schema validation")
            return True, ""
        except Exception as exc:
            return False, str(exc)[:200]
