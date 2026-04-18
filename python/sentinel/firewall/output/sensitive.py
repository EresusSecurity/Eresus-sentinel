"""
Sensitive Data / PII Scanner for LLM Outputs.

Detects personally identifiable information (PII) and sensitive data
in LLM responses before they reach the user.

Two-tier detection:
- Presidio Analyzer for NER-based entity detection
- Regex fallback for common PII patterns
- Configurable entity types and redaction
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# Built-in regex patterns for PII (fallback when Presidio unavailable)
PII_PATTERNS = {
    "email": {
        "pattern": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "description": "Email Address",
        "severity": Severity.MEDIUM,
    },
    "phone_us": {
        "pattern": re.compile(
            r"(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
        ),
        "description": "US Phone Number",
        "severity": Severity.MEDIUM,
    },
    "phone_intl": {
        "pattern": re.compile(r"\+[1-9]\d{7,14}"),
        "description": "International Phone Number",
        "severity": Severity.MEDIUM,
    },
    "ssn": {
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "description": "Social Security Number",
        "severity": Severity.CRITICAL,
    },
    "credit_card": {
        "pattern": re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
            r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
        ),
        "description": "Credit Card Number",
        "severity": Severity.CRITICAL,
    },
    "ip_address": {
        "pattern": re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "description": "IP Address",
        "severity": Severity.LOW,
    },
    "iban": {
        "pattern": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"),
        "description": "IBAN",
        "severity": Severity.HIGH,
    },
    "passport": {
        "pattern": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        "description": "Passport Number (potential)",
        "severity": Severity.MEDIUM,
    },
    "date_of_birth": {
        "pattern": re.compile(
            r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
        ),
        "description": "Date of Birth",
        "severity": Severity.MEDIUM,
    },
}

# Entity types for Presidio (when available)
DEFAULT_PRESIDIO_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "CREDIT_CARD", "IBAN_CODE", "US_SSN",
    "IP_ADDRESS", "LOCATION", "DATE_TIME",
    "NRP", "MEDICAL_LICENSE", "URL",
]


class SensitiveDataScanner(OutputScanner):
    """
    Detects PII and sensitive data in LLM outputs.

    Two-tier detection:
    1. Presidio Analyzer (if installed) — NER-based recognition
    2. Built-in regex patterns — common PII formats

    Two-tier detection approach.
    """

    def __init__(
        self,
        entities: Optional[list[str]] = None,
        threshold: float = 0.5,
        redact: bool = True,
        use_presidio: bool = True,
    ):
        """
        Args:
            entities: Presidio entity types to detect.
            threshold: Minimum confidence for Presidio results.
            redact: Whether to redact detected PII.
            use_presidio: Attempt to use Presidio if available.
        """
        self._entities = entities or DEFAULT_PRESIDIO_ENTITIES
        self._threshold = threshold
        self._redact = redact
        self._analyzer = None
        self._anonymizer = None
        self._presidio_available = False

        if use_presidio:
            self._presidio_available = self._try_load_presidio()

    def _try_load_presidio(self) -> bool:
        """Try to load Presidio Analyzer."""
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine

            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()
            logger.info("Presidio available, using NER-based PII detection")
            return True
        except ImportError:
            logger.debug("Presidio not installed, using regex fallback")
            return False

    def scan(self, prompt: str, output: str) -> ScanResult:
        """Scan LLM output for sensitive data."""
        if not output:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        findings = []
        detected_entities = []

        # Tier 1: Presidio
        if self._presidio_available and self._analyzer:
            presidio_results = self._scan_with_presidio(output)
            detected_entities.extend(presidio_results)

        # Tier 2: Regex fallback
        regex_results = self._scan_with_regex(output)
        detected_entities.extend(regex_results)

        # Deduplicate by position overlap
        unique_entities = self._deduplicate(detected_entities)

        if not unique_entities:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        # Generate findings
        for entity in unique_entities:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-002",
                title=f"Sensitive data in output: {entity['type']}",
                description=(
                    f"LLM response contains {entity['description']} "
                    f"({entity['type']}). This may violate privacy regulations "
                    f"or leak sensitive information."
                ),
                severity=entity["severity"],
                confidence=entity.get("confidence", 0.9),
                target="<output>",
                evidence=f"Type: {entity['type']}, Value: {self._mask(entity['value'])}",
                cwe_ids=["CWE-200", "CWE-359"],
                tags=["owasp:llm06", "gdpr:pii"],
                remediation="Redact PII from LLM responses. Implement output filtering.",
            ))

        # Redact if configured
        sanitized = output
        if self._redact:
            sanitized = self._redact_entities(output, unique_entities)

        max_severity = min(e["severity"].sort_key for e in unique_entities)
        risk_score = min(1.0, len(unique_entities) * 0.2 + 0.3)

        return ScanResult(
            sanitized=sanitized,
            action=ScanAction.REDACT if self._redact else ScanAction.WARN,
            risk_score=risk_score,
            findings=findings,
        )

    def _scan_with_presidio(self, text: str) -> list[dict]:
        """Scan using Presidio Analyzer."""
        results = []
        try:
            analyzer_results = self._analyzer.analyze(
                text=text,
                entities=self._entities,
                language="en",
                score_threshold=self._threshold,
            )
            for result in analyzer_results:
                results.append({
                    "type": result.entity_type,
                    "description": f"Presidio: {result.entity_type}",
                    "value": text[result.start:result.end],
                    "start": result.start,
                    "end": result.end,
                    "confidence": result.score,
                    "severity": self._entity_severity(result.entity_type),
                })
        except Exception as e:
            logger.warning("Presidio scan failed: %s", e)
        return results

    def _scan_with_regex(self, text: str) -> list[dict]:
        """Scan using built-in regex patterns."""
        results = []
        for pattern_name, pattern_info in PII_PATTERNS.items():
            for match in pattern_info["pattern"].finditer(text):
                results.append({
                    "type": pattern_name.upper(),
                    "description": pattern_info["description"],
                    "value": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.85,
                    "severity": pattern_info["severity"],
                })
        return results

    def _deduplicate(self, entities: list[dict]) -> list[dict]:
        """Remove overlapping entities, preferring higher confidence."""
        if not entities:
            return []

        # Sort by start position, then by confidence descending
        sorted_entities = sorted(
            entities, key=lambda e: (e["start"], -e.get("confidence", 0))
        )

        result = [sorted_entities[0]]
        for entity in sorted_entities[1:]:
            last = result[-1]
            # No overlap
            if entity["start"] >= last["end"]:
                result.append(entity)
            # Overlap — keep the one with higher confidence
            elif entity.get("confidence", 0) > last.get("confidence", 0):
                result[-1] = entity

        return result

    def _entity_severity(self, entity_type: str) -> Severity:
        """Map Presidio entity type to severity."""
        critical = {"US_SSN", "CREDIT_CARD"}
        high = {"IBAN_CODE", "MEDICAL_LICENSE", "PERSON"}
        if entity_type in critical:
            return Severity.CRITICAL
        if entity_type in high:
            return Severity.HIGH
        return Severity.MEDIUM

    def _mask(self, value: str) -> str:
        """Mask a value for evidence display."""
        if len(value) <= 6:
            return "***"
        return value[:2] + "***" + value[-2:]

    def _redact_entities(self, text: str, entities: list[dict]) -> str:
        """Redact all detected entities from text."""
        sorted_entities = sorted(entities, key=lambda e: e["start"], reverse=True)
        result = text
        for entity in sorted_entities:
            placeholder = f"[{entity['type']}]"
            result = result[:entity["start"]] + placeholder + result[entity["end"]:]
        return result
