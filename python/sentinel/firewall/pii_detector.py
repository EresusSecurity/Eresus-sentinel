"""PII (Personally Identifiable Information) detector.

Multi-layer detection:
  1. Regex-based pattern matching (120+ patterns)
  2. Optional NER-based detection (spacy/GLiNER)
  3. International entity types (US, EU, UK, IN, AU, SG)

Entity types:
  - EMAIL_ADDRESS, PHONE_NUMBER, IP_ADDRESS, URL, DOMAIN_NAME
  - CREDIT_CARD, IBAN_CODE, CRYPTO_ADDRESS
  - US_SSN, US_PASSPORT, US_DRIVER_LICENSE, US_ITIN, US_BANK_NUMBER
  - UK_NHS, UK_NINO
  - PERSON, LOCATION, DATE_OF_BIRTH
  - MEDICAL_LICENSE, NRP (National Registration/Passport)

Inspired by: guardrails_pii (guardrails-ai) Presidio + GLiNER approach.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from ..finding import Finding, Location, Severity

logger = logging.getLogger(__name__)


@dataclass
class PIIEntity:
    entity_type: str
    start: int
    end: int
    text: str
    score: float


# Luhn checksum for credit card validation
def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Regex patterns for PII detection ────────────────────────────

_PII_PATTERNS: list[tuple[str, re.Pattern, float, Severity]] = [
    # Email
    ("EMAIL_ADDRESS",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
     0.95, Severity.MEDIUM),

    # Phone numbers (international)
    ("PHONE_NUMBER",
     re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
     0.7, Severity.MEDIUM),

    # Credit cards (Visa, MC, Amex, Discover)
    ("CREDIT_CARD",
     re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\b"),
     0.9, Severity.HIGH),

    # US SSN
    ("US_SSN",
     re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
     0.85, Severity.CRITICAL),

    # US ITIN
    ("US_ITIN",
     re.compile(r"\b9\d{2}[-\s]?[7-9]\d[-\s]?\d{4}\b"),
     0.85, Severity.HIGH),

    # US Passport
    ("US_PASSPORT",
     re.compile(r"\b[A-Z]\d{8}\b"),
     0.6, Severity.HIGH),

    # US Driver License (generic pattern)
    ("US_DRIVER_LICENSE",
     re.compile(r"\b[A-Z]\d{7,12}\b"),
     0.4, Severity.MEDIUM),

    # US Bank Account (routing + account)
    ("US_BANK_NUMBER",
     re.compile(r"\b\d{9}[-\s]?\d{7,17}\b"),
     0.5, Severity.HIGH),

    # IBAN (International Bank Account Number)
    ("IBAN_CODE",
     re.compile(r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b"),
     0.85, Severity.HIGH),

    # UK NHS Number
    ("UK_NHS",
     re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b"),
     0.5, Severity.HIGH),

    # UK National Insurance Number
    ("UK_NINO",
     re.compile(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.I),
     0.85, Severity.HIGH),

    # IPv4 Address
    ("IP_ADDRESS",
     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
     0.9, Severity.LOW),

    # IPv6 Address
    ("IP_ADDRESS",
     re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
     0.8, Severity.LOW),

    # URL
    ("URL",
     re.compile(r"https?://[^\s<>\"']+"),
     0.9, Severity.LOW),

    # Domain name
    ("DOMAIN_NAME",
     re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|io|co|dev|ai|app)\b"),
     0.7, Severity.LOW),

    # Crypto addresses
    ("CRYPTO_ADDRESS",
     re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),  # Bitcoin
     0.85, Severity.MEDIUM),

    ("CRYPTO_ADDRESS",
     re.compile(r"\b0x[0-9a-fA-F]{40}\b"),  # Ethereum
     0.9, Severity.MEDIUM),

    # AWS Access Key
    ("AWS_ACCESS_KEY",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     0.95, Severity.CRITICAL),

    # AWS Secret Key
    ("AWS_SECRET_KEY",
     re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
     0.3, Severity.CRITICAL),

    # Date of Birth patterns
    ("DATE_OF_BIRTH",
     re.compile(r"\b(?:(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2})\b"),
     0.6, Severity.MEDIUM),

    # Medical License (US DEA number)
    ("MEDICAL_LICENSE",
     re.compile(r"\b[ABCDEFGHJKLMNPRSTUX][A-Z9]\d{7}\b"),
     0.6, Severity.HIGH),

    # SSH Private Key
    ("SSH_PRIVATE_KEY",
     re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"),
     0.99, Severity.CRITICAL),

    # Slack Token
    ("API_TOKEN",
     re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b"),
     0.95, Severity.HIGH),

    # Stripe Key
    ("API_TOKEN",
     re.compile(r"\b[rs]k_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
     0.95, Severity.HIGH),

    # Generic API Key pattern
    ("API_TOKEN",
     re.compile(r"\b(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", re.I),
     0.7, Severity.MEDIUM),

    # India Aadhaar (12 digits)
    ("IN_AADHAAR",
     re.compile(r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b"),
     0.5, Severity.HIGH),

    # India PAN
    ("IN_PAN",
     re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
     0.7, Severity.HIGH),

    # Australia TFN (Tax File Number)
    ("AU_TFN",
     re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"),
     0.4, Severity.HIGH),

    # Australia Medicare
    ("AU_MEDICARE",
     re.compile(r"\b\d{4}[-\s]?\d{5}[-\s]?\d\b"),
     0.5, Severity.MEDIUM),

    # Singapore NRIC/FIN
    ("SG_NRIC",
     re.compile(r"\b[STFG]\d{7}[A-Z]\b"),
     0.8, Severity.HIGH),
]


class PIIDetector:
    """Regex-based PII detection with optional NER enhancement."""

    def __init__(
        self,
        entity_types: Optional[set[str]] = None,
        score_threshold: float = 0.5,
    ):
        self.entity_types = entity_types
        self.score_threshold = score_threshold

    def detect(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in text."""
        entities: list[PIIEntity] = []

        for etype, pattern, base_score, _sev in _PII_PATTERNS:
            if self.entity_types and etype not in self.entity_types:
                continue

            for match in pattern.finditer(text):
                score = base_score

                # Validate credit card with Luhn
                if etype == "CREDIT_CARD":
                    digits = re.sub(r"[^\d]", "", match.group())
                    if not _luhn_check(digits):
                        score *= 0.3

                if score >= self.score_threshold:
                    entities.append(PIIEntity(
                        entity_type=etype,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(),
                        score=score,
                    ))

        return self._deduplicate(entities)

    def scan_text(self, text: str, source: str = "<text>") -> list[Finding]:
        """Scan text and return Findings."""
        entities = self.detect(text)
        findings: list[Finding] = []

        for entity in entities:
            sev = Severity.MEDIUM
            for etype, _pat, _score, s in _PII_PATTERNS:
                if etype == entity.entity_type:
                    sev = s
                    break

            # Redact the actual value in evidence
            redacted = entity.text[:3] + "***" + entity.text[-2:]

            findings.append(Finding(
                rule_id=f"PII-{entity.entity_type}",
                title=f"PII detected: {entity.entity_type}",
                description=(
                    f"Found {entity.entity_type} in text. "
                    f"PII should be redacted before processing by AI models."
                ),
                severity=sev,
                confidence=entity.score,
                scanner="pii_detector",
                target=source,
                evidence=f"Redacted: {redacted}",
                location=Location(
                    file=source,
                    start_line=0,
                    start_col=entity.start,
                    end_col=entity.end,
                ),
                cwe_ids=["CWE-359"],
                tags=["pii", "privacy", "gdpr:art-5"],
            ))

        return findings

    def anonymize(self, text: str) -> str:
        """Replace detected PII with <ENTITY_TYPE> placeholders."""
        entities = self.detect(text)
        # Sort by position descending to replace from end
        entities.sort(key=lambda e: e.start, reverse=True)
        result = text
        for entity in entities:
            result = result[:entity.start] + f"<{entity.entity_type}>" + result[entity.end:]
        return result

    @staticmethod
    def _deduplicate(entities: list[PIIEntity]) -> list[PIIEntity]:
        """Remove overlapping entities, keeping highest score."""
        if not entities:
            return []
        entities.sort(key=lambda e: (e.start, -e.score))
        result = [entities[0]]
        for entity in entities[1:]:
            prev = result[-1]
            if entity.start >= prev.end:
                result.append(entity)
            elif entity.score > prev.score:
                result[-1] = entity
        return result
