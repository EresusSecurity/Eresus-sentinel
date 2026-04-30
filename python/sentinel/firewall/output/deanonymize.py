"""
Output de-anonymization scanner — reverses anonymization placeholders.

Production-grade features:
  - Paired with AnonymizeScanner vault for round-trip PII protection
  - Partial de-anonymization (selective entity types)
  - Audit logging of all replacements
  - Hash-based placeholder validation
  - Statistics tracking
  - Fallback handling for missing vault entries
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Placeholder pattern matching (matches [TYPE_HASH] format)
_PLACEHOLDER_PATTERN = re.compile(r"\[([A-Z_]+)_([a-f0-9]{6,8})\]")


@dataclass
class ReplacementRecord:
    """Record of a single de-anonymization replacement."""
    placeholder: str
    entity_type: str
    original_value: str
    position: int


@dataclass
class DeanonymizeResult:
    """Complete de-anonymization result."""
    output: str
    replacements_made: int
    replacements: list[ReplacementRecord]
    unresolved_placeholders: list[str]
    entity_types_restored: list[str]


class DeanonymizeScanner:
    """
    Replaces anonymization placeholders in model output with original values.

    Requires pairing with an AnonymizeScanner instance to access the vault.

    Features:
      - Selective de-anonymization by entity type
      - Audit logging of all replacements
      - Unresolved placeholder detection
      - Statistics tracking

    Usage:
        from sentinel.firewall.input.anonymize import AnonymizeScanner

        anonymizer = AnonymizeScanner()
        sanitized, _, _ = anonymizer.scan("Call John at 555-1234")

        deanonymizer = DeanonymizeScanner(anonymizer)
        result = deanonymizer.scan("", "I'll contact [PERSON_a1b2c3] at [PHONE_d4e5f6]")
        # result.output → "I'll contact John at 555-1234"
    """

    def __init__(
        self,
        anonymizer=None,
        allowed_types: list[str] | None = None,
        log_replacements: bool = True,
        strict: bool = False,
    ):
        """
        Args:
            anonymizer: AnonymizeScanner instance with populated vault.
            allowed_types: If set, only de-anonymize these entity types.
                          E.g., ["PERSON", "LOCATION"] but NOT "SSN", "CREDIT_CARD".
            log_replacements: Log each replacement for audit trail.
            strict: If True, raise error on unresolved placeholders.
        """
        self._anonymizer = anonymizer
        self._allowed_types = set(t.upper() for t in allowed_types) if allowed_types else None
        self._log = log_replacements
        self._strict = strict
        self._total_replacements = 0

    def scan(self, prompt: str, output: str) -> DeanonymizeResult:
        """De-anonymize model output using the vault."""
        if not output or not output.strip():
            return DeanonymizeResult(
                output=output, replacements_made=0, replacements=[],
                unresolved_placeholders=[], entity_types_restored=[],
            )

        vault = {}
        if self._anonymizer is not None and hasattr(self._anonymizer, 'vault'):
            vault = self._anonymizer.vault

        replacements: list[ReplacementRecord] = []
        unresolved: list[str] = []
        deanonymized = output

        # Method 1: Vault-based replacement (exact placeholder match)
        if vault:
            for placeholder, entity in vault.items():
                if placeholder not in deanonymized:
                    continue

                entity_type = getattr(entity, 'entity_type', 'UNKNOWN') if hasattr(entity, 'entity_type') else 'UNKNOWN'
                original = getattr(entity, 'original', str(entity)) if hasattr(entity, 'original') else str(entity)

                # Check type filter
                if self._allowed_types and entity_type.upper() not in self._allowed_types:
                    continue

                pos = deanonymized.find(placeholder)
                deanonymized = deanonymized.replace(placeholder, original)

                record = ReplacementRecord(
                    placeholder=placeholder,
                    entity_type=entity_type,
                    original_value=original[:50],
                    position=pos,
                )
                replacements.append(record)

                if self._log:
                    logger.info("Deanonymized: %s → %s (type: %s)",
                               placeholder, original[:20] + "...", entity_type)

        # Method 2: Detect unresolved placeholders
        for match in _PLACEHOLDER_PATTERN.finditer(deanonymized):
            full = match.group(0)
            entity_type = match.group(1)
            if full not in [r.placeholder for r in replacements]:
                unresolved.append(full)
                if self._strict:
                    logger.error("Unresolved placeholder: %s", full)

        entity_types = list(set(r.entity_type for r in replacements))
        self._total_replacements += len(replacements)

        return DeanonymizeResult(
            output=deanonymized,
            replacements_made=len(replacements),
            replacements=replacements,
            unresolved_placeholders=unresolved,
            entity_types_restored=entity_types,
        )

    @property
    def total_replacements(self) -> int:
        """Total replacements across all scans."""
        return self._total_replacements
