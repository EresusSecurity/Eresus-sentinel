"""Notebook PII detection plugin — scans cells for personally identifiable information.

Two-tier detection:
1. **presidio-analyzer** (optional) — ML-based NER engine; much higher accuracy.
   Install with: pip install 'sentinel[pii]'  (adds presidio-analyzer + spacy)
2. **Regex fallback** — lightweight patterns for common PII types; always available.

Approach adapted from NB Defense (protectai/nbdefense, Apache-2.0).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.parser import NotebookCell, NotebookParser

logger = logging.getLogger(__name__)

# ─── Optional presidio backend ───────────────────────────────────────────────

_presidio_engine = None
_presidio_available = False

def _get_presidio_engine():
    global _presidio_engine, _presidio_available
    if _presidio_engine is not None:
        return _presidio_engine
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import SpacyNlpEngine
        import spacy
        if not spacy.util.is_package("en_core_web_sm"):
            logger.debug("spacy en_core_web_sm not installed; falling back to regex PII")
            return None
        nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
        _presidio_engine = AnalyzerEngine(nlp_engine=nlp_engine)
        _presidio_available = True
        logger.debug("presidio-analyzer engine initialized")
        return _presidio_engine
    except (ImportError, Exception) as exc:
        logger.debug("presidio not available (%s); using regex PII detection", exc)
        return None


_PRESIDIO_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    "IBAN_CODE", "IP_ADDRESS", "US_SSN", "NRP",
    "US_PASSPORT", "US_DRIVER_LICENSE",
]

PII_PATTERNS = {
    "Email Address": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "IPv4 Address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "IPv6 Address": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "Phone (US)": re.compile(r"\b(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "Phone (International)": re.compile(r"\+\d{1,3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Credit Card (Visa)": re.compile(r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "Credit Card (MC)": re.compile(r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "Credit Card (Amex)": re.compile(r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b"),
    "US Passport": re.compile(r"\b[A-Z]\d{8}\b"),
    "Date of Birth": re.compile(r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"),
    "MAC Address": re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
    "US Zip Code": re.compile(r"\b\d{5}(?:-\d{4})?\b"),
    "Street Address": re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s?){1,4}(?:St|Ave|Blvd|Dr|Ln|Rd|Way|Ct|Pl)\b"),
}


def _scan_pii_presidio(cell: NotebookCell, path: str) -> list[Finding]:
    """PII detection via presidio-analyzer (ML-based NER)."""
    engine = _get_presidio_engine()
    if engine is None:
        return []

    findings: list[Finding] = []
    try:
        results = engine.analyze(
            text=cell.source,
            entities=_PRESIDIO_ENTITIES,
            language="en",
        )
        entity_counts: dict[str, int] = {}
        for r in results:
            if r.score >= 0.6:
                entity_counts[r.entity_type] = entity_counts.get(r.entity_type, 0) + 1

        for entity, count in entity_counts.items():
            findings.append(Finding.sast(
                rule_id="NOTEBOOK-020",
                title=f"PII detected (presidio): {entity} ({count} occurrence{'s' if count > 1 else ''})",
                description=(
                    f"Notebook {cell.ref} contains {count} instance(s) of {entity} "
                    "(detected via presidio-analyzer ML engine)."
                ),
                severity=Severity.HIGH,
                confidence=0.85,
                target=path,
                evidence=f"{cell.ref}: {entity} x{count}",
                cwe_ids=["CWE-359"],
                tags=["category:notebook", "category:pii", "backend:presidio"],
                remediation="Remove or anonymize PII data before sharing.",
            ))
    except Exception as exc:
        logger.debug("presidio scan failed: %s", exc)
    return findings


def scan_pii(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan a cell's source for PII data.

    Uses presidio-analyzer if available, otherwise falls back to regex patterns.
    """
    presidio_findings = _scan_pii_presidio(cell, path)
    if presidio_findings:
        return presidio_findings

    findings = []
    for name, pattern in PII_PATTERNS.items():
        matches = pattern.findall(cell.source)
        if matches:
            findings.append(Finding.sast(
                rule_id="NOTEBOOK-020",
                title=f"PII detected: {name} ({len(matches)} occurrences)",
                description=f"Notebook {cell.ref} contains {len(matches)} instance(s) of {name}.",
                severity=Severity.HIGH,
                confidence=0.75,
                target=path,
                evidence=f"{cell.ref}: {name} x{len(matches)}",
                cwe_ids=["CWE-359"],
                tags=["category:notebook", "category:pii"],
                remediation="Remove or anonymize PII data before sharing.",
            ))
    return findings


def scan_output_pii(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan cell outputs for PII data leakage."""
    findings = []
    for out_idx, output in enumerate(cell.outputs):
        text = NotebookParser.extract_output_text(output)
        if not text:
            continue
        out_ref = f"cell[{cell.index}].output[{out_idx}]"
        for name, pattern in PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                findings.append(Finding.sast(
                    rule_id="NOTEBOOK-021",
                    title=f"PII in output: {name} ({len(matches)} occurrences)",
                    description=f"Notebook {out_ref} output contains {len(matches)} instance(s) of {name}.",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    target=path,
                    evidence=f"{out_ref}: {name} x{len(matches)}",
                    cwe_ids=["CWE-359"],
                    tags=["category:notebook", "category:pii-output"],
                    remediation="Clear outputs containing PII before sharing.",
                ))
    return findings
