"""Notebook PII detection plugin — scans cells for personally identifiable information."""

from __future__ import annotations

import re
from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.parser import NotebookCell, NotebookParser

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


def scan_pii(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan a cell's source for PII data."""
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
