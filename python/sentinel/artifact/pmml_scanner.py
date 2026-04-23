"""PMML XML model scanner."""
from __future__ import annotations
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = ["script", "exec", "eval", "system", "shell", "python", "javascript"]


class PMMLScanner:
    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".pmml":
            return findings
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        if "<!ENTITY" in text or "<!DOCTYPE" in text:
            findings.append(Finding.artifact(
                rule_id="PMML-001", title="XXE risk in PMML",
                description="PMML contains DOCTYPE/ENTITY — potential XXE",
                severity=Severity.CRITICAL, target=filepath,
                cwe_ids=["CWE-611"],
            ))
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            findings.append(Finding.artifact(
                rule_id="PMML-002", title="Invalid PMML XML",
                description="Cannot parse PMML", severity=Severity.MEDIUM, target=filepath,
            ))
            return findings
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag.lower() == "extension":
                name = elem.get("name", "")
                value = elem.get("value", "")
                for d in DANGEROUS_EXTENSIONS:
                    if d in name.lower() or d in value.lower():
                        findings.append(Finding.artifact(
                            rule_id="PMML-003", title=f"Dangerous Extension in PMML: {name}",
                            description=f"Extension may execute code: {value[:100]}",
                            severity=Severity.HIGH, target=filepath, evidence=f"{name}={value[:200]}",
                        ))
            if tag.lower() in ("simplepredicate", "compoundpredicate"):
                value = elem.get("value", "")
                if any(s in value for s in ["eval(", "exec(", "__import__", "os.system", "'; DROP"]):
                    findings.append(Finding.artifact(
                        rule_id="PMML-004", title="Injection in PMML predicate",
                        description=f"Suspicious value: {value[:100]}",
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=value[:200], cwe_ids=["CWE-94"],
                    ))
            for attr_val in elem.attrib.values():
                if "<script" in attr_val.lower() or "javascript:" in attr_val.lower():
                    findings.append(Finding.artifact(
                        rule_id="PMML-005", title="XSS in PMML attributes",
                        description="Script injection in PMML attribute",
                        severity=Severity.HIGH, target=filepath,
                        evidence=attr_val[:200], cwe_ids=["CWE-79"],
                    ))
        return findings
