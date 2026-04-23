"""Scikit-learn Skops safe format scanner."""
from __future__ import annotations
import json
import logging
import zipfile
from pathlib import Path
from ..finding import Finding, Severity

logger = logging.getLogger(__name__)
TRUSTED_SKLEARN_TYPES = ["sklearn.", "numpy.", "scipy.", "collections.", "builtins."]
DANGEROUS_TYPES = ["os.", "subprocess.", "shutil.", "importlib.", "builtins.eval", "builtins.exec", "builtins.__import__", "builtins.compile"]


class SkopsScanner:
    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".skops":
            return findings
        if not zipfile.is_zipfile(str(path)):
            findings.append(Finding.artifact(
                rule_id="SKOPS-001", title="Invalid Skops file",
                description="Not a valid ZIP", severity=Severity.HIGH, target=filepath,
            ))
            return findings
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="SKOPS-002", title="Path traversal in Skops",
                            description=f"Path: {info.filename}",
                            severity=Severity.CRITICAL, target=filepath, cwe_ids=["CWE-22"],
                        ))
                if "schema.json" in zf.namelist():
                    schema = json.loads(zf.read("schema.json"))
                    types = self._extract_types(schema)
                    for t in types:
                        for d in DANGEROUS_TYPES:
                            if t.startswith(d):
                                findings.append(Finding.artifact(
                                    rule_id="SKOPS-003", title=f"Dangerous type in Skops: {t}",
                                    description="Untrusted type in schema",
                                    severity=Severity.CRITICAL, target=filepath, evidence=t,
                                ))
                        if not any(t.startswith(s) for s in TRUSTED_SKLEARN_TYPES):
                            findings.append(Finding.artifact(
                                rule_id="SKOPS-004", title=f"Untrusted type in Skops: {t}",
                                description="Type not in trusted list",
                                severity=Severity.MEDIUM, target=filepath, evidence=t,
                            ))
                for name in zf.namelist():
                    if name.endswith((".pkl", ".pickle")):
                        findings.append(Finding.artifact(
                            rule_id="SKOPS-005", title="Pickle fallback in Skops",
                            description=f"Pickle file found: {name}",
                            severity=Severity.HIGH, target=filepath, evidence=name, cwe_ids=["CWE-502"],
                        ))
        except (zipfile.BadZipFile, json.JSONDecodeError) as e:
            findings.append(Finding.artifact(
                rule_id="SKOPS-006", title="Corrupted Skops file",
                description=str(e), severity=Severity.MEDIUM, target=filepath,
            ))
        return findings

    def _extract_types(self, schema: dict) -> list[str]:
        types = []
        if isinstance(schema, dict):
            if "__class__" in schema:
                types.append(schema["__class__"])
            if "__module__" in schema and "__class__" in schema:
                types.append(f"{schema['__module__']}.{schema['__class__']}")
            for v in schema.values():
                types.extend(self._extract_types(v))
        elif isinstance(schema, list):
            for item in schema:
                types.extend(self._extract_types(item))
        return types
