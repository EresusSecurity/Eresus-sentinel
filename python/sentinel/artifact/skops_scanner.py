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
    """Scan scikit-learn Skops format files for trusted-types violations."""

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
                names = zf.namelist()
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="SKOPS-002", title="Path traversal in Skops",
                            description=f"Path: {info.filename}",
                            severity=Severity.CRITICAL, target=filepath, cwe_ids=["CWE-22"],
                        ))
                    if info.file_size > 10 * 1024 * 1024:
                        findings.append(Finding.artifact(
                            rule_id="CVE-2025-54412",
                            title=f"Oversized zip entry in Skops (CVE-2025-54412): {info.filename}",
                            description=(
                                "Excessively large zip entry may cause memory exhaustion on load. "
                                "CVE-2025-54412: skops zip bomb / oversized entry DoS."
                            ),
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"{info.filename}: {info.file_size // 1024}KB",
                            cwe_ids=["CWE-400"],
                        ))

                if "schema.json" in names:
                    schema_bytes = zf.read("schema.json")
                    schema = json.loads(schema_bytes)
                    types = self._extract_types(schema)

                    if len(types) > 5000:
                        findings.append(Finding.artifact(
                            rule_id="CVE-2025-54413",
                            title="Excessive type count in Skops schema (CVE-2025-54413)",
                            description=(
                                "Skops schema contains an abnormal number of type entries, "
                                "which may trigger quadratic processing or memory exhaustion. "
                                "CVE-2025-54413: skops schema type explosion."
                            ),
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"{len(types)} types",
                            cwe_ids=["CWE-400"],
                        ))

                    all_class_keys = self._extract_all_class_keys(schema)
                    if len(set(all_class_keys)) != len(all_class_keys):
                        findings.append(Finding.artifact(
                            rule_id="CVE-2025-54886",
                            title="Duplicate class keys in Skops schema (CVE-2025-54886)",
                            description=(
                                "Skops schema contains duplicate __class__ keys which may "
                                "trigger type confusion on deserialization. "
                                "CVE-2025-54886: skops type confusion via duplicate keys."
                            ),
                            severity=Severity.CRITICAL, target=filepath,
                            cwe_ids=["CWE-843"],
                        ))

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

                for name in names:
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

    def _extract_all_class_keys(self, schema: object) -> list[str]:
        """Collect all __class__ values recursively to detect duplicates (CVE-2025-54886)."""
        keys: list[str] = []
        if isinstance(schema, dict):
            if "__class__" in schema:
                keys.append(str(schema["__class__"]))
            for v in schema.values():
                keys.extend(self._extract_all_class_keys(v))
        elif isinstance(schema, list):
            for item in schema:
                keys.extend(self._extract_all_class_keys(item))
        return keys

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
