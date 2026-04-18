"""
Notebook Metadata Security Plugin.

Scans Jupyter notebook metadata for security-relevant information:
  - Kernel specification tampering
  - Suspicious execution counts / cell ordering
  - Hidden metadata fields that could carry payloads
  - Trust/signature metadata manipulation
  - Custom metadata injection vectors
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MetadataFinding:
    """A security finding in notebook metadata."""
    rule_id: str
    severity: str
    title: str
    description: str
    evidence: str
    cell_index: Optional[int] = None


# Known dangerous kernel specs
_SUSPICIOUS_KERNELS = {
    "bash", "sh", "zsh", "fish",
    "powershell", "cmd",
    "javascript", "typescript",
    "ruby", "perl", "php", "lua",
}

# Metadata keys that should never contain executable content
_INJECTABLE_KEYS = re.compile(
    r"(?:custom|widget|application/vnd|colab|papermill|tags)"
)

# Suspicious patterns in metadata values
_PAYLOAD_PATTERNS = [
    (re.compile(r"<script[^>]*>", re.I), "NOTEBOOK-META-001", "Script tag in metadata"),
    (re.compile(r"javascript:", re.I), "NOTEBOOK-META-002", "JavaScript URI in metadata"),
    (re.compile(r"data:text/html", re.I), "NOTEBOOK-META-003", "Data URI HTML payload"),
    (re.compile(r"on(?:load|error|click|mouseover)\s*=", re.I), "NOTEBOOK-META-004", "Event handler in metadata"),
    (re.compile(r"\{\{.*\}\}", re.I), "NOTEBOOK-META-005", "Template injection in metadata"),
    (re.compile(r"\\u00[0-9a-f]{2}", re.I), "NOTEBOOK-META-006", "Unicode escape sequences"),
    (re.compile(r"__import__\s*\(", re.I), "NOTEBOOK-META-007", "Python import in metadata"),
    (re.compile(r"exec\s*\(|eval\s*\(", re.I), "NOTEBOOK-META-008", "Code execution in metadata"),
]


class MetadataPlugin:
    """
    Scan Jupyter notebook metadata for security issues.

    Checks:
      - Kernel specification tampering
      - Suspicious execution count patterns
      - Metadata injection payloads
      - Hidden/custom metadata abuse
      - Trust and signature manipulation

    Usage:
        plugin = MetadataPlugin()
        findings = plugin.scan(notebook_dict)
    """

    def scan(self, notebook: dict) -> list[MetadataFinding]:
        """Scan a parsed notebook dict for metadata security issues."""
        findings = []

        # Top-level metadata
        metadata = notebook.get("metadata", {})
        findings.extend(self._check_kernel_spec(metadata))
        findings.extend(self._check_language_info(metadata))
        findings.extend(self._check_custom_metadata(metadata))
        findings.extend(self._check_trust(metadata))

        # Cell-level metadata
        for idx, cell in enumerate(notebook.get("cells", [])):
            cell_meta = cell.get("metadata", {})
            findings.extend(self._check_cell_metadata(cell_meta, idx))
            findings.extend(self._check_execution_count(cell, idx))

        return findings

    def _check_kernel_spec(self, metadata: dict) -> list[MetadataFinding]:
        """Check kernel specification for suspicious values."""
        findings = []
        kernel = metadata.get("kernelspec", {})
        kernel_name = kernel.get("name", "").lower()
        display_name = kernel.get("display_name", "")

        # Suspicious kernel
        if kernel_name in _SUSPICIOUS_KERNELS:
            findings.append(MetadataFinding(
                rule_id="NOTEBOOK-META-010",
                severity="HIGH",
                title="Suspicious kernel specification",
                description=f"Notebook uses '{kernel_name}' kernel which can execute system commands directly",
                evidence=f"kernelspec.name = {kernel_name}",
            ))

        # Display name mismatch (social engineering)
        if kernel_name and display_name:
            if "python" in display_name.lower() and "python" not in kernel_name:
                findings.append(MetadataFinding(
                    rule_id="NOTEBOOK-META-011",
                    severity="MEDIUM",
                    title="Kernel display name mismatch",
                    description=f"Display name says '{display_name}' but actual kernel is '{kernel_name}'",
                    evidence=f"display_name={display_name}, name={kernel_name}",
                ))

        return findings

    def _check_language_info(self, metadata: dict) -> list[MetadataFinding]:
        """Check language_info for inconsistencies."""
        findings = []
        lang = metadata.get("language_info", {})
        name = lang.get("name", "").lower()
        file_ext = lang.get("file_extension", "")

        if name and file_ext:
            expected_exts = {"python": ".py", "r": ".r", "julia": ".jl", "javascript": ".js"}
            expected = expected_exts.get(name)
            if expected and file_ext != expected:
                findings.append(MetadataFinding(
                    rule_id="NOTEBOOK-META-012",
                    severity="LOW",
                    title="Language extension mismatch",
                    description=f"Language '{name}' should use '{expected}' but has '{file_ext}'",
                    evidence=f"name={name}, file_extension={file_ext}",
                ))

        return findings

    def _check_custom_metadata(self, metadata: dict) -> list[MetadataFinding]:
        """Scan custom metadata fields for injection payloads."""
        findings = []
        self._scan_dict_recursive(metadata, findings, prefix="metadata")
        return findings

    def _scan_dict_recursive(self, obj: dict, findings: list, prefix: str, depth: int = 0) -> None:
        """Recursively scan dict values for payloads."""
        if depth > 10:
            return

        for key, value in obj.items():
            full_key = f"{prefix}.{key}"

            if isinstance(value, str):
                for pattern, rule_id, title in _PAYLOAD_PATTERNS:
                    if pattern.search(value):
                        findings.append(MetadataFinding(
                            rule_id=rule_id,
                            severity="HIGH",
                            title=title,
                            description=f"Suspicious content found in metadata key '{full_key}'",
                            evidence=value[:200],
                        ))
                        break

            elif isinstance(value, dict):
                self._scan_dict_recursive(value, findings, full_key, depth + 1)

            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        for pattern, rule_id, title in _PAYLOAD_PATTERNS:
                            if pattern.search(item):
                                findings.append(MetadataFinding(
                                    rule_id=rule_id,
                                    severity="HIGH",
                                    title=title,
                                    description=f"Suspicious content in '{full_key}[{i}]'",
                                    evidence=item[:200],
                                ))
                                break
                    elif isinstance(item, dict):
                        self._scan_dict_recursive(item, findings, f"{full_key}[{i}]", depth + 1)

    def _check_trust(self, metadata: dict) -> list[MetadataFinding]:
        """Check for manipulated trust/signature metadata."""
        findings = []

        # nbformat_minor downgrade
        if "signature" in metadata:
            findings.append(MetadataFinding(
                rule_id="NOTEBOOK-META-020",
                severity="MEDIUM",
                title="Notebook signature metadata present",
                description="Notebook contains signature metadata — verify it hasn't been tampered with",
                evidence=str(metadata["signature"])[:100],
            ))

        return findings

    def _check_cell_metadata(self, cell_meta: dict, idx: int) -> list[MetadataFinding]:
        """Check individual cell metadata."""
        findings = []

        # Trusting a cell
        if cell_meta.get("trusted") is True:
            # This is normal, but in combination with suspicious code, flag it
            pass

        # Hidden cells
        if cell_meta.get("jupyter", {}).get("source_hidden") is True:
            findings.append(MetadataFinding(
                rule_id="NOTEBOOK-META-030",
                severity="MEDIUM",
                title="Hidden source cell",
                description="Cell source is hidden — could conceal malicious code",
                evidence=f"cell[{idx}].metadata.jupyter.source_hidden = true",
                cell_index=idx,
            ))

        if cell_meta.get("jupyter", {}).get("outputs_hidden") is True:
            findings.append(MetadataFinding(
                rule_id="NOTEBOOK-META-031",
                severity="LOW",
                title="Hidden output cell",
                description="Cell output is hidden — could conceal exfiltrated data",
                evidence=f"cell[{idx}].metadata.jupyter.outputs_hidden = true",
                cell_index=idx,
            ))

        # Scan cell metadata values for payloads
        for key, value in cell_meta.items():
            if isinstance(value, str):
                for pattern, rule_id, title in _PAYLOAD_PATTERNS:
                    if pattern.search(value):
                        findings.append(MetadataFinding(
                            rule_id=rule_id,
                            severity="HIGH",
                            title=f"{title} (cell {idx})",
                            description=f"Suspicious content in cell[{idx}].metadata.{key}",
                            evidence=value[:200],
                            cell_index=idx,
                        ))
                        break

        return findings

    def _check_execution_count(self, cell: dict, idx: int) -> list[MetadataFinding]:
        """Check for suspicious execution count patterns."""
        findings = []

        exec_count = cell.get("execution_count")
        if exec_count is not None and isinstance(exec_count, int):
            # Extremely high execution count (potential DoS/loop indicator)
            if exec_count > 10000:
                findings.append(MetadataFinding(
                    rule_id="NOTEBOOK-META-040",
                    severity="LOW",
                    title="Abnormal execution count",
                    description=f"Cell {idx} has execution_count={exec_count}, which may indicate automated execution",
                    evidence=f"execution_count={exec_count}",
                    cell_index=idx,
                ))

        return findings
