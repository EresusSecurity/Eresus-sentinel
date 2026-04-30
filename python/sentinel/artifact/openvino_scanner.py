"""OpenVINO IR .xml + .bin scanner."""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

DANGEROUS_LAYER_TYPES = [
    "Custom", "Extension", "Plugin", "Native", "ExternalCall",
    "PythonOp", "ShellExec", "SystemCall",
]


class OpenVINOScanner:
    """Scan OpenVINO IR .xml/.bin model pairs for security issues."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        suffix = path.suffix.lower()
        if suffix == ".xml":
            self._scan_ir_xml(path, findings)
        elif suffix == ".bin":
            self._scan_weights_bin(path, findings)
        return findings

    def _scan_ir_xml(self, path: Path, findings: list[Finding]) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        if "<!ENTITY" in text or "<!DOCTYPE" in text:
            findings.append(Finding.artifact(
                rule_id="OPENVINO-001", title="XXE risk in OpenVINO IR XML",
                description="XML contains DOCTYPE/ENTITY declarations — potential XXE attack",
                severity=Severity.CRITICAL, target=str(path),
                evidence="DOCTYPE or ENTITY declaration found", cwe_ids=["CWE-611"],
            ))

        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            findings.append(Finding.artifact(
                rule_id="OPENVINO-002", title="Invalid OpenVINO IR XML",
                description=str(e), severity=Severity.MEDIUM, target=str(path),
            ))
            return

        if root.tag != "net":
            findings.append(Finding.artifact(
                rule_id="OPENVINO-003", title="Unexpected root element in OpenVINO IR",
                description=f"Expected 'net', got '{root.tag}'",
                severity=Severity.MEDIUM, target=str(path),
            ))

        layers = root.find("layers")
        if layers is not None:
            for layer in layers:
                layer_type = layer.get("type", "")
                for dangerous in DANGEROUS_LAYER_TYPES:
                    if dangerous.lower() in layer_type.lower():
                        findings.append(Finding.artifact(
                            rule_id="OPENVINO-004",
                            title=f"Suspicious layer type in OpenVINO: {layer_type}",
                            description=f"Layer '{layer.get('name','')}' has potentially dangerous type",
                            severity=Severity.HIGH, target=str(path),
                            evidence=f"type={layer_type}, name={layer.get('name','')}",
                        ))

                for elem in layer.iter():
                    for attr_val in elem.attrib.values():
                        if any(d in attr_val for d in ["eval(", "exec(", "__import__", "os.system"]):
                            findings.append(Finding.artifact(
                                rule_id="OPENVINO-005",
                                title="Code injection in OpenVINO layer attributes",
                                description=f"Dangerous value in attribute: {attr_val[:100]}",
                                severity=Severity.CRITICAL, target=str(path),
                                evidence=attr_val[:200],
                            ))

        bin_path = path.with_suffix(".bin")
        if bin_path.exists():
            xml_size = path.stat().st_size
            bin_size = bin_path.stat().st_size
            if xml_size > 0 and bin_size > xml_size * 10000:
                findings.append(Finding.artifact(
                    rule_id="OPENVINO-006",
                    title="Weight file size mismatch",
                    description=f"Bin file ({bin_size/1e6:.1f} MB) is disproportionately larger than XML ({xml_size} bytes)",
                    severity=Severity.MEDIUM, target=str(path),
                ))

    def _scan_weights_bin(self, path: Path, findings: list[Finding]) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        dangerous = [b"__import__", b"os.system", b"subprocess", b"eval(", b"exec("]
        for pat in dangerous:
            idx = data.find(pat)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="OPENVINO-007",
                    title=f"Suspicious string in OpenVINO weights: {pat.decode()}",
                    description=f"Found at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=str(path),
                    evidence=f"offset=0x{idx:x}",
                ))
        for label, magic in [("ELF", b"\x7fELF"), ("PE", b"MZ")]:
            idx = data.find(magic)
            if idx > 10:
                findings.append(Finding.artifact(
                    rule_id="OPENVINO-008",
                    title=f"Embedded {label} in OpenVINO weights",
                    description=f"{label} binary at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=str(path),
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-506"],
                ))
