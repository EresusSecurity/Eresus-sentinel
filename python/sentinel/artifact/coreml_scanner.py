"""Apple CoreML .mlmodel / .mlpackage scanner."""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

PROTOBUF_WIRE_TYPES = {0: "varint", 1: "64-bit", 2: "length-delimited", 5: "32-bit"}
DANGEROUS_CUSTOM_LAYER_NAMES = [
    "eval", "exec", "system", "popen", "subprocess", "os.", "shutil",
    "__import__", "compile", "marshal",
]


class CoreMLScanner:
    """Scan Apple CoreML .mlmodel and .mlpackage files for unsafe operations."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        suffix = path.suffix.lower()

        if suffix == ".mlpackage":
            self._scan_mlpackage(path, findings)
        elif suffix == ".mlmodel":
            self._scan_mlmodel(path, findings)
        else:
            return findings
        return findings

    def _scan_mlpackage(self, path: Path, findings: list[Finding]) -> None:
        if not zipfile.is_zipfile(str(path)):
            findings.append(Finding.artifact(
                rule_id="COREML-001", title="Invalid mlpackage (not a ZIP)",
                description="mlpackage should be a ZIP archive",
                severity=Severity.MEDIUM, target=str(path),
            ))
            return
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="COREML-002", title="Path traversal in mlpackage",
                            description=f"Suspicious path: {info.filename}",
                            severity=Severity.CRITICAL, target=str(path),
                            evidence=info.filename, cwe_ids=["CWE-22"],
                        ))
                    if info.filename.endswith(".mlmodel"):
                        data = zf.read(info.filename)
                        self._scan_protobuf_data(data, str(path), findings)
                    if info.filename.endswith((".py", ".sh", ".bat")):
                        findings.append(Finding.artifact(
                            rule_id="COREML-003", title="Executable script in mlpackage",
                            description=f"Script file found: {info.filename}",
                            severity=Severity.HIGH, target=str(path),
                            evidence=info.filename,
                        ))
        except zipfile.BadZipFile:
            findings.append(Finding.artifact(
                rule_id="COREML-004", title="Corrupted mlpackage ZIP",
                description="ZIP file is corrupted", severity=Severity.HIGH,
                target=str(path),
            ))

    def _scan_mlmodel(self, path: Path, findings: list[Finding]) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        self._scan_protobuf_data(data, str(path), findings)

    def _scan_protobuf_data(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        if len(data) < 4:
            findings.append(Finding.artifact(
                rule_id="COREML-005", title="CoreML model too small",
                description="Model data smaller than valid protobuf",
                severity=Severity.MEDIUM, target=fp,
            ))
            return

        for name in DANGEROUS_CUSTOM_LAYER_NAMES:
            name_bytes = name.encode()
            idx = data.find(name_bytes)
            if idx != -1:
                context = data[max(0, idx-30):idx+len(name_bytes)+30]
                findings.append(Finding.artifact(
                    rule_id="COREML-006",
                    title=f"Suspicious custom layer reference: {name}",
                    description=f"CoreML model references potentially dangerous name at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=fp,
                    evidence=context.decode(errors="replace")[:200],
                ))

        pickle_idx = data.find(b"\x80\x02")
        if pickle_idx == -1:
            pickle_idx = data.find(b"\x80\x04")
        if pickle_idx != -1:
            findings.append(Finding.artifact(
                rule_id="COREML-007", title="Pickle data inside CoreML model",
                description=f"Pickle stream detected at offset 0x{pickle_idx:x}",
                severity=Severity.CRITICAL, target=fp,
                evidence=f"offset=0x{pickle_idx:x}", cwe_ids=["CWE-502"],
            ))

        shell_patterns = [b"/bin/sh", b"/bin/bash", b"cmd.exe", b"powershell"]
        for pat in shell_patterns:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="COREML-008", title=f"Shell reference in CoreML: {pat.decode()}",
                    description="Model contains shell command references",
                    severity=Severity.CRITICAL, target=fp,
                    evidence=pat.decode(),
                ))

        if len(data) > 10_000_000_000:
            findings.append(Finding.artifact(
                rule_id="COREML-009", title="Abnormally large CoreML model",
                description=f"Model is {len(data)/1e9:.1f} GB",
                severity=Severity.MEDIUM, target=fp,
            ))
