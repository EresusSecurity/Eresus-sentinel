"""NVIDIA NeMo .nemo (tar-based) model scanner."""
from __future__ import annotations

import logging
import tarfile
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

PICKLE_MARKERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
EXPECTED_NEMO_FILES = {"model_config.yaml", "model_weights.ckpt"}
DANGEROUS_STRINGS = [
    b"__import__", b"os.system", b"subprocess", b"eval(", b"exec(",
    b"/bin/sh", b"/bin/bash", b"curl ", b"wget ",
]


class NeMoScanner:
    """Scan NVIDIA NeMo .nemo archives for embedded pickle and script threats."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".nemo":
            return findings

        if not tarfile.is_tarfile(str(path)):
            findings.append(Finding.artifact(
                rule_id="NEMO-001", title="Invalid NeMo archive",
                description="NeMo file is not a valid tar archive",
                severity=Severity.HIGH, target=filepath,
            ))
            return findings

        try:
            with tarfile.open(str(path), "r:*") as tf:
                members = tf.getmembers()
                self._check_path_traversal(members, filepath, findings)
                self._check_unexpected_files(members, filepath, findings)
                self._check_symlinks(members, filepath, findings)
                for member in members:
                    if member.isfile() and member.size < 50_000_000:
                        try:
                            f = tf.extractfile(member)
                            if f:
                                data = f.read()
                                self._check_member_content(data, member.name, filepath, findings)
                        except Exception:
                            pass
        except (tarfile.TarError, OSError) as e:
            findings.append(Finding.artifact(
                rule_id="NEMO-002", title="Error reading NeMo archive",
                description=str(e), severity=Severity.MEDIUM, target=filepath,
            ))
        return findings

    def _check_path_traversal(self, members: list, fp: str, findings: list[Finding]) -> None:
        for m in members:
            if m.name.startswith("/") or ".." in m.name:
                findings.append(Finding.artifact(
                    rule_id="NEMO-003", title="Path traversal in NeMo archive",
                    description=f"Member path: {m.name}",
                    severity=Severity.CRITICAL, target=fp,
                    evidence=m.name, cwe_ids=["CWE-22"],
                ))

    def _check_unexpected_files(self, members: list, fp: str, findings: list[Finding]) -> None:
        for m in members:
            name_lower = m.name.lower()
            if name_lower.endswith((".py", ".sh", ".bat", ".exe", ".so", ".dll")):
                findings.append(Finding.artifact(
                    rule_id="NEMO-004", title=f"Executable file in NeMo archive: {m.name}",
                    description="NeMo models should not contain executable files",
                    severity=Severity.HIGH, target=fp, evidence=m.name,
                ))

    def _check_symlinks(self, members: list, fp: str, findings: list[Finding]) -> None:
        for m in members:
            if m.issym() or m.islnk():
                findings.append(Finding.artifact(
                    rule_id="NEMO-005", title="Symlink in NeMo archive",
                    description=f"Symlink {m.name} -> {m.linkname}",
                    severity=Severity.HIGH, target=fp,
                    evidence=f"{m.name} -> {m.linkname}", cwe_ids=["CWE-59"],
                ))

    def _check_member_content(self, data: bytes, name: str, fp: str, findings: list[Finding]) -> None:
        for marker in PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                stop = data.find(b".", idx)
                if stop != -1:
                    global_op = data.find(b"c", idx, stop)
                    stack_global = data.find(b"\x93", idx, stop)
                    if global_op != -1 or stack_global != -1:
                        findings.append(Finding.artifact(
                            rule_id="NEMO-006",
                            title=f"Pickle with imports in NeMo member: {name}",
                            description=f"Pickle stream with GLOBAL opcode at offset 0x{idx:x}",
                            severity=Severity.CRITICAL, target=fp,
                            evidence=f"{name}:0x{idx:x}", cwe_ids=["CWE-502"],
                        ))
                break
        for pat in DANGEROUS_STRINGS:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="NEMO-007",
                    title=f"Suspicious string in NeMo member {name}: {pat.decode(errors='replace')}",
                    description="Dangerous pattern found",
                    severity=Severity.HIGH, target=fp, evidence=f"{name}: {pat.decode(errors='replace')}",
                ))
