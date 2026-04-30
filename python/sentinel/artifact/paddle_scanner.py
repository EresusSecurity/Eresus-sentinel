"""PaddlePaddle .pdmodel + .pdiparams scanner."""
from __future__ import annotations

import logging
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

PICKLE_MARKERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
DANGEROUS_OPS = [
    "custom_op", "py_func", "py_layer", "exec", "eval", "system",
    "plugin_op", "shell", "subprocess",
]


class PaddleScanner:
    """Scan PaddlePaddle .pdmodel/.pdiparams files for security issues."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        suffix = path.suffix.lower()
        if suffix == ".pdmodel":
            self._scan_pdmodel(path, findings)
        elif suffix == ".pdiparams":
            self._scan_pdiparams(path, findings)
        elif suffix == ".pdparams":
            self._scan_pdiparams(path, findings)
        return findings

    def _scan_pdmodel(self, path: Path, findings: list[Finding]) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        if len(data) < 4:
            findings.append(Finding.artifact(
                rule_id="PADDLE-001", title="PaddlePaddle model too small",
                description="pdmodel file is smaller than valid protobuf",
                severity=Severity.MEDIUM, target=str(path),
            ))
            return

        for op in DANGEROUS_OPS:
            op_bytes = op.encode()
            idx = data.find(op_bytes)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="PADDLE-002",
                    title=f"Suspicious op in PaddlePaddle model: {op}",
                    description=f"Potentially dangerous operation reference at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=str(path), evidence=op,
                ))

        dangerous = [b"__import__", b"os.system", b"subprocess", b"eval(", b"exec("]
        for pat in dangerous:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="PADDLE-003",
                    title=f"Code injection in PaddlePaddle model: {pat.decode()}",
                    description="Dangerous pattern in model protobuf",
                    severity=Severity.CRITICAL, target=str(path),
                    evidence=pat.decode(), cwe_ids=["CWE-94"],
                ))

        for marker in PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="PADDLE-004", title="Pickle stream in PaddlePaddle model",
                    description=f"Pickle data at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=str(path),
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-502"],
                ))
                break

    def _scan_pdiparams(self, path: Path, findings: list[Finding]) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return

        for marker in PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="PADDLE-005", title="Pickle in PaddlePaddle params",
                    description=f"Pickle data at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=str(path),
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-502"],
                ))
                break

        dangerous = [b"__import__", b"os.system", b"subprocess"]
        for pat in dangerous:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="PADDLE-006",
                    title=f"Suspicious string in PaddlePaddle params: {pat.decode()}",
                    severity=Severity.HIGH, target=str(path),
                    description="Dangerous pattern in parameter file",
                    evidence=pat.decode(),
                ))

        model_path = path.with_suffix(".pdmodel")
        if model_path.exists():
            model_size = model_path.stat().st_size
            param_size = path.stat().st_size
            if model_size > 0 and param_size > model_size * 10000:
                findings.append(Finding.artifact(
                    rule_id="PADDLE-007",
                    title="Params/model size mismatch",
                    description=f"Params ({param_size/1e6:.1f} MB) disproportionate to model ({model_size} bytes)",
                    severity=Severity.MEDIUM, target=str(path),
                ))
