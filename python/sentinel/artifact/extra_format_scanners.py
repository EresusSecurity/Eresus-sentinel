"""CNTK, JAX checkpoint, RKNN model format scanners."""
from __future__ import annotations
import logging
from pathlib import Path
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


class CNTKScanner:
    """Microsoft CNTK model scanner."""
    EXTENSIONS = {".cntk", ".dnn", ".cmf"}

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self.EXTENSIONS:
            return findings
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        for pat in [b"__import__", b"eval(", b"exec(", b"os.system", b"subprocess"]:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="CNTK-001", title=f"Dangerous call in CNTK model: {pat.decode()}",
                    description="CNTK model contains executable code pattern",
                    severity=Severity.CRITICAL, target=filepath, evidence=pat.decode(),
                ))
        if b"pickle" in data.lower() if isinstance(data, bytes) else b"":
            findings.append(Finding.artifact(
                rule_id="CNTK-002", title="Pickle serialization in CNTK model",
                description="CNTK model may use pickle deserialization",
                severity=Severity.HIGH, target=filepath, cwe_ids=["CWE-502"],
            ))
        return findings


class JAXCheckpointScanner:
    """JAX/Orbax checkpoint scanner."""
    EXTENSIONS = {".orbax", ".ckpt", ".msgpack"}

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        try:
            data = path.read_bytes()[:8192]
        except OSError:
            return findings
        if b"pickle" in data or b"\x80\x02" in data[:4] or b"\x80\x05" in data[:4]:
            findings.append(Finding.artifact(
                rule_id="JAX-001", title="Pickle detected in JAX checkpoint",
                description="JAX checkpoint contains pickle serialization",
                severity=Severity.HIGH, target=filepath, cwe_ids=["CWE-502"],
            ))
        for pat in [b"__import__", b"eval(", b"exec(", b"os.system"]:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="JAX-002", title=f"Dangerous pattern in JAX checkpoint: {pat.decode()}",
                    description="Executable code in JAX checkpoint",
                    severity=Severity.CRITICAL, target=filepath,
                ))
        if path.is_dir():
            for child in path.rglob("*"):
                if child.suffix == ".pkl":
                    findings.append(Finding.artifact(
                        rule_id="JAX-003", title=f"Pickle file in JAX checkpoint: {child.name}",
                        description="Pickle file inside Orbax checkpoint directory",
                        severity=Severity.HIGH, target=filepath, evidence=str(child),
                    ))
        return findings


class RKNNScanner:
    """Rockchip RKNN model scanner."""
    RKNN_MAGIC = b"RKNN"

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".rknn":
            return findings
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        if data[:4] != self.RKNN_MAGIC:
            findings.append(Finding.artifact(
                rule_id="RKNN-001", title="Invalid RKNN magic bytes",
                description=f"Expected RKNN, got {data[:4].hex()}",
                severity=Severity.MEDIUM, target=filepath,
            ))
        for pat in [b"__import__", b"eval(", b"exec(", b"os.system", b"subprocess"]:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="RKNN-002", title=f"Dangerous pattern in RKNN: {pat.decode()}",
                    description="RKNN model contains executable code",
                    severity=Severity.CRITICAL, target=filepath,
                ))
        if len(data) > 100_000_000:
            findings.append(Finding.artifact(
                rule_id="RKNN-003", title="Unusually large RKNN model",
                description=f"Size: {len(data) / 1e6:.0f}MB — may contain embedded payloads",
                severity=Severity.MEDIUM, target=filepath,
            ))
        return findings
