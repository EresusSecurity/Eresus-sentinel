"""Flax/JAX checkpoint scanner (.msgpack, .orbax, .flax)."""
from __future__ import annotations

import logging
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

MSGPACK_MAP_16 = 0xDE
MSGPACK_MAP_32 = 0xDF
MSGPACK_FIXMAP_RANGE = range(0x80, 0x90)
PICKLE_MARKERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
DANGEROUS_PATTERNS = [
    b"__import__", b"os.system", b"subprocess", b"eval(", b"exec(",
    b"builtins", b"pickle.loads", b"marshal",
]


class FlaxScanner:
    """Scan Flax/JAX .msgpack and .orbax checkpoints for pickle-based threats."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        suffix = path.suffix.lower()
        if suffix not in (".msgpack", ".orbax", ".flax"):
            return findings

        try:
            data = path.read_bytes()
        except OSError as e:
            logger.warning("Cannot read %s: %s", filepath, e)
            return findings

        self._check_msgpack_header(data, filepath, findings)
        self._check_pickle_inside(data, filepath, findings)
        self._check_suspicious_content(data, filepath, findings)
        self._check_numpy_deserialization(data, filepath, findings)
        self._check_size_anomaly(data, filepath, findings)

        if suffix == ".orbax" or path.is_dir():
            self._check_orbax_structure(path, findings)
        return findings

    def _check_msgpack_header(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        if len(data) < 1:
            findings.append(Finding.artifact(
                rule_id="FLAX-001", title="Empty Flax checkpoint",
                description="Checkpoint file is empty",
                severity=Severity.MEDIUM, target=fp,
            ))
            return
        first_byte = data[0]
        valid_start = (
            first_byte in MSGPACK_FIXMAP_RANGE
            or first_byte == MSGPACK_MAP_16
            or first_byte == MSGPACK_MAP_32
            or first_byte == 0x92  # fixarray(2)
            or first_byte == 0x93  # fixarray(3)
        )
        if not valid_start and first_byte not in (0xC4, 0xC5, 0xC6):
            findings.append(Finding.artifact(
                rule_id="FLAX-002", title="Unexpected Flax checkpoint header",
                description=f"First byte 0x{first_byte:02x} not a valid msgpack container",
                severity=Severity.MEDIUM, target=fp,
                evidence=f"header=0x{first_byte:02x}",
            ))

    def _check_pickle_inside(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        for marker in PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="FLAX-003", title="Pickle stream inside Flax checkpoint",
                    description=f"Pickle protocol marker at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=fp,
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-502"],
                ))
                break

    def _check_suspicious_content(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        for pattern in DANGEROUS_PATTERNS:
            idx = data.find(pattern)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="FLAX-004",
                    title=f"Dangerous string in Flax checkpoint: {pattern.decode(errors='replace')}",
                    description=f"Found at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=fp,
                    evidence=data[max(0,idx-10):idx+len(pattern)+10].decode(errors="replace")[:200],
                ))

    def _check_numpy_deserialization(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        npy_magic = b"\x93NUMPY"
        idx = data.find(npy_magic)
        if idx != -1:
            allow_pickle_nearby = data.find(b"allow_pickle", max(0, idx-500), idx+500)
            if allow_pickle_nearby != -1:
                findings.append(Finding.artifact(
                    rule_id="FLAX-005",
                    title="NumPy deserialization with allow_pickle in checkpoint",
                    description="Checkpoint contains numpy data with allow_pickle flag nearby",
                    severity=Severity.HIGH, target=fp,
                    evidence=f"npy_offset=0x{idx:x}",
                ))

    def _check_size_anomaly(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        if len(data) > 50_000_000_000:
            findings.append(Finding.artifact(
                rule_id="FLAX-006", title="Extremely large Flax checkpoint",
                description=f"Checkpoint is {len(data)/1e9:.1f} GB",
                severity=Severity.MEDIUM, target=fp,
            ))

    def _check_orbax_structure(self, path: Path, findings: list[Finding]) -> None:
        if path.is_dir():
            for child in path.rglob("*"):
                if child.suffix in (".py", ".sh", ".bat"):
                    findings.append(Finding.artifact(
                        rule_id="FLAX-007", title="Script file in Orbax checkpoint",
                        description=f"Executable file found: {child.name}",
                        severity=Severity.HIGH, target=str(path),
                        evidence=str(child),
                    ))
