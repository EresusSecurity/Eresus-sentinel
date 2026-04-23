"""CatBoost .cbm binary model scanner."""
from __future__ import annotations
import logging
import struct
from pathlib import Path
from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

CATBOOST_MAGIC = b"\xa0\xb1\xc2\xd3"
PICKLE_MAGIC = b"\x80"
SUSPICIOUS_STRINGS = [
    b"__import__", b"os.system", b"subprocess", b"eval(", b"exec(",
    b"/bin/sh", b"/bin/bash", b"curl ", b"wget ", b"socket.socket",
    b"base64.b64decode", b"marshal.loads", b"<script", b"javascript:",
]


class CatBoostScanner:
    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        try:
            data = path.read_bytes()
        except OSError as e:
            logger.warning("Cannot read %s: %s", filepath, e)
            return findings

        if path.suffix.lower() != ".cbm":
            return findings

        self._check_magic(data, filepath, findings)
        self._check_pickle_inside(data, filepath, findings)
        self._check_suspicious_strings(data, filepath, findings)
        self._check_file_size(data, filepath, findings)
        self._check_embedded_blobs(data, filepath, findings)
        return findings

    def _check_magic(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        if len(data) < 4:
            findings.append(Finding.artifact(
                rule_id="CATBOOST-001", title="CatBoost file too small",
                description="File is smaller than minimum CatBoost header size",
                severity=Severity.HIGH, target=fp, evidence=f"size={len(data)}",
            ))
            return
        if data[:4] != CATBOOST_MAGIC:
            header_hex = data[:4].hex()
            findings.append(Finding.artifact(
                rule_id="CATBOOST-002", title="Invalid CatBoost magic bytes",
                description=f"Expected a0b1c2d3, got {header_hex}",
                severity=Severity.MEDIUM, target=fp, evidence=header_hex,
            ))

    def _check_pickle_inside(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        offset = 0
        count = 0
        while offset < len(data) - 2:
            idx = data.find(PICKLE_MAGIC, offset)
            if idx == -1:
                break
            if idx + 1 < len(data) and data[idx + 1] <= 5:
                stop_idx = data.find(b".", idx + 2)
                if stop_idx != -1 and stop_idx - idx < 1_000_000:
                    global_idx = data.find(b"c", idx, stop_idx)
                    stack_global = data.find(b"\x93", idx, stop_idx)
                    if global_idx != -1 or stack_global != -1:
                        count += 1
                        if count <= 3:
                            findings.append(Finding.artifact(
                                rule_id="CATBOOST-003",
                                title="Pickle stream with imports inside CatBoost model",
                                description=f"Pickle data with GLOBAL/STACK_GLOBAL opcode at offset 0x{idx:x}",
                                severity=Severity.CRITICAL, target=fp,
                                evidence=f"offset=0x{idx:x}",
                                cwe_ids=["CWE-502"],
                            ))
            offset = idx + 1

    def _check_suspicious_strings(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        for pattern in SUSPICIOUS_STRINGS:
            idx = data.find(pattern)
            if idx != -1:
                context = data[max(0, idx - 20):idx + len(pattern) + 20]
                findings.append(Finding.artifact(
                    rule_id="CATBOOST-004",
                    title=f"Suspicious string in CatBoost model: {pattern.decode(errors='replace')}",
                    description=f"Potentially dangerous string found at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=fp,
                    evidence=context.decode(errors="replace")[:200],
                ))

    def _check_file_size(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        if len(data) > 5_000_000_000:
            findings.append(Finding.artifact(
                rule_id="CATBOOST-005", title="Abnormally large CatBoost model",
                description=f"Model file is {len(data) / 1e9:.1f} GB — may contain hidden data",
                severity=Severity.MEDIUM, target=fp, evidence=f"size={len(data)}",
            ))

    def _check_embedded_blobs(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        elf_magic = b"\x7fELF"
        pe_magic = b"MZ"
        for label, magic in [("ELF binary", elf_magic), ("PE executable", pe_magic)]:
            idx = data.find(magic)
            if idx > 4:
                findings.append(Finding.artifact(
                    rule_id="CATBOOST-006",
                    title=f"Embedded {label} in CatBoost model",
                    description=f"{label} signature at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=fp,
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-506"],
                ))
