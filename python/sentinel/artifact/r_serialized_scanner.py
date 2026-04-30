"""R serialized format (.rds/.rda/.rdata) scanner."""
from __future__ import annotations

import gzip
import logging
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)
R_MAGIC = b"RD"
DANGEROUS_R = [b"system(", b"system2(", b"eval(", b"parse(", b"source(", b"shell(", b"exec(", b".C(", b".Call(", b".Fortran(", b".External(", b"dyn.load("]


class RSerializedScanner:
    """Scan R serialized .rds/.rda/.rdata files for deserialization risks."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in (".rds", ".rda", ".rdata"):
            return findings
        try:
            raw = path.read_bytes()
        except OSError:
            return findings
        data = raw
        if raw[:2] == b"\x1f\x8b":
            try:
                data = gzip.decompress(raw)
            except Exception:
                findings.append(Finding.artifact(
                    rule_id="R-001", title="Corrupted gzip in R file",
                    description="Cannot decompress", severity=Severity.MEDIUM, target=filepath,
                ))
                return findings
        for pat in DANGEROUS_R:
            idx = data.find(pat)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="R-002", title=f"Dangerous R function: {pat.decode(errors='replace')}",
                    description=f"R native code execution at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=filepath, evidence=pat.decode(errors="replace"),
                ))
        for label, magic in [("ELF", b"\x7fELF"), ("PE", b"MZ")]:
            idx = data.find(magic)
            if idx > 10:
                findings.append(Finding.artifact(
                    rule_id="R-003", title=f"Embedded {label} in R file",
                    description=f"{label} at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=filepath, cwe_ids=["CWE-506"],
                ))
        return findings
