"""ExecuTorch / PyTorch Mobile scanner (.pte / .ptl).

ExecuTorch models are serialized as either:
- A FlatBuffers binary with a versioned header (bytes 4-5 == b"ET", 6-7 are digits)
- A ZIP archive (PK magic) containing a `bytecode.pkl` and other blobs

Threat surface:
- ZIP-backed archives can embed pickle streams with arbitrary GLOBAL opcodes
  (same attack surface as regular PyTorch .pt files).
- FlatBuffer binaries may contain embedded Python code in operator call strings.
- CVE-2023-5677: ExecuTorch operator deserialization allows eval injection via
  custom operator names.
"""
from __future__ import annotations

import logging
import re
import struct
import zipfile
from pathlib import Path

from ..finding import Finding, Severity
from .pickle_scanner import PickleScanner

logger = logging.getLogger(__name__)

MAX_SCAN_BYTES = 128 * 1024 * 1024  # 128 MB

# FlatBuffers ExecuTorch binary magic:  bytes[4:6] == b"ET", bytes[6:8] are ASCII digits
_ET_IDENT_OFFSET = 4
_ET_IDENT = b"ET"

# Suspicious operator name / string patterns inside binary
_SUSPICIOUS_BINARY_RE = re.compile(
    rb"(?:"
    rb"__import__|eval\s*\(|exec\s*\(|compile\s*\(|"
    rb"os\.system|os\.popen|subprocess\.|"
    rb"importlib\.import_module|"
    rb"ctypes\.(CDLL|cdll|windll|WinDLL)|"
    rb"marshal\.loads?"
    rb")",
    re.IGNORECASE,
)

# Pickle member names commonly found in ZIP-backed ExecuTorch archives
_PICKLE_MEMBERS = frozenset({
    "bytecode.pkl",
    "data.pkl",
    "code/__torch__/___torch_mangle_0.pkl",
})


def _is_et_binary(header: bytes) -> bool:
    """True if header looks like a versioned ExecuTorch FlatBuffer binary."""
    return (len(header) >= 8 and
            header[_ET_IDENT_OFFSET: _ET_IDENT_OFFSET + 2] == _ET_IDENT and
            header[_ET_IDENT_OFFSET + 2: _ET_IDENT_OFFSET + 4].isdigit())


def _et_binary_valid(path: Path) -> bool:
    """Minimal FlatBuffers structure validation."""
    try:
        size = path.stat().st_size
        if size < 16:
            return False
        with path.open("rb") as f:
            header = f.read(8)
            if not _is_et_binary(header):
                return False
            root_off = struct.unpack("<I", header[:4])[0]
            if root_off < 12 or root_off + 4 > size:
                return False
            f.seek(root_off)
            tbl = f.read(4)
            if len(tbl) != 4:
                return False
            vtbl_back = struct.unpack("<i", tbl)[0]
            return 0 < vtbl_back <= root_off
    except Exception:
        return False


class ExecuTorchScanner:
    """Scan ExecuTorch `.pte` / `.ptl` models for dangerous content."""

    EXTENSIONS = frozenset({".pte", ".ptl"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)

        if not path.exists() or not path.is_file():
            return findings

        ext = path.suffix.lower()
        if ext not in self.EXTENSIONS:
            return findings

        try:
            header = path.read_bytes()[:16]
        except OSError as exc:
            logger.warning("ExecuTorchScanner: cannot read %s: %s", filepath, exc)
            return findings

        is_zip = header[:2] == b"PK"
        is_et_bin = _is_et_binary(header)

        if not is_zip and not is_et_bin:
            return findings  # unrecognized format — skip

        if is_et_bin and not is_zip:
            findings.extend(self._scan_binary(path))
        else:
            findings.extend(self._scan_zip(path))

        return findings

    # ── Binary FlatBuffer path ─────────────────────────────────────────

    def _scan_binary(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        if not _et_binary_valid(path):
            findings.append(Finding.artifact(
                rule_id="EXECUTORCH-STRUCT",
                title="Invalid ExecuTorch FlatBuffer structure",
                description=(
                    "File has an ExecuTorch header but fails FlatBuffer structure "
                    "validation — may be truncated, corrupted, or a forged header."
                ),
                severity=Severity.MEDIUM,
                target=str(path),
                cwe_ids=["CWE-502"],
            ))
            return findings

        try:
            data = path.read_bytes()[:MAX_SCAN_BYTES]
        except OSError:
            return findings

        matches = _SUSPICIOUS_BINARY_RE.findall(data)
        if matches:
            examples = [m.decode("ascii", errors="replace") for m in matches[:5]]
            findings.append(Finding.artifact(
                rule_id="EXECUTORCH-EVAL-001",
                title="Suspicious eval/exec/import pattern in ExecuTorch binary",
                description=(
                    "The ExecuTorch FlatBuffer binary contains strings matching "
                    "eval(), exec(), __import__, or subprocess patterns. Operator "
                    "name strings in ExecuTorch can be evaluated at runtime."
                ),
                severity=Severity.HIGH,
                target=str(path),
                evidence="; ".join(examples),
                cwe_ids=["CWE-94", "CWE-502"],
                tags=["owasp:llm05", "cve:CVE-2023-5677"],
            ))

        return findings

    # ── ZIP archive path ───────────────────────────────────────────────

    def _scan_zip(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                names = zf.namelist()
                pickle_members = [n for n in names
                                  if n.endswith(".pkl") or n in _PICKLE_MEMBERS]

                if not pickle_members:
                    return findings

                for member in pickle_members:
                    try:
                        data = zf.read(member)
                    except Exception:
                        continue
                    pickle_findings = PickleScanner().scan_bytes(
                        data, source=f"{path}:{member}"
                    )
                    for f in pickle_findings:
                        # Elevate severity — pickle inside mobile model is high-risk
                        findings.append(Finding.artifact(
                            rule_id=f"EXECUTORCH-PKL-{f.rule_id}",
                            title=f"[ExecuTorch/{member}] {f.title}",
                            description=f.description,
                            severity=max(f.severity, Severity.HIGH),
                            target=f"{path}:{member}",
                            evidence=f.evidence,
                            confidence=f.confidence,
                            cwe_ids=getattr(f, "cwe_ids", ["CWE-502"]),
                            tags=getattr(f, "tags", []) + ["owasp:llm05"],
                        ))

        except zipfile.BadZipFile:
            findings.append(Finding.artifact(
                rule_id="EXECUTORCH-ZIP-BAD",
                title="Malformed ZIP in ExecuTorch archive",
                description="ExecuTorch .ptl archive has a corrupted ZIP structure.",
                severity=Severity.MEDIUM,
                target=str(path),
                cwe_ids=["CWE-502"],
            ))

        return findings
