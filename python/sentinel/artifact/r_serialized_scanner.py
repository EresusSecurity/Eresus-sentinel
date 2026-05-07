"""R serialized format (.rds/.rda/.rdata) scanner.

Detects:
- R code execution primitives (system, eval, parse, dyn.load, etc.)
- Network activity (curl, wget, download.file, socketConnection)
- Hardcoded URLs and suspicious commands
- Embedded PE/ELF executables
- Supports gzip / bzip2 / xz compressed R workspace files
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import logging
import re
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

_SUPPORTED_EXTENSIONS = frozenset({".rds", ".rda", ".rdata"})

_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_WORKSPACE_HEADERS = (b"RDX2\n", b"RDX3\n", b"RDA2\n", b"RDA3\n")

_PRINTABLE_RE = re.compile(rb"[ -~]{4,512}")

_EXEC_RE = re.compile(
    r"(?<![\w.])(?:base::|utils::)?"
    r"(?:system2?|eval|parse|source|do\.call|dyn\.load"
    r"|socketConnection|socket|pipe|url|download\.file"
    r"|setattr|globalenv|environment|new\.env"
    r"|readLines|writeLines|file\.create|unlink)"
    r"(?![\w.])",
    re.IGNORECASE,
)

_NETWORK_RE = re.compile(
    r"(?i)\b("
    r"curl|wget|powershell|invoke-webrequest|cmd(?:\.exe)?|/bin/sh|/bin/bash"
    r"|python\s+-c|rscript\s+-e|rm\s+-rf|chmod\s+\+x|nc|netcat"
    r")\b"
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]{8,}", re.IGNORECASE)


def _decompress(raw: bytes) -> bytes | None:
    """Try gzip / bzip2 / xz decompression; return None on failure."""
    if raw[:2] == _GZIP_MAGIC:
        try:
            return gzip.decompress(raw)
        except Exception:
            return None
    if raw[:3] == _BZIP2_MAGIC:
        try:
            return bz2.decompress(raw)
        except Exception:
            return None
    if raw[:6] == _XZ_MAGIC:
        try:
            return lzma.decompress(raw, memlimit=128 * 1024 * 1024)
        except Exception:
            return None
    return raw


def _extract_strings(data: bytes) -> list[str]:
    return [m.group().decode("latin-1") for m in _PRINTABLE_RE.finditer(data)]


class RSerializedScanner:
    """Static scanner for R serialized model artifacts (.rds/.rda/.rdata).

    Performs string extraction after decompression and applies regex-based
    detection for R code execution, network activity, and embedded executables.
    No R runtime is required.
    """

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in _SUPPORTED_EXTENSIONS:
            return findings

        try:
            raw = path.read_bytes()
        except OSError as exc:
            logger.debug("R scanner: cannot read %s: %s", filepath, exc)
            return findings

        data = _decompress(raw)
        if data is None:
            findings.append(Finding.artifact(
                rule_id="R-001",
                title="Corrupted compressed R file",
                description="Decompression failed — file may be truncated or obfuscated.",
                severity=Severity.MEDIUM,
                target=filepath,
            ))
            return findings

        strings = _extract_strings(data)
        seen_exec: set[str] = set()
        seen_net: set[str] = set()
        seen_url: set[str] = set()

        for s in strings:
            m = _EXEC_RE.search(s)
            if m:
                func = m.group().strip()
                if func not in seen_exec:
                    seen_exec.add(func)
                    findings.append(Finding.artifact(
                        rule_id="R-002",
                        title=f"R code execution: {func}",
                        description=(
                            f"R serialized file contains '{func}' — a function that can "
                            "execute arbitrary code or load native libraries when the object is loaded."
                        ),
                        severity=Severity.HIGH,
                        target=filepath,
                        evidence=s[:200],
                        cwe_ids=["CWE-502", "CWE-94"],
                    ))

            mn = _NETWORK_RE.search(s)
            if mn:
                cmd = mn.group(1).strip()
                if cmd not in seen_net:
                    seen_net.add(cmd)
                    findings.append(Finding.artifact(
                        rule_id="R-003",
                        title=f"Network/shell command in R file: {cmd}",
                        description="Shell or network command string embedded in R serialized object.",
                        severity=Severity.CRITICAL,
                        target=filepath,
                        evidence=s[:200],
                        cwe_ids=["CWE-78", "CWE-918"],
                    ))

            for mu in _URL_RE.finditer(s):
                url = mu.group()
                if url not in seen_url:
                    seen_url.add(url)
                    findings.append(Finding.artifact(
                        rule_id="R-004",
                        title="Hardcoded URL in R file",
                        description=f"URL may indicate C2 or data-exfiltration: {url[:120]}",
                        severity=Severity.MEDIUM,
                        target=filepath,
                        evidence=url[:200],
                        cwe_ids=["CWE-912"],
                    ))

        for label, magic in [("ELF", b"\x7fELF"), ("PE", b"MZ\x90\x00"), ("PE", b"MZ")]:
            idx = data.find(magic)
            if idx > 16:
                findings.append(Finding.artifact(
                    rule_id="R-005",
                    title=f"Embedded {label} executable in R file",
                    description=f"{label} binary header at offset 0x{idx:x} — potential dropper.",
                    severity=Severity.CRITICAL,
                    target=filepath,
                    cwe_ids=["CWE-506"],
                ))
                break

        return findings
