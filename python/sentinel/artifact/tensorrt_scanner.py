"""TensorRT engine file scanner (.engine / .plan / .trt).

TensorRT serialized engines are opaque GPU-compiled binaries that:
- Can embed arbitrary Linux shared objects (.so) or Windows DLLs via
  custom plugins loaded at runtime (LoadLibrary / dlopen).
- May reference path-traversal strings or Python/exec primitives if
  the engine was produced by a malicious workflow.
- Can contain embedded PE or ELF executables injected as polyglot payloads.

Threat references:
- NVIDIA TRT plugin ABI: setLoggerFinder / getPluginCreators entry points
- CVE-2024-0213: TensorRT engine deserialization RCE (CVSS 8.2)
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

MAX_SCAN_BYTES = 256 * 1024 * 1024  # 256 MB — engines can be large
MAX_STRINGS = 10_000

# ── String extraction ──────────────────────────────────────────────────────
_ASCII_RE = re.compile(rb"[\t\n\r\x20-\x7e]{4,}")
_UTF16LE_RE = re.compile(rb"(?:(?:[\t\n\r\x20-\x7e]\x00){4,})")


def _iter_strings(data: bytes) -> Iterator[str]:
    count = 0
    seen: set[str] = set()
    for pattern in (_ASCII_RE, _UTF16LE_RE):
        for m in pattern.finditer(data):
            raw = m.group()
            try:
                s = raw.decode("utf-16-le" if b"\x00" in raw[:2] else "ascii",
                               errors="replace").strip()
            except Exception:
                continue
            if s and s not in seen:
                seen.add(s)
                yield s
                count += 1
                if count >= MAX_STRINGS:
                    return


# ── Suspicious string patterns ─────────────────────────────────────────────
_SUSPICIOUS_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    # path traversal
    ("TRT-PATH-001", "Path traversal string in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_.\-])(?:\.\./|\.\.\\)", re.IGNORECASE),
     Severity.HIGH),
    # /tmp write
    ("TRT-TMP-001", "/tmp path reference in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_.\-])(?:/tmp/|(?:[A-Za-z]:)?\\tmp\\)", re.IGNORECASE),
     Severity.MEDIUM),
    # .so shared-object reference
    ("TRT-SO-001", "Shared-object (.so) reference — possible plugin load",
     re.compile(r"(?<![A-Za-z0-9_.\-])(?:[A-Za-z0-9_+.\-]+)?\.so(?:\.[0-9]+(?:\.[0-9]+)*)?(?![A-Za-z0-9_.\-])", re.IGNORECASE),
     Severity.MEDIUM),
    # .dll reference
    ("TRT-DLL-001", "DLL reference in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_.\-])(?:[A-Za-z0-9_+.\-]+)?\.dll(?![A-Za-z0-9_.\-])", re.IGNORECASE),
     Severity.MEDIUM),
    # LoadLibrary
    ("TRT-LOAD-001", "LoadLibrary call in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_])LoadLibrary(?:Ex)?[AW]?(?![A-Za-z0-9_])", re.IGNORECASE),
     Severity.HIGH),
    # TRT plugin entry points (legitimate OR hijacked)
    ("TRT-PLUGIN-001", "TensorRT plugin entry-point symbol",
     re.compile(r"(?<![A-Za-z0-9_])(?:setLoggerFinder|getCreators|getPluginCreators)(?![A-Za-z0-9_])"),
     Severity.MEDIUM),
    # Python interpreter reference
    ("TRT-PY-001", "Python interpreter reference in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_])python(?:[0-9.]+)?(?:\.exe)?(?![A-Za-z0-9_])", re.IGNORECASE),
     Severity.HIGH),
    # import keyword (Python / dynamic loading)
    ("TRT-IMPORT-001", "import keyword in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_])import(?![A-Za-z0-9_])", re.IGNORECASE),
     Severity.MEDIUM),
    # exec family
    ("TRT-EXEC-001", "exec() / execv*() call in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_])(?:execvpe|execvp|execve|execlpe|execlp|execle|execl|execv|exec)(?![A-Za-z0-9_])", re.IGNORECASE),
     Severity.HIGH),
    # eval
    ("TRT-EVAL-001", "eval() call in TensorRT engine",
     re.compile(r"(?<![A-Za-z0-9_])eval(?![A-Za-z0-9_])", re.IGNORECASE),
     Severity.HIGH),
]

# ── PE / ELF embedded binary ───────────────────────────────────────────────
_PE_SIGNATURE = b"PE\x00\x00"
_ELF_SIGNATURE = b"\x7fELF"
_PE_POINTER_OFFSET = 0x3C
_ELF_EXECUTABLE_TYPES = {2, 3}   # ET_EXEC, ET_DYN
_ELF_SUPPORTED_MACHINES = {3, 40, 62, 183}  # x86, ARM, x86_64, AArch64


def _find_embedded_pe(data: bytes) -> int | None:
    offset = 0
    while True:
        mz = data.find(b"MZ", offset)
        if mz < 0:
            break
        if mz + _PE_POINTER_OFFSET + 4 <= len(data):
            pe_off = int.from_bytes(data[mz + _PE_POINTER_OFFSET: mz + _PE_POINTER_OFFSET + 4], "little")
            abs_pe = mz + pe_off
            if (0x40 <= pe_off <= 0x100000 and
                    abs_pe + 4 <= len(data) and
                    data[abs_pe: abs_pe + 4] == _PE_SIGNATURE):
                return mz
        offset = mz + 1
    return None


def _find_embedded_elf(data: bytes) -> int | None:
    offset = 0
    while True:
        elf = data.find(_ELF_SIGNATURE, offset)
        if elf < 0:
            break
        if elf + 18 <= len(data):
            elf_class = data[elf + 4]
            byte_order = data[elf + 5]
            elf_version = data[elf + 6]
            obj_type = int.from_bytes(data[elf + 16: elf + 18], "little" if byte_order == 1 else "big")
            machine = int.from_bytes(data[elf + 18: elf + 20], "little" if byte_order == 1 else "big") if elf + 20 <= len(data) else 0
            if (elf_class in {1, 2} and byte_order in {1, 2} and
                    elf_version == 1 and obj_type in _ELF_EXECUTABLE_TYPES and
                    machine in _ELF_SUPPORTED_MACHINES):
                return elf
        offset = elf + 1
    return None


# ── Scanner ────────────────────────────────────────────────────────────────

class TensorRTScanner:
    """Scan TensorRT `.engine` / `.plan` / `.trt` files for embedded
    executables, plugin-load gadgets, and suspicious string patterns."""

    EXTENSIONS = frozenset({".engine", ".plan", ".trt"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)

        if not path.exists() or not path.is_file():
            return findings
        if path.suffix.lower() not in self.EXTENSIONS:
            return findings

        try:
            raw = path.read_bytes()
        except OSError as exc:
            logger.warning("TensorRTScanner: cannot read %s: %s", filepath, exc)
            return findings

        truncated = len(raw) > MAX_SCAN_BYTES
        data = raw[:MAX_SCAN_BYTES]

        if truncated:
            findings.append(Finding.artifact(
                rule_id="TRT-TRUNC",
                title="TensorRT engine scan truncated (large file)",
                description=f"File exceeds {MAX_SCAN_BYTES // (1024**2)} MB; remaining bytes not analyzed.",
                severity=Severity.LOW,
                target=filepath,
                evidence=f"file_size={path.stat().st_size}",
            ))

        # ── Embedded PE
        pe_off = _find_embedded_pe(data)
        if pe_off is not None:
            findings.append(Finding.artifact(
                rule_id="TRT-PE-001",
                title="Embedded Windows PE/DLL header in TensorRT engine",
                description=(
                    "A Windows Portable Executable (MZ+PE) header was found inside the "
                    "TensorRT engine binary. Legitimate engines do not contain executable "
                    "blobs; this indicates a polyglot or plugin-injection payload."
                ),
                severity=Severity.CRITICAL,
                target=filepath,
                evidence=f"PE header at offset 0x{pe_off:x}",
                cwe_ids=["CWE-494", "CWE-94"],
                tags=["owasp:llm05", "cve:CVE-2024-0213"],
            ))

        # ── Embedded ELF
        elf_off = _find_embedded_elf(data)
        if elf_off is not None:
            findings.append(Finding.artifact(
                rule_id="TRT-ELF-001",
                title="Embedded Linux ELF executable in TensorRT engine",
                description=(
                    "A Linux ELF executable or shared-object header was found inside the "
                    "TensorRT engine binary. This strongly indicates a malicious payload "
                    "or unauthorized native plugin injection."
                ),
                severity=Severity.CRITICAL,
                target=filepath,
                evidence=f"ELF header at offset 0x{elf_off:x}",
                cwe_ids=["CWE-494", "CWE-94"],
                tags=["owasp:llm05", "cve:CVE-2024-0213"],
            ))

        # ── Suspicious string patterns
        fired: set[str] = set()
        string_examples: dict[str, list[str]] = {}

        for s in _iter_strings(data):
            for rule_id, _, pattern, _ in _SUSPICIOUS_PATTERNS:
                if rule_id in fired:
                    continue
                if pattern.search(s):
                    fired.add(rule_id)
                    string_examples[rule_id] = [s[:120]]

        for rule_id, title, _, severity in _SUSPICIOUS_PATTERNS:
            if rule_id in fired:
                findings.append(Finding.artifact(
                    rule_id=rule_id,
                    title=title,
                    description=(
                        f"Pattern '{rule_id}' matched a string extracted from the "
                        "TensorRT engine binary. TensorRT engines are opaque blobs; "
                        "presence of shell/loader strings warrants investigation."
                    ),
                    severity=severity,
                    target=filepath,
                    evidence="; ".join(string_examples.get(rule_id, [])[:3]),
                    cwe_ids=["CWE-494"],
                    tags=["owasp:llm05"],
                ))

        return findings
