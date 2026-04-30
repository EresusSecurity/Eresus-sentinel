"""
H5/HDF5 model artifact scanner.

Detects security issues in HDF5 files (Keras legacy, sklearn, generic):
  - Embedded Python code in HDF5 attributes/datasets
  - Pickle-in-HDF5 payloads
  - Suspicious layer configurations (Keras Lambda)
  - Executable content in metadata
"""

from __future__ import annotations

import logging
import re
import struct
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity

_log = logging.getLogger("sentinel.artifact.h5_scanner")

# HDF5 magic bytes: \x89HDF\r\n\x1a\n
HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"


class H5Scanner:
    """Security scanner for HDF5/H5 model files."""

    # Dangerous patterns in HDF5 string data
    _CODE_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
        (re.compile(rb"__import__\s*\("), "Dynamic import in HDF5", Severity.CRITICAL),
        (re.compile(rb"eval\s*\("), "eval() in HDF5", Severity.CRITICAL),
        (re.compile(rb"exec\s*\("), "exec() in HDF5", Severity.CRITICAL),
        (re.compile(rb"os\.system\s*\("), "os.system() in HDF5", Severity.CRITICAL),
        (re.compile(rb"subprocess\.\w+\s*\("), "subprocess in HDF5", Severity.CRITICAL),
        (re.compile(rb"lambda\s+[^:]+:"), "Lambda expression in HDF5 metadata", Severity.HIGH),
        (re.compile(rb"compile\s*\("), "compile() in HDF5", Severity.HIGH),
        (re.compile(rb"marshal\.loads\s*\("), "marshal.loads() in HDF5", Severity.CRITICAL),
        (re.compile(rb"pickle\.loads\s*\("), "pickle.loads() in HDF5", Severity.CRITICAL),
        (re.compile(rb"ctypes\.\w+"), "ctypes usage in HDF5", Severity.HIGH),
        (re.compile(rb"socket\.socket\s*\("), "Socket in HDF5", Severity.HIGH),
    ]

    # Keras-specific dangerous layer types
    _KERAS_DANGEROUS_LAYERS = [
        b"Lambda",
        b"CustomLayer",
        b"TFOpLambda",
    ]

    # Pickle protocol markers
    _PICKLE_MARKERS = [
        b"\x80\x02",  # Proto 2
        b"\x80\x03",  # Proto 3
        b"\x80\x04",  # Proto 4
        b"\x80\x05",  # Proto 5
        b"cos\n",     # GLOBAL opcode (text)
        b"cposix\n",  # posix module
    ]

    def scan_file(self, filepath: str) -> list[Finding]:
        """Scan an HDF5 file for security issues."""
        findings: list[Finding] = []
        path = Path(filepath)

        if not path.exists() or not path.is_file():
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-H5-000",
                title="HDF5 file not found or not a regular file",
                description=f"Cannot scan '{filepath}': file does not exist or is not a regular file.",
                severity=Severity.INFO,
                target=filepath,
            ))
            return findings

        try:
            data = path.read_bytes()
        except OSError as exc:
            _log.warning("Cannot read %s: %s", filepath, exc)
            return findings

        if len(data) < 8:
            return findings

        # Verify HDF5 magic
        if data[:8] != HDF5_MAGIC:
            return findings

        # 1. Scan for embedded code patterns
        for pat, desc, severity in self._CODE_PATTERNS:
            for m in pat.finditer(data[:50_000_000]):
                findings.append(Finding.artifact(
                    rule_id="H5-001",
                    title=f"Code in HDF5: {desc}",
                    description=f"At offset 0x{m.start():x} in {filepath}",
                    severity=severity,
                    target=filepath,
                    evidence=m.group().decode(errors="replace")[:200],
                ))

        # 2. Detect pickle payloads embedded in HDF5
        for marker in self._PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="H5-002",
                    title="Pickle payload in HDF5",
                    description=(
                        f"Pickle protocol marker found at offset 0x{idx:x}. "
                        "Embedded pickle payloads can execute arbitrary code."
                    ),
                    severity=Severity.CRITICAL,
                    target=filepath,
                    evidence=f"marker={marker!r} at 0x{idx:x}",
                ))
                break  # One finding is enough

        # 3. Keras Lambda layer detection
        for layer in self._KERAS_DANGEROUS_LAYERS:
            if layer in data:
                findings.append(Finding.artifact(
                    rule_id="H5-003",
                    title=f"Keras {layer.decode()} layer in model",
                    description=(
                        f"{layer.decode()} layers can execute arbitrary Python code "
                        "when the model is loaded."
                    ),
                    severity=Severity.HIGH,
                    target=filepath,
                    evidence=layer.decode(),
                ))

        # 4. Check for suspiciously large string attributes
        long_strings = [m for m in re.finditer(rb"[\x20-\x7e]{500,}", data[:10_000_000])]
        for m in long_strings[:5]:
            content = m.group()
            # Check if it looks like Python code
            if any(kw in content for kw in [b"def ", b"class ", b"import ", b"from ", b"return "]):
                findings.append(Finding.artifact(
                    rule_id="H5-004",
                    title="Python code in HDF5 string attribute",
                    description=(
                        f"Long string at offset 0x{m.start():x} appears to contain Python code."
                    ),
                    severity=Severity.HIGH,
                    target=filepath,
                    evidence=content[:200].decode(errors="replace"),
                ))

        return findings

    def scan_bytes(self, data: bytes, source: str = "") -> list[Finding]:
        """Scan raw bytes as HDF5."""
        findings: list[Finding] = []
        if len(data) < 8 or data[:8] != HDF5_MAGIC:
            return findings

        for pat, desc, severity in self._CODE_PATTERNS:
            for m in pat.finditer(data[:50_000_000]):
                findings.append(Finding.artifact(
                    rule_id="H5-001",
                    title=f"Code in HDF5: {desc}",
                    description=f"At offset 0x{m.start():x}",
                    severity=severity,
                    target=source,
                    evidence=m.group().decode(errors="replace")[:200],
                ))

        for marker in self._PICKLE_MARKERS:
            if marker in data:
                findings.append(Finding.artifact(
                    rule_id="H5-002",
                    title="Pickle payload in HDF5",
                    description="Embedded pickle payload detected.",
                    severity=Severity.CRITICAL,
                    target=source,
                ))
                break

        return findings
