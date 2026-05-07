"""Binary tail scanner — detects executables appended to model files.

Scans the last section of model files for:
  - PE (Windows .exe/.dll) headers
  - ELF (Linux) headers
  - Mach-O (macOS) headers
  - Shell/PowerShell scripts
  - Embedded code patterns (import os, eval, exec, etc.)
  - Base64/hex encoded payloads with dangerous seeds

"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..finding import Finding, Location, Severity

logger = logging.getLogger(__name__)

# Executable format signatures to detect in file tails
_BINARY_SIGNATURES: list[tuple[bytes, str, str, Severity]] = [
    (b"MZ",                "Windows executable (PE)",          "TAIL-001", Severity.CRITICAL),
    (b"\x7fELF",           "Linux executable (ELF)",           "TAIL-002", Severity.CRITICAL),
    (b"\xfe\xed\xfa\xce", "macOS Mach-O (32-bit)",            "TAIL-003", Severity.CRITICAL),
    (b"\xfe\xed\xfa\xcf", "macOS Mach-O (64-bit)",            "TAIL-003", Severity.CRITICAL),
    (b"\xcf\xfa\xed\xfe", "macOS Mach-O (reversed)",          "TAIL-003", Severity.CRITICAL),
    (b"\xca\xfe\xba\xbe", "macOS Universal Binary (Fat)",     "TAIL-003", Severity.CRITICAL),
    (b"#!/bin/sh",         "Shell script",                     "TAIL-004", Severity.HIGH),
    (b"#!/bin/bash",       "Bash script",                      "TAIL-004", Severity.HIGH),
    (b"#!/usr/bin/env",    "Env script",                       "TAIL-004", Severity.HIGH),
    (b"#!/usr/bin/python", "Python script",                    "TAIL-004", Severity.HIGH),
    (b"#!/usr/bin/perl",   "Perl script",                      "TAIL-004", Severity.HIGH),
]

# Code patterns to search for in binary data
_BINARY_CODE_PATTERNS: list[tuple[bytes, str]] = [
    (b"import os",            "Python os import"),
    (b"import subprocess",    "Python subprocess import"),
    (b"import socket",        "Python socket import"),
    (b"import ctypes",        "Python ctypes import"),
    (b"eval(",                "eval() call"),
    (b"exec(",                "exec() call"),
    (b"__import__(",          "Dynamic import"),
    (b"os.system(",           "os.system call"),
    (b"subprocess.call(",     "subprocess call"),
    (b"subprocess.Popen(",    "subprocess Popen"),
    (b"socket.socket(",       "Socket creation"),
    (b"ctypes.CDLL(",         "DLL loading"),
    (b"posix\nsystem",        "POSIX system call"),
    (b"nt\nsystem",           "NT system call"),
    (b"powershell",           "PowerShell reference"),
    (b"invoke-expression",    "PowerShell invoke"),
    (b"cmd.exe",              "Windows cmd reference"),
    (b"/bin/sh -c",           "Shell execution"),
]

# Base64-encoded dangerous payload seeds (for seed-based detection)
_BASE64_SEEDS: list[tuple[bytes, str]] = [
    (b"ZXZhbCg",              "eval("),
    (b"ZXhlYyg",              "exec("),
    (b"b3Muc3lzdGVt",         "os.system"),
    (b"c3VicHJvY2Vzcw",       "subprocess"),
    (b"X19pbXBvcnRfXw",       "__import__"),
    (b"L2Jpbi9zaA",           "/bin/sh"),
    (b"L2Jpbi9iYXNo",         "/bin/bash"),
    (b"Y21kLmV4ZQ",           "cmd.exe"),
    (b"cG93ZXJzaGVsbA",       "powershell"),
]

# Hex-encoded dangerous payload seeds
_HEX_SEEDS: list[tuple[bytes, str]] = [
    (b"6576616c28",            "eval("),
    (b"6578656328",            "exec("),
    (b"6f732e73797374656d",    "os.system"),
    (b"73756270726f63657373",  "subprocess"),
    (b"5f5f696d706f72745f5f",  "__import__"),
]

# Regex for base64/hex tokens in binary data
_BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(rb"(?<![A-Fa-f0-9])[A-Fa-f0-9]{20,}(?![A-Fa-f0-9])")

# How much of the file tail to scan (bytes)
_TAIL_SIZE = 1 * 1024 * 1024  # 1MB
_CHUNK_SIZE = 1 * 1024 * 1024  # 1MB scanning chunks


class BinaryTailScanner:
    """Scans model files for appended executables and encoded payloads."""

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        path = Path(file_path)
        source = str(path)
        findings: list[Finding] = []

        if not path.exists():
            return []

        file_size = path.stat().st_size
        if file_size < 16:
            return []

        try:
            with open(path, "rb") as f:
                # Scan the tail for appended executables
                tail_findings = self._scan_tail(f, file_size, source)
                findings.extend(tail_findings)

                # Scan entire file in chunks for code patterns
                code_findings = self._scan_for_code_patterns(f, file_size, source)
                findings.extend(code_findings)

                # Scan for encoded payloads
                encoded_findings = self._scan_encoded_payloads(f, file_size, source)
                findings.extend(encoded_findings)
        except OSError as exc:
            logger.debug("Could not read %s: %s", path, exc)

        return findings

    def _scan_tail(self, f, file_size: int, source: str) -> list[Finding]:
        """Check the last _TAIL_SIZE bytes for executable signatures."""
        findings: list[Finding] = []
        offset = max(0, file_size - _TAIL_SIZE)
        f.seek(offset)
        tail = f.read(_TAIL_SIZE)

        for sig, desc, rule_id, severity in _BINARY_SIGNATURES:
            pos = tail.find(sig)
            if pos >= 0:
                abs_pos = offset + pos
                # Skip if signature is at the very start (the file IS an executable)
                if abs_pos < 256:
                    continue
                findings.append(Finding.artifact(
                    rule_id=rule_id,
                    title=f"Appended {desc} detected",
                    description=(
                        f"A {desc} signature was found at byte offset {abs_pos} "
                        f"in '{source}'. This suggests an executable has been "
                        f"appended to the model file, which will execute when "
                        f"the file is renamed and run directly."
                    ),
                    severity=severity,
                    confidence=0.9,
                    target=source,
                    evidence=f"Signature: {sig!r} at offset {abs_pos}",
                    location=Location(file=source, byte_offset=abs_pos),
                    cwe_ids=["CWE-506"],
                    tags=["mitre-atlas:AML.T0010", "binary-tail", "trojan"],
                ))
        return findings

    def _scan_for_code_patterns(
        self, f, file_size: int, source: str,
    ) -> list[Finding]:
        """Scan file for embedded code patterns in binary data."""
        findings: list[Finding] = []
        found_patterns: set[str] = set()

        f.seek(0)
        offset = 0
        while offset < file_size:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            for pattern, desc in _BINARY_CODE_PATTERNS:
                if desc in found_patterns:
                    continue
                pos = chunk.find(pattern)
                if pos >= 0:
                    abs_pos = offset + pos
                    found_patterns.add(desc)
                    # Don't flag if it's within first 4KB (could be metadata)
                    if abs_pos < 4096:
                        continue
                    findings.append(Finding.artifact(
                        rule_id="TAIL-005",
                        title=f"Embedded code pattern: {desc}",
                        description=(
                            f"Found '{pattern.decode('ascii', errors='replace')}' "
                            f"at byte offset {abs_pos} in binary data of '{source}'. "
                            f"Model files should not contain executable code patterns."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        target=source,
                        evidence=f"Pattern: {desc} at offset {abs_pos}",
                        location=Location(file=source, byte_offset=abs_pos),
                        cwe_ids=["CWE-506"],
                        tags=["binary-code-pattern"],
                    ))
            offset += len(chunk)

        return findings

    def _scan_encoded_payloads(
        self, f, file_size: int, source: str,
    ) -> list[Finding]:
        """Detect base64/hex encoded dangerous payloads using seed matching."""
        findings: list[Finding] = []

        f.seek(0)
        offset = 0
        found_b64 = False
        found_hex = False

        while offset < file_size:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break

            # Base64 seed detection
            if not found_b64:
                for token_match in _BASE64_RE.finditer(chunk):
                    token = token_match.group()
                    for seed, decoded_name in _BASE64_SEEDS:
                        if seed in token:
                            abs_pos = offset + token_match.start()
                            findings.append(Finding.artifact(
                                rule_id="TAIL-006",
                                title=f"Base64-encoded payload: {decoded_name}",
                                description=(
                                    f"A base64 token containing encoded '{decoded_name}' "
                                    f"was found at offset {abs_pos} in '{source}'. "
                                    f"This may be an obfuscated malicious payload."
                                ),
                                severity=Severity.HIGH,
                                confidence=0.8,
                                target=source,
                                evidence=f"Base64 seed for '{decoded_name}' at offset {abs_pos}",
                                location=Location(file=source, byte_offset=abs_pos),
                                cwe_ids=["CWE-506"],
                                tags=["obfuscation", "base64-payload"],
                            ))
                            found_b64 = True
                            break
                    if found_b64:
                        break

            # Hex seed detection
            if not found_hex:
                for token_match in _HEX_RE.finditer(chunk):
                    token = token_match.group()
                    for seed, decoded_name in _HEX_SEEDS:
                        if seed in token:
                            abs_pos = offset + token_match.start()
                            findings.append(Finding.artifact(
                                rule_id="TAIL-007",
                                title=f"Hex-encoded payload: {decoded_name}",
                                description=(
                                    f"A hex token containing encoded '{decoded_name}' "
                                    f"was found at offset {abs_pos} in '{source}'. "
                                    f"This may be an obfuscated malicious payload."
                                ),
                                severity=Severity.HIGH,
                                confidence=0.8,
                                target=source,
                                evidence=f"Hex seed for '{decoded_name}' at offset {abs_pos}",
                                location=Location(file=source, byte_offset=abs_pos),
                                cwe_ids=["CWE-506"],
                                tags=["obfuscation", "hex-payload"],
                            ))
                            found_hex = True
                            break
                    if found_hex:
                        break

            if found_b64 and found_hex:
                break
            offset += len(chunk)

        return findings
