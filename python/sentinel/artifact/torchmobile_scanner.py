"""
Eresus Sentinel — TorchMobile (PyTorch Lite) Scanner.

Scans .ptl files (PyTorch Lite Interpreter format) for security risks.
PTL files are ZIP archives containing:
  - bytecode/: Serialized TorchScript bytecode
  - constants.pkl: Pickled tensor constants
  - extra/: Optional metadata files
  - libs/: Optional shared libraries

Attack surface:
  - constants.pkl uses pickle deserialization (CWE-502)
  - bytecode can embed malicious ops
  - ZIP archive may contain path traversal entries
  - extra/ files can contain injection payloads
  - libs/ may contain native code for arbitrary execution

No external dependencies required.
"""

from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import List

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

# Known safe TorchMobile internal paths
_SAFE_PREFIXES = {"bytecode/", "constants/", "extra/", "libs/"}

# Suspicious patterns in bytecode or extra files
_DANGEROUS_PATTERNS = [
    b"__import__", b"os.system", b"subprocess",
    b"eval(", b"exec(", b"compile(",
    b"marshal.loads", b"pickle.loads",
    b"/bin/sh", b"/bin/bash",
    b"socket.socket", b"connect(",
    b"__reduce__", b"__reduce_ex__",
    b"builtins.exec", b"builtins.eval",
]

# Native library extensions that indicate code execution
_NATIVE_EXTENSIONS = {".so", ".dll", ".dylib", ".pyd"}


class TorchMobileScanner:
    """Scan PyTorch Lite (.ptl) files for security threats.

    PTL files are ZIP archives containing serialized TorchScript bytecode
    and pickled constants. Both attack surfaces are analyzed.
    """

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a .ptl file for security issues.

        Args:
            path: Path to a .ptl file.

        Returns:
            List of security findings.
        """
        findings: List[Finding] = []
        p = Path(path)

        if not p.exists() or not p.is_file():
            findings.append(Finding.artifact(
                rule_id="PTL-000", title="File not found",
                description=f"TorchMobile file not found: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return findings

        file_size = p.stat().st_size
        if file_size < 22:  # Minimum ZIP size
            findings.append(Finding.artifact(
                rule_id="PTL-001", title="File too small",
                description=f"File is only {file_size} bytes — too small for valid PTL.",
                severity=Severity.HIGH, target=path,
                evidence=f"size={file_size}",
            ))
            return findings

        try:
            with zipfile.ZipFile(path, "r") as zf:
                members = zf.namelist()
                findings.extend(self._check_archive_structure(zf, members, path))
                findings.extend(self._scan_constants(zf, members, path))
                findings.extend(self._scan_bytecode(zf, members, path))
                findings.extend(self._scan_extra_files(zf, members, path))
                findings.extend(self._check_native_libs(zf, members, path))
        except zipfile.BadZipFile:
            findings.append(Finding.artifact(
                rule_id="PTL-002", title="Corrupt PTL archive",
                description="File is not a valid ZIP archive.",
                severity=Severity.HIGH, target=path,
            ))
        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="PTL-099", title="Scan error",
                description=f"Failed to scan PTL file: {e}",
                severity=Severity.MEDIUM, target=path,
                evidence=str(e),
            ))

        return findings

    def _check_archive_structure(
        self, zf: zipfile.ZipFile, members: list[str], source: str
    ) -> List[Finding]:
        """Validate PTL archive structure and check for path traversal."""
        findings: List[Finding] = []

        has_bytecode = False
        has_constants = False

        for name in members:
            # Path traversal check
            if ".." in name or name.startswith("/"):
                findings.append(Finding.artifact(
                    rule_id="PTL-010", title="Path traversal in PTL archive",
                    description=f"Member '{name}' contains path traversal.",
                    severity=Severity.CRITICAL, target=f"{source}!{name}",
                    cwe_ids=["CWE-22"],
                ))

            # Track expected structure
            if name.startswith("bytecode/"):
                has_bytecode = True
            if "constants" in name:
                has_constants = True

            # Check for oversized entries
            info = zf.getinfo(name)
            if info.file_size > 500_000_000:  # 500MB
                findings.append(Finding.artifact(
                    rule_id="PTL-011", title=f"Oversized archive entry: {name}",
                    description=f"Entry '{name}' is {info.file_size / 1e6:.1f}MB — "
                                "possible decompression bomb.",
                    severity=Severity.HIGH, target=f"{source}!{name}",
                    evidence=f"size={info.file_size}",
                ))

            # Check compression ratio (zip bomb detection)
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > 1000:
                    findings.append(Finding.artifact(
                        rule_id="PTL-012", title=f"High compression ratio: {name}",
                        description=f"Entry '{name}' has {ratio:.0f}x compression ratio — "
                                    "possible zip bomb.",
                        severity=Severity.HIGH, target=f"{source}!{name}",
                        evidence=f"ratio={ratio:.0f}x",
                    ))

        if not has_bytecode and not has_constants:
            findings.append(Finding.artifact(
                rule_id="PTL-020", title="Non-standard PTL structure",
                description="Archive lacks expected bytecode/ or constants entries. "
                            "This may not be a legitimate PyTorch Lite model.",
                severity=Severity.MEDIUM, target=source,
                evidence=f"members={members[:10]}",
            ))

        return findings

    def _scan_constants(
        self, zf: zipfile.ZipFile, members: list[str], source: str
    ) -> List[Finding]:
        """Scan constants.pkl for pickle deserialization risks."""
        findings: List[Finding] = []

        pkl_files = [m for m in members if m.endswith(".pkl")]
        if not pkl_files:
            return findings

        for pkl_name in pkl_files:
            # Flag pickle usage
            findings.append(Finding.artifact(
                rule_id="PTL-100",
                title=f"Pickle deserialization in PTL: {pkl_name}",
                description=f"PTL archive contains '{pkl_name}' which uses pickle "
                            "deserialization. Loading this file with torch.jit.load() "
                            "will deserialize pickle data, enabling arbitrary code execution.",
                severity=Severity.HIGH, target=f"{source}!{pkl_name}",
                cwe_ids=["CWE-502"],
                remediation="Use safetensors format or verify model provenance.",
            ))

            # Scan pickle content for dangerous patterns
            try:
                data = zf.read(pkl_name)
                for pattern in _DANGEROUS_PATTERNS:
                    if pattern in data:
                        findings.append(Finding.artifact(
                            rule_id="PTL-101",
                            title=f"Dangerous pattern in {pkl_name}: {pattern.decode('ascii', errors='replace')}",
                            description=f"Pickle file contains '{pattern.decode('ascii', errors='replace')}' "
                                        "which indicates potential code execution.",
                            severity=Severity.CRITICAL,
                            target=f"{source}!{pkl_name}",
                            evidence=f"pattern={pattern!r}",
                            cwe_ids=["CWE-502"],
                        ))

                # Delegate to PickleScanner for deep analysis if available
                try:
                    from .pickle_scanner import PickleScanner
                    ps = PickleScanner()
                    analysis = ps.scan(data, source=f"{source}!{pkl_name}")
                    for imp in analysis.dangerous_imports:
                        findings.append(Finding.artifact(
                            rule_id="PTL-102",
                            title=f"Dangerous import in PTL pickle: {imp.module}.{imp.name}",
                            description=f"Pickle stream imports '{imp.module}.{imp.name}' "
                                        f"via {imp.opcode} at offset {imp.position}.",
                            severity=Severity.CRITICAL,
                            target=f"{source}!{pkl_name}",
                            evidence=f"opcode={imp.opcode}, offset={imp.position}",
                            cwe_ids=["CWE-502"],
                        ))
                except ImportError:
                    pass
            except Exception as e:
                logger.debug("Failed to read %s in PTL: %s", pkl_name, e)

        return findings

    def _scan_bytecode(
        self, zf: zipfile.ZipFile, members: list[str], source: str
    ) -> List[Finding]:
        """Scan TorchScript bytecode files for suspicious patterns."""
        findings: List[Finding] = []

        bytecode_files = [m for m in members if m.startswith("bytecode/")]
        for bc_name in bytecode_files:
            try:
                data = zf.read(bc_name)

                # Check for dangerous string patterns in bytecode
                for pattern in _DANGEROUS_PATTERNS:
                    if pattern in data:
                        findings.append(Finding.artifact(
                            rule_id="PTL-200",
                            title=f"Suspicious pattern in bytecode: {pattern.decode('ascii', errors='replace')}",
                            description=f"Bytecode file '{bc_name}' contains "
                                        f"'{pattern.decode('ascii', errors='replace')}' "
                                        "which may indicate embedded malicious operations.",
                            severity=Severity.HIGH,
                            target=f"{source}!{bc_name}",
                            evidence=f"pattern={pattern!r}",
                            cwe_ids=["CWE-94"],
                        ))

                # Check bytecode size
                if len(data) > 100_000_000:  # 100MB
                    findings.append(Finding.artifact(
                        rule_id="PTL-201",
                        title=f"Oversized bytecode: {bc_name}",
                        description=f"Bytecode file is {len(data) / 1e6:.1f}MB.",
                        severity=Severity.MEDIUM,
                        target=f"{source}!{bc_name}",
                    ))

            except Exception as e:
                logger.debug("Failed to read bytecode %s: %s", bc_name, e)

        return findings

    def _scan_extra_files(
        self, zf: zipfile.ZipFile, members: list[str], source: str
    ) -> List[Finding]:
        """Scan extra/ files for injection payloads."""
        findings: List[Finding] = []

        extra_files = [m for m in members if m.startswith("extra/")]
        for extra_name in extra_files:
            try:
                data = zf.read(extra_name)
                text = data.decode("utf-8", errors="replace")

                # Check for code injection patterns
                for pattern in _DANGEROUS_PATTERNS:
                    pattern_str = pattern.decode("ascii", errors="replace")
                    if pattern_str in text:
                        findings.append(Finding.artifact(
                            rule_id="PTL-300",
                            title=f"Injection pattern in extra file: {extra_name}",
                            description=f"Extra file '{extra_name}' contains "
                                        f"'{pattern_str}' which may be an injection payload.",
                            severity=Severity.HIGH,
                            target=f"{source}!{extra_name}",
                            evidence=f"pattern={pattern_str}",
                            cwe_ids=["CWE-94"],
                        ))
                        break

                # Check for JSON metadata with suspicious keys
                if extra_name.endswith(".json"):
                    try:
                        meta = json.loads(text)
                        if isinstance(meta, dict):
                            suspicious_keys = {"exec", "eval", "command", "script", "shell"}
                            found = suspicious_keys & set(k.lower() for k in meta.keys())
                            if found:
                                findings.append(Finding.artifact(
                                    rule_id="PTL-301",
                                    title=f"Suspicious metadata key in {extra_name}",
                                    description=f"JSON metadata contains suspicious keys: {found}.",
                                    severity=Severity.HIGH,
                                    target=f"{source}!{extra_name}",
                                    evidence=f"keys={list(meta.keys())[:10]}",
                                ))
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug("Failed to read extra file %s: %s", extra_name, e)

        return findings

    def _check_native_libs(
        self, zf: zipfile.ZipFile, members: list[str], source: str
    ) -> List[Finding]:
        """Check for native library files that enable code execution."""
        findings: List[Finding] = []

        for name in members:
            suffix = Path(name).suffix.lower()
            if suffix in _NATIVE_EXTENSIONS:
                findings.append(Finding.artifact(
                    rule_id="PTL-400",
                    title=f"Native library in PTL: {name}",
                    description=f"PTL archive contains native library '{name}' "
                                f"(extension: {suffix}). Loading this model will "
                                "execute native code, enabling arbitrary code execution.",
                    severity=Severity.CRITICAL,
                    target=f"{source}!{name}",
                    evidence=f"library={name}",
                    cwe_ids=["CWE-426"],
                    remediation="Verify the library source and integrity before loading.",
                ))

        return findings
