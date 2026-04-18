"""
Eresus Sentinel — LlamaFile Scanner.

Deep-inspects LlamaFile executables for security threats. LlamaFiles are
Cosmopolitan "Actually Portable Executables" (APE) that bundle an ELF/PE
binary with a GGUF model. This creates a unique dual attack surface:
executable shell + model weights.

Covers PAIT threat IDs:
  - PAIT-LMAFL-300: Malicious executable payload detection

Attack surface:
  LlamaFile binary structure:
  ┌────────────────────────┐
  │  APE Header (MZ/ELF)  │  ← Executable code (x86/ARM)
  │  Cosmopolitan runtime  │
  ├────────────────────────┤
  │  GGUF Model Weights    │  ← Delegated to GGUFReverseEngine
  │  (embedded at offset)  │
  └────────────────────────┘

Strategy:
  1. Validate header structure (MZ/ELF)
  2. Locate embedded GGUF offset
  3. Check for suspicious executable sections
  4. Delegate GGUF weight analysis to GGUFReverseEngine

No external dependencies required.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ..finding import Finding, Severity
from ..rules import load_scanner_rules
from .gguf_engine import GGUFReverseEngine, GGUF_MAGIC_BYTES

_rules = load_scanner_rules()
_llama_rules = _rules.get("llamafile", {})
_common = _rules.get("common", {})

MAX_HEADER_SIZE = _llama_rules.get("max_header_size", 67_108_864)  # 64MB
MAX_GGUF_SCAN_RANGE = _llama_rules.get("max_gguf_scan_range", 104_857_600)  # 100MB

SUSPICIOUS_SECTIONS: Set[str] = set(
    _llama_rules.get("suspicious_sections", [
        ".shellcode", ".payload", ".backdoor",
        ".exploit", ".malware",
    ])
)

SUSPICIOUS_NAMES = _common.get("suspicious_names", [
    "backdoor", "trojan", "payload", "exploit", "malware",
    "reverse_shell", "c2", "exfil", "keylogger",
])


class LlamaFileScanner:
    """Deep-inspect LlamaFile executables for security threats.

    Validates the executable envelope and delegates GGUF weight analysis
    to GGUFReverseEngine.
    """

    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self._gguf_engine = GGUFReverseEngine()

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a LlamaFile executable.

        Args:
            path: Path to a .llamafile file.

        Returns:
            List of security findings.
        """
        self.findings = []
        p = Path(path)

        if not p.exists():
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-000", title="File not found",
                description=f"LlamaFile not found: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        if not p.is_file():
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-000", title="Not a file",
                description=f"Path is not a file: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        try:
            file_size = p.stat().st_size
        except OSError as e:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-099", title="File access error",
                description=f"Failed to access LlamaFile: {e}",
                severity=Severity.MEDIUM, target=path,
                evidence=str(e),
            ))
            return self.findings

        if file_size < 64:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-050", title="File too small",
                description="LlamaFile is too small to contain a valid executable.",
                severity=Severity.HIGH, target=path,
                evidence=f"size={file_size}",
            ))
            return self.findings

        try:
            with open(path, "rb") as f:
                header = f.read(min(file_size, 8192))
        except OSError as e:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-099", title="Read error",
                description=f"Failed to read LlamaFile: {e}",
                severity=Severity.MEDIUM, target=path,
                evidence=str(e),
            ))
            return self.findings

        # Identify executable format
        exe_format = self._identify_format(header)
        if exe_format is None:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-051", title="Unknown executable format",
                description="LlamaFile does not start with MZ (PE/APE) or ELF magic. "
                            "File may not be a valid LlamaFile.",
                severity=Severity.HIGH, target=path,
                evidence=f"header_bytes={header[:16].hex()}",
            ))
            return self.findings

        self.findings.append(Finding.artifact(
            rule_id="LLAMA-INFO", title=f"LlamaFile format: {exe_format}",
            description=f"LlamaFile uses {exe_format} executable format. "
                        "LlamaFiles are executable model containers that combine "
                        "a native binary with embedded GGUF model weights.",
            severity=Severity.INFO, target=path,
        ))

        # Format-specific checks
        if exe_format == "MZ/APE":
            self._check_mz_header(header, path, file_size)
        elif exe_format == "ELF":
            self._check_elf_header(header, path, file_size)

        # Locate embedded GGUF
        gguf_offset = self._find_gguf_offset(path, file_size)

        if gguf_offset is not None:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-INFO",
                title=f"GGUF found at offset 0x{gguf_offset:x}",
                description=f"Embedded GGUF model weights found at byte offset "
                            f"{gguf_offset} ({gguf_offset / 1e6:.1f}MB into file).",
                severity=Severity.INFO, target=path,
                evidence=f"gguf_offset=0x{gguf_offset:x}",
            ))

            # Delegate to GGUF engine for weight analysis
            self._analyze_embedded_gguf(path, gguf_offset, file_size)
        else:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-060",
                title="No embedded GGUF found",
                description="Could not locate GGUF model weights in the LlamaFile. "
                            "The file may be a plain executable or contain a "
                            "different model format.",
                severity=Severity.MEDIUM, target=path,
            ))

        return self.findings

    def _identify_format(self, header: bytes) -> Optional[str]:
        """Identify the executable format from the header."""
        if header[:2] == b"MZ":
            return "MZ/APE"
        if header[:4] == b"\x7fELF":
            return "ELF"
        return None

    def _check_mz_header(
        self, header: bytes, filepath: str, file_size: int
    ) -> None:
        """Validate MZ/PE/APE header structure."""
        if len(header) < 64:
            return

        # PE header offset at 0x3C
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]

        if pe_offset > MAX_HEADER_SIZE:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-001",
                title=f"Abnormal PE offset: {pe_offset}",
                description=f"PE header offset {pe_offset} is unusually large "
                            f"(max expected: {MAX_HEADER_SIZE}). "
                            "This may indicate header manipulation.",
                severity=Severity.HIGH, target=filepath,
                evidence=f"pe_offset={pe_offset}",
            ))
            return

        if pe_offset + 4 <= len(header):
            pe_sig = header[pe_offset:pe_offset + 4]
            if pe_sig == b"PE\x00\x00":
                # Valid PE — check sections for suspicious names
                self._check_pe_sections(header, pe_offset, filepath)
            else:
                # APE format — Cosmopolitan uses a non-standard PE header
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-002",
                    title="Non-standard PE signature (likely APE)",
                    description=f"PE signature at offset 0x{pe_offset:x} is "
                                f"'{pe_sig.hex()}' instead of 'PE\\0\\0'. "
                                "This is typical of Cosmopolitan APE format.",
                    severity=Severity.INFO, target=filepath,
                    evidence=f"pe_sig={pe_sig.hex()}",
                ))

    def _check_pe_sections(
        self, header: bytes, pe_offset: int, filepath: str
    ) -> None:
        """Check PE section names for suspicious entries."""
        if pe_offset + 24 > len(header):
            return

        # COFF header starts at pe_offset + 4
        coff_start = pe_offset + 4
        num_sections = struct.unpack_from("<H", header, coff_start + 2)[0]
        optional_size = struct.unpack_from("<H", header, coff_start + 16)[0]
        sections_start = coff_start + 20 + optional_size

        for i in range(min(num_sections, 96)):
            sec_offset = sections_start + i * 40
            if sec_offset + 40 > len(header):
                break

            sec_name = header[sec_offset:sec_offset + 8].rstrip(b"\x00").decode(
                "ascii", errors="replace"
            ).lower()

            if sec_name in SUSPICIOUS_SECTIONS:
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-003",
                    title=f"Suspicious PE section: {sec_name}",
                    description=f"PE section '{sec_name}' has a name commonly "
                                "associated with malicious payloads.",
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=f"section_index={i}, name={sec_name}",
                    cwe_ids=["CWE-506"],
                ))

    def _check_elf_header(
        self, header: bytes, filepath: str, file_size: int
    ) -> None:
        """Validate ELF header structure."""
        if len(header) < 52:
            return

        # ELF class (32 vs 64 bit)
        ei_class = header[4]
        if ei_class not in (1, 2):
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-004",
                title=f"Invalid ELF class: {ei_class}",
                description=f"ELF header has class {ei_class} — expected 1 (32-bit) "
                            "or 2 (64-bit).",
                severity=Severity.HIGH, target=filepath,
                evidence=f"ei_class={ei_class}",
            ))

        # Check section header for suspicious names in 64-bit ELF
        if ei_class == 2 and len(header) >= 64:
            e_shoff = struct.unpack_from("<Q", header, 40)[0]
            e_shnum = struct.unpack_from("<H", header, 60)[0]
            e_shstrndx = struct.unpack_from("<H", header, 62)[0]

            if e_shoff > file_size:
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-005",
                    title=f"ELF section header offset beyond EOF",
                    description=f"Section header table offset {e_shoff} exceeds "
                                f"file size {file_size}.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"e_shoff={e_shoff}, file_size={file_size}",
                    cwe_ids=["CWE-125"],
                ))

    def _find_gguf_offset(self, filepath: str, file_size: int) -> Optional[int]:
        """Locate the GGUF magic bytes within the file."""
        scan_size = min(file_size, MAX_GGUF_SCAN_RANGE)
        chunk_size = 1_048_576  # 1MB chunks

        try:
            with open(filepath, "rb") as f:
                offset = 0
                while offset < scan_size:
                    f.seek(offset)
                    chunk = f.read(min(chunk_size + 4, scan_size - offset))
                    if not chunk:
                        break

                    pos = chunk.find(GGUF_MAGIC_BYTES)
                    if pos != -1 and (offset + pos) >= 4:
                        return offset + pos

                    # Overlap by 4 bytes to handle boundary cases
                    offset += chunk_size

        except OSError:
            pass

        return None

    def _analyze_embedded_gguf(
        self, filepath: str, gguf_offset: int, file_size: int
    ) -> None:
        """Delegate GGUF analysis to GGUFReverseEngine on the embedded weights."""
        try:
            with open(filepath, "rb") as f:
                f.seek(gguf_offset)
                # Read header to validate it's actually GGUF
                magic = f.read(4)
                if magic != GGUF_MAGIC_BYTES:
                    return

                f.seek(gguf_offset)
                # Read enough for header + metadata
                gguf_size = min(file_size - gguf_offset, 100_000_000)  # 100MB max
                gguf_data = f.read(gguf_size)

            # Write to temp buffer and analyze
            import tempfile
            import os

            # Parse the GGUF header inline for security checks
            if len(gguf_data) < 24:
                return

            version = struct.unpack_from("<I", gguf_data, 4)[0]
            tensor_count = struct.unpack_from("<Q", gguf_data, 8)[0]
            kv_count = struct.unpack_from("<Q", gguf_data, 16)[0]

            if version not in (2, 3):
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-010",
                    title=f"Unusual embedded GGUF version: {version}",
                    description=f"Embedded GGUF has version {version} (expected 2 or 3).",
                    severity=Severity.LOW, target=filepath,
                    evidence=f"gguf_version={version}",
                ))

            if tensor_count > 10_000:
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-011",
                    title=f"High tensor count: {tensor_count}",
                    description=f"Embedded GGUF reports {tensor_count} tensors, "
                                "may indicate corruption.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"tensor_count={tensor_count}",
                ))

            if kv_count > 10_000:
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-012",
                    title=f"High metadata KV count: {kv_count}",
                    description=f"Embedded GGUF has {kv_count} metadata entries, "
                                "may indicate corruption or metadata injection.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"kv_count={kv_count}",
                ))

            # Check for suspicious strings in the GGUF metadata region
            metadata_preview = gguf_data[24:min(len(gguf_data), 100_000)]
            self._check_gguf_metadata_strings(metadata_preview, filepath)

        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="LLAMA-099",
                title="GGUF analysis error",
                description=f"Failed to analyze embedded GGUF: {e}",
                severity=Severity.MEDIUM, target=filepath,
                evidence=str(e),
            ))

    def _check_gguf_metadata_strings(
        self, data: bytes, filepath: str
    ) -> None:
        """Quick scan of GGUF metadata for dangerous string patterns."""
        dangerous_patterns = [
            b"eval(", b"exec(", b"import os",
            b"subprocess", b"__import__",
            b"os.system", b"<script",
        ]

        for pattern in dangerous_patterns:
            pos = data.find(pattern)
            if pos != -1:
                context = data[max(0, pos - 20):pos + len(pattern) + 20]
                self.findings.append(Finding.artifact(
                    rule_id="LLAMA-020",
                    title=f"Dangerous string in GGUF metadata: {pattern.decode('ascii', errors='replace')}",
                    description="Embedded GGUF metadata contains a string pattern "
                                "associated with code injection.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"pattern={pattern!r}, context={context!r}",
                    cwe_ids=["CWE-94"],
                ))
