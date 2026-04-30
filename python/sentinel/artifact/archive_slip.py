"""Archive slip detector — path traversal, symlink chains, compression bombs."""

from __future__ import annotations

import logging
import os
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
from pathlib import Path
from typing import List

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────

# Maximum decompressed size (1GB)
MAX_DECOMPRESSED_SIZE = 1 * 1024 * 1024 * 1024

# Maximum compression ratio before flagging
MAX_COMPRESSION_RATIO = 100.0

# Maximum number of entries before flagging
MAX_ENTRY_COUNT = 100_000

# Maximum symlink chain depth
MAX_SYMLINK_CHAIN_DEPTH = 10

# Maximum nested archive depth
MAX_NESTED_ARCHIVE_DEPTH = 3

# Maximum bytes to read from one archive member while validating nested
# archives or central-directory size claims.
MAX_STREAM_VALIDATE_BYTES = 16 * 1024 * 1024

# Archive-based model extensions
ARCHIVE_EXTENSIONS = {
    ".nemo", ".keras", ".pth", ".pt", ".mar",
    ".tar", ".tar.gz", ".tgz", ".tar.bz2",
    ".zip", ".onnx",
}

NESTED_ARCHIVE_EXTENSIONS = (
    ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".7z",
)

# Sensitive filesystem paths that hardlinks should never target
SENSITIVE_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/sudoers",
    "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa",
    "/proc/self/environ", "/proc/self/cmdline",
    "/var/run/docker.sock",
    "C:\\Windows\\System32",
}

# Control characters (ASCII 0-31, except tab/newline)
CONTROL_CHARS = set(range(0, 32)) - {9, 10, 13}

# Dangerous Unicode characters that look like path separators
LOOKALIKE_SEPARATORS = {
    "\u2044",  # ⁄ Fraction slash
    "\u2215",  # ∕ Division slash
    "\u29F8",  # ⧸ Big solidus
    "\uFF0F",  # ／ Fullwidth solidus
    "\uFF3C",  # ＼ Fullwidth reverse solidus
    "\u2216",  # ∖ Set minus
    "\uFE68",  # ﹨ Small reverse solidus
}

# Dangerous Unicode characters that look like dots
LOOKALIKE_DOTS = {
    "\u2024",  # ․ One dot leader
    "\uFF0E",  # ．Fullwidth full stop
    "\u2025",  # ‥ Two dot leader
    "\u00B7",  # · Middle dot
}


class ArchiveSlipDetector:
    """
    Advanced archive slip detector for model file archives.

    Goes beyond basic path traversal to detect multi-step attacks,
    encoding bypasses, and platform-specific exploitation patterns.
    """

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a model archive for all archive-slip attack vectors."""
        return self._scan_file(Path(path), depth=0, source_override=None)

    def _scan_file(
        self,
        path: Path,
        depth: int = 0,
        source_override: str | None = None,
    ) -> List[Finding]:
        """Scan an archive path, optionally preserving nested member context."""
        p = Path(path)
        findings: list[Finding] = []

        if zipfile.is_zipfile(path):
            findings.extend(self._scan_zip(p, depth, source_override))
        elif self._is_7z_file(p):
            findings.extend(self._scan_7z(p))
        else:
            try:
                if tarfile.is_tarfile(path):
                    findings.extend(self._scan_tar(p, depth, source_override))
            except Exception:
                pass

        return findings

    @staticmethod
    def _is_7z_file(path: Path) -> bool:
        """Check if file is a 7z archive by magic bytes."""
        try:
            with open(path, "rb") as f:
                return f.read(6) == b"7z\xbc\xaf\x27\x1c"
        except OSError:
            return False

    def _scan_7z(self, path: Path) -> List[Finding]:
        """Scan 7z archive for path traversal and bombs."""
        try:
            import py7zr
        except ImportError:
            return [Finding.artifact(
                rule_id="ARCHSLIP-030",
                title="7z archive detected but py7zr not installed",
                description=(
                    "A 7z archive was found but the py7zr library is not "
                    "available. Install it with: pip install py7zr"
                ),
                severity=Severity.MEDIUM,
                target=str(path),
                evidence="7z magic bytes detected",
                cwe_ids=["CWE-434"],
            )]

        findings: list[Finding] = []
        source = str(path)

        try:
            with py7zr.SevenZipFile(path, mode="r") as szf:
                entries = szf.list()
                if len(entries) > MAX_ENTRY_COUNT:
                    findings.append(Finding.artifact(
                        rule_id="ARCHSLIP-031",
                        title="Excessive 7z entry count",
                        description=(
                            f"7z archive contains {len(entries):,} entries — "
                            f"possible file-bomb."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Entry count: {len(entries):,}",
                        cwe_ids=["CWE-400"],
                    ))

                for entry in entries:
                    filename = entry.filename
                    # Path traversal check (same logic as ZIP scanner)
                    if ".." in filename or filename.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-032",
                            title=f"Path traversal in 7z: {filename}",
                            description=(
                                f"7z entry '{filename}' contains path traversal "
                                f"that would write outside the extraction directory."
                            ),
                            severity=Severity.CRITICAL,
                            target=source,
                            evidence=f"Entry: {filename}",
                            cwe_ids=["CWE-22"],
                        ))

        except Exception as e:
            logger.warning("Failed to scan 7z %s: %s", path, e)

        return findings

    # ─── ZIP Scanning ─────────────────────────────────────────

    def _scan_zip(
        self,
        path: Path,
        depth: int = 0,
        source_override: str | None = None,
    ) -> List[Finding]:
        """Comprehensive ZIP archive scan."""
        findings: list[Finding] = []
        source = source_override or str(path)

        try:
            with zipfile.ZipFile(path, "r") as zf:
                entries = zf.infolist()

                # Entry count check
                if len(entries) > MAX_ENTRY_COUNT:
                    findings.append(Finding.artifact(
                        rule_id="ARCHSLIP-020",
                        title="Excessive ZIP entry count",
                        description=(
                            f"Archive contains {len(entries):,} entries. "
                            f"This could be a file-bomb designed to exhaust "
                            f"filesystem resources during extraction."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Entry count: {len(entries):,}",
                        cwe_ids=["CWE-400"],
                    ))

                total_size = 0
                total_compressed = 0
                symlinks: dict[str, str] = {}
                all_names: list[str] = []

                for info in entries:
                    filename = info.filename
                    all_names.append(filename)

                    # ── Path traversal (basic) ──
                    if ".." in filename or filename.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-001",
                            title="ZIP path traversal",
                            description=(
                                f"Archive member '{filename}' contains path traversal. "
                                f"Extraction would write outside the target directory."
                            ),
                            severity=Severity.CRITICAL,
                            target=source,
                            evidence=f"Member: {filename}",
                            cwe_ids=["CWE-22"],
                        ))

                    # ── Unicode normalization bypass ──
                    findings.extend(
                        self._check_unicode_bypass(filename, source)
                    )

                    # ── Filename confusion ──
                    findings.extend(
                        self._check_filename_confusion(filename, source)
                    )

                    # ── Windows ADS ──
                    findings.extend(
                        self._check_windows_ads(filename, source)
                    )

                    # ── Symlink detection ──
                    if (info.external_attr >> 28) == 0xA:
                        try:
                            target = zf.read(info.filename).decode(
                                "utf-8", errors="replace"
                            )
                            symlinks[filename] = target

                            if ".." in target or target.startswith("/"):
                                findings.append(Finding.artifact(
                                    rule_id="ARCHSLIP-003",
                                    title="ZIP symlink escape",
                                    description=(
                                        f"Member '{filename}' is a symlink pointing to "
                                        f"'{target}'. This crosses the extraction boundary."
                                    ),
                                    severity=Severity.CRITICAL,
                                    target=source,
                                    evidence=f"Symlink: {filename} → {target}",
                                    cwe_ids=["CWE-59", "CWE-22"],
                                ))
                            else:
                                findings.append(Finding.artifact(
                                    rule_id="ARCHSLIP-021",
                                    title="ZIP symlink entry",
                                    description=(
                                        f"Member '{filename}' is a symlink to '{target}'. "
                                        f"Even local symlinks can be chained."
                                    ),
                                    severity=Severity.MEDIUM,
                                    target=source,
                                    cwe_ids=["CWE-59"],
                                ))
                        except Exception:
                            pass

                    # ── Size tracking ──
                    total_size += info.file_size
                    total_compressed += info.compress_size

                    stream_sample, stream_error = self._read_zip_member_limited(zf, info)
                    if stream_error:
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-022",
                            title="ZIP structural bomb indicator",
                            description=(
                                f"ZIP member '{filename}' could not be safely "
                                f"stream-validated: {stream_error}"
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            evidence=f"Member: {filename}; error={stream_error}",
                            cwe_ids=["CWE-409"],
                        ))
                    actual_sample_size = len(stream_sample)
                    if (
                        actual_sample_size > info.file_size
                        and info.file_size > 0
                        and actual_sample_size / info.file_size > 4
                    ):
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-023",
                            title="ZIP member size mismatch",
                            description=(
                                f"ZIP member '{filename}' decompresses to at least "
                                f"{actual_sample_size:,} bytes while the central "
                                f"directory advertises {info.file_size:,} bytes."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            evidence=f"Member: {filename}",
                            cwe_ids=["CWE-409"],
                        ))
                    if info.compress_size > 0:
                        stream_ratio = actual_sample_size / info.compress_size
                        if stream_ratio > MAX_COMPRESSION_RATIO:
                            findings.append(Finding.artifact(
                                rule_id="ARCHSLIP-022",
                                title=f"ZIP compression ratio bomb ({stream_ratio:.0f}:1)",
                                description=(
                                    f"Stream-verified compression ratio for '{filename}' "
                                    f"is at least {stream_ratio:.0f}:1."
                                ),
                                severity=Severity.HIGH,
                                target=source,
                                evidence=f"Member: {filename}",
                                cwe_ids=["CWE-409"],
                            ))

                    findings.extend(
                        self._scan_nested_archive_bytes(
                            stream_sample, filename, source, depth
                        )
                    )

                    # Flat size limit
                    if total_size > MAX_DECOMPRESSED_SIZE:
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-002",
                            title="ZIP decompression bomb (size limit)",
                            description=(
                                f"Total decompressed size exceeds "
                                f"{MAX_DECOMPRESSED_SIZE // (1024*1024)}MB."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            evidence=f"Total size: {total_size:,} bytes",
                            cwe_ids=["CWE-409"],
                        ))
                        break

                # ── Compression ratio bomb ──
                if total_compressed > 0:
                    ratio = total_size / total_compressed
                    if ratio > MAX_COMPRESSION_RATIO:
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-022",
                            title=f"ZIP compression ratio bomb ({ratio:.0f}:1)",
                            description=(
                                f"Compression ratio is {ratio:.0f}:1 "
                                f"(compressed: {total_compressed:,}, "
                                f"decompressed: {total_size:,}). "
                                f"Ratios above {MAX_COMPRESSION_RATIO:.0f}:1 "
                                f"indicate a decompression bomb."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            cwe_ids=["CWE-409"],
                        ))

                # ── Symlink chain analysis ──
                if symlinks:
                    findings.extend(
                        self._analyze_symlink_chains(symlinks, source, "ZIP")
                    )

                # ── Case-insensitive collision ──
                findings.extend(
                    self._check_case_collisions(all_names, source)
                )

        except zipfile.BadZipFile:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-010",
                title="Corrupt ZIP archive",
                description="File is a corrupt or malformed ZIP archive.",
                severity=Severity.MEDIUM,
                target=source,
            ))

        return findings

    # ─── TAR Scanning ─────────────────────────────────────────

    def _scan_tar(
        self,
        path: Path,
        depth: int = 0,
        source_override: str | None = None,
    ) -> List[Finding]:
        """Comprehensive TAR archive scan."""
        findings: list[Finding] = []
        source = source_override or str(path)

        try:
            with tarfile.open(path, "r:*") as tf:
                total_size = 0
                symlinks: dict[str, str] = {}
                all_names: list[str] = []
                entry_count = 0

                # Use iterative tf.next() instead of tf.getmembers()
                # to avoid loading all headers into memory at once (OOM protection)
                while True:
                    try:
                        member = tf.next()
                    except (tarfile.TarError, StopIteration):
                        break
                    if member is None:
                        break

                    entry_count += 1
                    if entry_count > MAX_ENTRY_COUNT:
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-033",
                            title="Excessive TAR entry count",
                            description=(
                                f"Archive contains >{MAX_ENTRY_COUNT:,} entries. "
                                f"Aborting scan — possible entry-count bomb."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            evidence=f"Entry count: >{MAX_ENTRY_COUNT:,}",
                            cwe_ids=["CWE-400"],
                        ))
                        break

                    all_names.append(member.name)

                    # ── Path traversal ──
                    if ".." in member.name or member.name.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-004",
                            title="TAR path traversal",
                            description=(
                                f"Member '{member.name}' contains path traversal."
                            ),
                            severity=Severity.CRITICAL,
                            target=source,
                            evidence=f"Member: {member.name}",
                            cwe_ids=["CWE-22"],
                        ))

                    # ── Unicode bypass ──
                    findings.extend(
                        self._check_unicode_bypass(member.name, source)
                    )

                    # ── Filename confusion ──
                    findings.extend(
                        self._check_filename_confusion(member.name, source)
                    )

                    # ── Symlink / hardlink ──
                    if member.issym():
                        lt = member.linkname
                        symlinks[member.name] = lt

                        if ".." in lt or lt.startswith("/"):
                            findings.append(Finding.artifact(
                                rule_id="ARCHSLIP-005",
                                title="TAR symlink sandbox escape",
                                description=(
                                    f"Member '{member.name}' is a symlink to '{lt}'. "
                                    f"This points outside the extraction directory."
                                ),
                                severity=Severity.CRITICAL,
                                target=source,
                                evidence=f"Symlink: {member.name} → {lt}",
                                cwe_ids=["CWE-59", "CWE-22"],
                            ))
                        else:
                            findings.append(Finding.artifact(
                                rule_id="ARCHSLIP-006",
                                title="TAR symlink entry",
                                description=(
                                    f"Member '{member.name}' is a symlink to '{lt}'."
                                ),
                                severity=Severity.MEDIUM,
                                target=source,
                                cwe_ids=["CWE-59"],
                            ))

                    if member.islnk():
                        lt = member.linkname
                        # Hardlinks to absolute paths
                        if lt.startswith("/") or ".." in lt:
                            findings.append(Finding.artifact(
                                rule_id="ARCHSLIP-030",
                                title="TAR hardlink escape",
                                description=(
                                    f"Member '{member.name}' is a hardlink to '{lt}'. "
                                    f"Hardlinks can overwrite files outside extraction dir."
                                ),
                                severity=Severity.CRITICAL,
                                target=source,
                                cwe_ids=["CWE-59", "CWE-22"],
                            ))

                        # Hardlinks to sensitive paths
                        if lt in SENSITIVE_PATHS:
                            findings.append(Finding.artifact(
                                rule_id="ARCHSLIP-031",
                                title=f"TAR hardlink to sensitive file: {lt}",
                                description=(
                                    f"Member '{member.name}' is a hardlink to '{lt}'. "
                                    f"This could read or overwrite sensitive system files."
                                ),
                                severity=Severity.CRITICAL,
                                target=source,
                                cwe_ids=["CWE-59"],
                            ))

                    # ── Device files ──
                    if member.ischr() or member.isblk():
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-007",
                            title="TAR device file entry",
                            description=(
                                f"Member '{member.name}' is a device file. "
                                f"Device files should never appear in model archives."
                            ),
                            severity=Severity.CRITICAL,
                            target=source,
                        ))

                    # ── FIFO entries ──
                    if member.isfifo():
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-032",
                            title="TAR FIFO entry",
                            description=(
                                f"Member '{member.name}' is a FIFO (named pipe). "
                                f"FIFOs can be used for inter-process communication "
                                f"attacks during extraction."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                        ))

                    # ── Dangerous permissions ──
                    if member.mode:
                        findings.extend(
                            self._check_permissions(member, source)
                        )

                    # ── Size tracking ──
                    total_size += member.size
                    if member.isfile() and _is_nested_archive_name(member.name):
                        nested_sample = self._read_tar_member_limited(tf, member)
                        findings.extend(
                            self._scan_nested_archive_bytes(
                                nested_sample, member.name, source, depth
                            )
                        )

                    if total_size > MAX_DECOMPRESSED_SIZE:
                        findings.append(Finding.artifact(
                            rule_id="ARCHSLIP-008",
                            title="TAR decompression bomb",
                            description=(
                                f"Total size exceeds "
                                f"{MAX_DECOMPRESSED_SIZE // (1024*1024)}MB."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            cwe_ids=["CWE-409"],
                        ))
                        break

                # Symlink chain analysis
                if symlinks:
                    findings.extend(
                        self._analyze_symlink_chains(symlinks, source, "TAR")
                    )

                # Case collision check
                findings.extend(
                    self._check_case_collisions(all_names, source)
                )

        except tarfile.TarError:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-011",
                title="Corrupt TAR archive",
                description="File is a corrupt or malformed TAR archive.",
                severity=Severity.MEDIUM,
                target=source,
            ))

        return findings

    # ─── Nested Archive Helpers ─────────────────────────────────

    @staticmethod
    def _read_zip_member_limited(
        zf: zipfile.ZipFile,
        info: zipfile.ZipInfo,
    ) -> tuple[bytes, str]:
        """Read a bounded sample from a ZIP member."""
        try:
            with zf.open(info, "r") as fh:
                return fh.read(MAX_STREAM_VALIDATE_BYTES + 1), ""
        except Exception as exc:
            return b"", str(exc)

    @staticmethod
    def _read_tar_member_limited(tf: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
        """Read a bounded sample from a TAR member."""
        try:
            fh = tf.extractfile(member)
            if fh is None:
                return b""
            with fh:
                return fh.read(MAX_STREAM_VALIDATE_BYTES + 1)
        except Exception:
            return b""

    def _scan_nested_archive_bytes(
        self,
        data: bytes,
        member_name: str,
        source: str,
        depth: int,
    ) -> List[Finding]:
        """Scan nested archives without extracting to user-controlled paths."""
        if depth >= MAX_NESTED_ARCHIVE_DEPTH:
            return []
        if not data or len(data) > MAX_STREAM_VALIDATE_BYTES:
            return []
        if not _is_nested_archive_name(member_name):
            return []

        suffix = _archive_suffix(member_name)
        tmp_path = ""
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as fh:
                fh.write(data)
                tmp_path = fh.name
            nested_source = f"{source}!{member_name}"
            return self._scan_file(Path(tmp_path), depth + 1, nested_source)
        except Exception as exc:
            logger.debug("Nested archive scan skipped for %s: %s", member_name, exc)
            return []
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ─── Symlink Chain Analysis ───────────────────────────────

    def _analyze_symlink_chains(
        self, symlinks: dict[str, str], source: str, fmt: str
    ) -> List[Finding]:
        """
        Detect multi-step symlink chains that escape sandbox.

        Attack: entry A → entry B → entry C → /etc/passwd
        Each individual link looks local, but the chain escapes.
        """
        findings = []

        for start, target in symlinks.items():
            visited = {start}
            current = target
            depth = 0

            while depth < MAX_SYMLINK_CHAIN_DEPTH:
                if current in symlinks and current not in visited:
                    visited.add(current)
                    current = symlinks[current]
                    depth += 1
                else:
                    break

            if depth > 1:
                # Multi-step chain detected
                chain_escapes = (
                    ".." in current or current.startswith("/")
                )
                if chain_escapes:
                    findings.append(Finding.artifact(
                        rule_id="ARCHSLIP-040",
                        title=f"{fmt} symlink chain escape (depth: {depth})",
                        description=(
                            f"Symlink chain starting at '{start}' resolves through "
                            f"{depth} links to '{current}' which is outside the "
                            f"extraction boundary. Each individual link appears safe, "
                            f"but the chain achieves sandbox escape."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        target=source,
                        evidence=(
                            f"Chain: {start} → ... ({depth} hops) → {current}"
                        ),
                        cwe_ids=["CWE-59", "CWE-22"],
                        remediation=(
                            "Resolve all symlinks before extraction and verify "
                            "final targets are within the extraction directory."
                        ),
                    ))
                else:
                    findings.append(Finding.artifact(
                        rule_id="ARCHSLIP-041",
                        title=f"{fmt} symlink chain (depth: {depth})",
                        description=(
                            f"Symlink chain from '{start}' to '{current}' via "
                            f"{depth} intermediate links. While the final target "
                            f"appears local, deep chains are suspicious."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                        cwe_ids=["CWE-59"],
                    ))

            # Circular symlink (DoS)
            if depth >= MAX_SYMLINK_CHAIN_DEPTH:
                findings.append(Finding.artifact(
                    rule_id="ARCHSLIP-042",
                    title=f"{fmt} circular symlink chain",
                    description=(
                        f"Symlink chain starting at '{start}' exceeds max depth "
                        f"({MAX_SYMLINK_CHAIN_DEPTH}). This could be a circular "
                        f"reference designed to cause DoS during extraction."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    cwe_ids=["CWE-835"],
                ))

        return findings

    # ─── Unicode Bypass Detection ─────────────────────────────

    def _check_unicode_bypass(self, filename: str, source: str) -> List[Finding]:
        """
        Detect Unicode normalization path traversal bypasses.

        Attack: use Unicode look-alikes for '..' or '/' to bypass
        ASCII-only path checks. When the filesystem normalizes
        these characters, they become real path separators.
        """
        findings = []

        # Check for look-alike separators
        for char in filename:
            if char in LOOKALIKE_SEPARATORS:
                findings.append(Finding.artifact(
                    rule_id="ARCHSLIP-050",
                    title="Unicode path separator look-alike",
                    description=(
                        f"Filename '{filename}' contains Unicode character "
                        f"U+{ord(char):04X} ({unicodedata.name(char, 'UNKNOWN')}) "
                        f"which resembles a path separator. After Unicode normalization, "
                        f"this may become a real separator enabling path traversal."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Char: U+{ord(char):04X} in '{filename}'",
                    cwe_ids=["CWE-22", "CWE-176"],
                ))
                break

        # Check for look-alike dots
        for char in filename:
            if char in LOOKALIKE_DOTS:
                findings.append(Finding.artifact(
                    rule_id="ARCHSLIP-051",
                    title="Unicode dot look-alike in filename",
                    description=(
                        f"Filename '{filename}' contains Unicode character "
                        f"U+{ord(char):04X} which resembles a period/dot. "
                        f"Combined with other characters, this could bypass "
                        f"'../' path traversal checks."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Char: U+{ord(char):04X}",
                    cwe_ids=["CWE-22", "CWE-176"],
                ))
                break

        # Check NFC/NFD normalization difference
        nfc = unicodedata.normalize("NFC", filename)
        nfd = unicodedata.normalize("NFD", filename)
        if nfc != nfd and (".." in nfc or ".." in nfd):
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-052",
                title="Unicode normalization produces path traversal",
                description=(
                    f"Filename '{filename}' normalizes to different forms "
                    f"under NFC/NFD that contain path traversal patterns."
                ),
                severity=Severity.CRITICAL,
                target=source,
                cwe_ids=["CWE-22", "CWE-176"],
            ))

        return findings

    # ─── Windows ADS Detection ────────────────────────────────

    def _check_windows_ads(self, filename: str, source: str) -> List[Finding]:
        """Detect Windows Alternate Data Streams (NTFS ADS)."""
        findings = []

        # ADS format: filename:stream_name or filename:stream_name:$DATA
        # Skip colons in Windows drive letters (C:\)
        parts = filename.split("/")
        for part in parts:
            if ":" in part:
                # Skip drive letter patterns
                if len(part) >= 2 and part[1] == ":" and part[0].isalpha():
                    continue
                findings.append(Finding.artifact(
                    rule_id="ARCHSLIP-060",
                    title="Windows Alternate Data Stream (ADS)",
                    description=(
                        f"Filename '{filename}' contains a colon which is the "
                        f"NTFS Alternate Data Stream separator. On Windows, "
                        f"this hides data in an alternate stream of a file."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Filename: {filename}",
                    cwe_ids=["CWE-22"],
                ))
                break

        return findings

    # ─── Filename Confusion ───────────────────────────────────

    def _check_filename_confusion(
        self, filename: str, source: str
    ) -> List[Finding]:
        """Detect filename confusion attacks."""
        findings = []

        # Null bytes
        if "\x00" in filename:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-070",
                title="Null byte in archive filename",
                description=(
                    "Filename contains null byte which can truncate the path "
                    "in C-based extractors, causing files to be written to "
                    "unexpected locations."
                ),
                severity=Severity.CRITICAL,
                target=source,
                cwe_ids=["CWE-626"],
            ))

        # Control characters
        for char in filename:
            if ord(char) in CONTROL_CHARS:
                findings.append(Finding.artifact(
                    rule_id="ARCHSLIP-071",
                    title="Control character in archive filename",
                    description=(
                        f"Filename contains control character U+{ord(char):04X}. "
                        f"Control characters can cause display issues and may "
                        f"confuse extraction tools."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                ))
                break

        # Backslash (potential Windows path on Unix)
        if "\\" in filename and "/" not in filename:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-072",
                title="Backslash path separator in filename",
                description=(
                    f"Filename '{filename}' uses backslash separators. "
                    f"This may be treated differently on Windows vs Unix, "
                    f"potentially bypassing path traversal checks."
                ),
                severity=Severity.LOW,
                target=source,
            ))

        return findings

    # ─── Case Collision Detection ─────────────────────────────

    def _check_case_collisions(
        self, names: list[str], source: str
    ) -> List[Finding]:
        """Detect case-insensitive filename collisions."""
        findings = []
        seen: dict[str, str] = {}

        for name in names:
            lower = name.lower()
            if lower in seen and seen[lower] != name:
                findings.append(Finding.artifact(
                    rule_id="ARCHSLIP-080",
                    title="Case-insensitive filename collision",
                    description=(
                        f"Entries '{seen[lower]}' and '{name}' differ only in case. "
                        f"On case-insensitive filesystems (Windows, macOS default), "
                        f"one will overwrite the other during extraction."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"Collision: '{seen[lower]}' vs '{name}'",
                ))
            seen[lower] = name

        return findings

    # ─── Permission Checks (TAR) ──────────────────────────────

    def _check_permissions(self, member, source: str) -> List[Finding]:
        """Check TAR member permissions for dangerous modes."""
        findings = []
        mode = member.mode

        # SUID/SGID bits
        if mode & stat.S_ISUID:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-090",
                title=f"SUID bit set: {member.name}",
                description=(
                    f"Member '{member.name}' has SUID bit set. "
                    f"SUID executables run with the file owner's privileges."
                ),
                severity=Severity.CRITICAL,
                target=source,
            ))

        if mode & stat.S_ISGID:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-091",
                title=f"SGID bit set: {member.name}",
                description=(
                    f"Member '{member.name}' has SGID bit set."
                ),
                severity=Severity.HIGH,
                target=source,
            ))

        # World-writable
        if mode & stat.S_IWOTH:
            findings.append(Finding.artifact(
                rule_id="ARCHSLIP-092",
                title=f"World-writable permissions: {member.name}",
                description=(
                    f"Member '{member.name}' has world-writable permissions "
                    f"(mode: {oct(mode)}). This is unusual for model files."
                ),
                severity=Severity.LOW,
                target=source,
            ))

        return findings


def _is_nested_archive_name(name: str) -> bool:
    """Return True when an archive member name looks like another archive."""
    lowered = name.lower()
    return any(lowered.endswith(ext) for ext in NESTED_ARCHIVE_EXTENSIONS)


def _archive_suffix(name: str) -> str:
    """Preserve compound archive suffixes for temporary nested scans."""
    lowered = name.lower()
    for suffix in NESTED_ARCHIVE_EXTENSIONS:
        if lowered.endswith(suffix):
            return suffix
    return Path(name).suffix or ".archive"
