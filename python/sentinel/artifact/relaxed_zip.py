"""
Eresus Sentinel — Relaxed ZIP Parser.

Handles malformed/corrupted ZIP archives that standard zipfile rejects.
Attackers can craft ZIP files with:
  - Corrupted central directory
  - Mismatched CRC checksums
  - Non-standard compression methods
  - Truncated local file headers
  - Overlapping entries

These bypass standard zipfile validation but can still be extracted by
torch.load(), pickle.load(), and other loaders that use lenient parsers.

Usage:
    from sentinel.artifact.relaxed_zip import RelaxedZipFile

    # Falls back to relaxed parsing when standard zipfile fails
    zf = RelaxedZipFile.open(path_or_bytes)
    for entry in zf.entries():
        data = zf.read(entry.name)
"""

from __future__ import annotations

import io
import logging
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

# ZIP magic bytes
LOCAL_FILE_HEADER_MAGIC = b"PK\x03\x04"
CENTRAL_DIR_MAGIC = b"PK\x01\x02"
END_OF_CENTRAL_DIR_MAGIC = b"PK\x05\x06"

# Local file header size (fixed part)
LOCAL_HEADER_SIZE = 30


@dataclass
class ZipEntry:
    """A single entry in a relaxed ZIP archive."""
    name: str
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    offset: int  # Offset of local file header
    data_offset: int  # Offset of actual file data
    crc32: int
    is_corrupted: bool = False
    corruption_reason: str = ""


class RelaxedZipFile:
    """
    ZIP parser that tolerates malformed archives.

    Standard library's zipfile module raises BadZipFile for any structural
    anomaly. This parser recovers what it can, which is essential for
    scanning adversarial model files that intentionally corrupt ZIP
    structure to evade scanners while remaining loadable by PyTorch.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._entries: list[ZipEntry] = []
        self._findings: list[Finding] = []
        self._parse()

    @classmethod
    def open(cls, source: Union[str, Path, bytes]) -> "RelaxedZipFile":
        """Open a ZIP file from path or bytes."""
        if isinstance(source, (str, Path)):
            data = Path(source).read_bytes()
        else:
            data = source
        return cls(data)

    @classmethod
    def try_standard_then_relaxed(
        cls, source: Union[str, Path, bytes], target: str = ""
    ) -> tuple[zipfile.ZipFile | "RelaxedZipFile", list[Finding]]:
        """
        Try standard zipfile first; fall back to relaxed on failure.

        Returns (zipfile, findings) where findings contains any
        corruption warnings from the relaxed parser.
        """
        findings: list[Finding] = []

        if isinstance(source, (str, Path)):
            path = Path(source)
            try:
                zf = zipfile.ZipFile(path, "r")
                return zf, findings
            except zipfile.BadZipFile:
                findings.append(Finding.artifact(
                    rule_id="ZIP-001",
                    title="Malformed ZIP — using relaxed parser",
                    description=(
                        f"Standard ZIP parser rejected '{target or path.name}'. "
                        f"Falling back to relaxed parser. Malformed ZIPs are commonly "
                        f"used to evade security scanners while remaining loadable by "
                        f"model frameworks (PyTorch, TensorFlow)."
                    ),
                    severity=Severity.HIGH,
                    target=target or str(path),
                    cwe_ids=["CWE-434"],
                ))
                data = path.read_bytes()
        else:
            data = source
            try:
                zf = zipfile.ZipFile(io.BytesIO(data), "r")
                return zf, findings
            except zipfile.BadZipFile:
                findings.append(Finding.artifact(
                    rule_id="ZIP-001",
                    title="Malformed ZIP — using relaxed parser",
                    description=(
                        "Standard ZIP parser rejected the data. Falling back to "
                        "relaxed parser. This is a security indicator."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                ))

        relaxed = cls(data)
        findings.extend(relaxed.get_findings())
        return relaxed, findings

    def entries(self) -> list[ZipEntry]:
        """Return all discovered entries."""
        return self._entries

    def namelist(self) -> list[str]:
        """Return names of all entries (zipfile.ZipFile compatible)."""
        return [e.name for e in self._entries]

    def read(self, name: str) -> bytes:
        """Read data for a named entry."""
        for entry in self._entries:
            if entry.name == name:
                return self._read_entry(entry)
        raise KeyError(f"Entry not found: {name}")

    def get_findings(self) -> list[Finding]:
        """Return security findings from parsing."""
        return list(self._findings)

    # ─── Internal parsing ─────────────────────────────────────

    def _parse(self) -> None:
        """Parse ZIP structure with relaxed validation."""
        data = self._data
        offset = 0

        # Scan for local file headers
        while offset < len(data) - LOCAL_HEADER_SIZE:
            # Find next PK\x03\x04 signature
            pos = data.find(LOCAL_FILE_HEADER_MAGIC, offset)
            if pos < 0:
                break

            try:
                entry = self._parse_local_header(pos)
                if entry:
                    self._entries.append(entry)
                    # Move past this entry
                    offset = entry.data_offset + entry.compressed_size
                else:
                    offset = pos + 4
            except Exception as e:
                logger.debug("Relaxed ZIP parse error at offset %d: %s", pos, e)
                offset = pos + 4

        if not self._entries:
            # Try central directory approach
            self._parse_central_directory()

    def _parse_local_header(self, offset: int) -> ZipEntry | None:
        """Parse a local file header at the given offset."""
        data = self._data
        if offset + LOCAL_HEADER_SIZE > len(data):
            return None

        # Local file header structure (30 bytes fixed):
        # 4: signature
        # 2: version needed
        # 2: flags
        # 2: compression method
        # 2: mod time
        # 2: mod date
        # 4: CRC-32
        # 4: compressed size
        # 4: uncompressed size
        # 2: filename length
        # 2: extra field length
        try:
            (
                sig, ver, flags, method, _mtime, _mdate,
                crc32, comp_size, uncomp_size,
                name_len, extra_len
            ) = struct.unpack_from("<4sHHHHHIIIHH", data, offset)
        except struct.error:
            return None

        if sig != LOCAL_FILE_HEADER_MAGIC:
            return None

        filename_start = offset + LOCAL_HEADER_SIZE
        filename_end = filename_start + name_len

        if filename_end > len(data):
            return None

        try:
            filename = data[filename_start:filename_end].decode("utf-8", errors="replace")
        except Exception:
            filename = f"<corrupt-entry-{offset}>"

        data_offset = filename_end + extra_len

        # Validate sizes
        is_corrupted = False
        corruption_reason = ""

        if comp_size == 0 and (flags & 0x08):
            # Data descriptor follows — sizes in descriptor after data
            # Try to find the next local header or central dir to determine size
            next_header = data.find(LOCAL_FILE_HEADER_MAGIC, data_offset + 1)
            next_cd = data.find(CENTRAL_DIR_MAGIC, data_offset + 1)

            if next_header > 0 and (next_cd < 0 or next_header < next_cd):
                comp_size = next_header - data_offset
            elif next_cd > 0:
                comp_size = next_cd - data_offset
            else:
                comp_size = len(data) - data_offset

            is_corrupted = True
            corruption_reason = "Data descriptor flag set, sizes recovered heuristically"

        if data_offset + comp_size > len(data):
            comp_size = len(data) - data_offset
            is_corrupted = True
            corruption_reason = f"Compressed size truncated from {comp_size} to {len(data) - data_offset}"

        if is_corrupted:
            self._findings.append(Finding.artifact(
                rule_id="ZIP-002",
                title=f"Corrupted ZIP entry: {filename}",
                description=(
                    f"ZIP entry '{filename}' has structural issues: {corruption_reason}. "
                    f"This can be used to evade scanners that use strict ZIP parsing."
                ),
                severity=Severity.MEDIUM,
                target=filename,
                evidence=corruption_reason,
            ))

        return ZipEntry(
            name=filename,
            compressed_size=comp_size,
            uncompressed_size=uncomp_size,
            compression_method=method,
            offset=offset,
            data_offset=data_offset,
            crc32=crc32,
            is_corrupted=is_corrupted,
            corruption_reason=corruption_reason,
        )

    def _parse_central_directory(self) -> None:
        """Parse central directory records as fallback."""
        data = self._data
        offset = 0

        while True:
            pos = data.find(CENTRAL_DIR_MAGIC, offset)
            if pos < 0:
                break

            try:
                if pos + 46 > len(data):
                    break

                (
                    _sig, _ver_made, _ver_needed, _flags, method,
                    _mtime, _mdate, crc32, comp_size, uncomp_size,
                    name_len, extra_len, comment_len,
                    _disk_start, _int_attr, _ext_attr, local_offset
                ) = struct.unpack_from("<4sHHHHHHIIIHHHHHII", data, pos)

                name_start = pos + 46
                name_end = name_start + name_len
                if name_end > len(data):
                    break

                filename = data[name_start:name_end].decode("utf-8", errors="replace")

                # Calculate data offset from local header
                if local_offset + LOCAL_HEADER_SIZE < len(data):
                    local_name_len = struct.unpack_from("<H", data, local_offset + 26)[0]
                    local_extra_len = struct.unpack_from("<H", data, local_offset + 28)[0]
                    data_off = local_offset + LOCAL_HEADER_SIZE + local_name_len + local_extra_len
                else:
                    data_off = 0

                self._entries.append(ZipEntry(
                    name=filename,
                    compressed_size=comp_size,
                    uncompressed_size=uncomp_size,
                    compression_method=method,
                    offset=local_offset,
                    data_offset=data_off,
                    crc32=crc32,
                    is_corrupted=True,
                    corruption_reason="Recovered from central directory only",
                ))

                offset = name_end + extra_len + comment_len

            except (struct.error, Exception) as e:
                logger.debug("Central directory parse error at %d: %s", pos, e)
                offset = pos + 4

    def _read_entry(self, entry: ZipEntry) -> bytes:
        """Read and decompress an entry's data."""
        data = self._data
        raw = data[entry.data_offset:entry.data_offset + entry.compressed_size]

        if entry.compression_method == 0:
            # Stored (no compression)
            return raw
        elif entry.compression_method == 8:
            # Deflate
            import zlib
            try:
                return zlib.decompress(raw, -15)
            except zlib.error:
                # Try with different wbits
                try:
                    return zlib.decompress(raw)
                except zlib.error:
                    logger.warning("Failed to decompress entry: %s", entry.name)
                    return raw
        else:
            logger.warning(
                "Unknown compression method %d for %s",
                entry.compression_method, entry.name
            )
            return raw
