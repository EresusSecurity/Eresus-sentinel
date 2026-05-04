"""Compressed wrapper scanner for model artifacts."""

from __future__ import annotations

import bz2
import gzip
import lzma
import tempfile
import zlib
from pathlib import Path

from ..finding import Finding, Severity

MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024


class CompressedWrapperScanner:
    """Decompress simple wrappers and route the inner artifact to scanners."""

    EXTENSIONS = {".gz", ".bz2", ".xz", ".lz4", ".zlib"}

    def scan_file(self, filepath: str) -> list[Finding]:
        path = Path(filepath)
        suffix = path.suffix.lower()
        if not path.exists() or suffix not in self.EXTENSIONS:
            return []

        if suffix == ".lz4":
            return [
                Finding.artifact(
                    rule_id="COMPRESSED-UNSUPPORTED",
                    title="LZ4 wrapper scanning is unsupported",
                    description="No safe LZ4 decompressor is configured; treat the wrapped artifact as inconclusive.",
                    severity=Severity.HIGH,
                    target=filepath,
                    confidence=0.9,
                )
            ]

        try:
            raw = path.read_bytes()
            data = self._decompress(raw, suffix)
        except Exception as exc:
            return [
                Finding.artifact(
                    rule_id="COMPRESSED-001",
                    title="Compressed artifact could not be decompressed",
                    description=f"{type(exc).__name__}: {exc}",
                    severity=Severity.HIGH,
                    target=filepath,
                    confidence=0.9,
                )
            ]

        if len(data) > MAX_DECOMPRESSED_BYTES:
            return [
                Finding.artifact(
                    rule_id="COMPRESSED-002",
                    title="Compressed artifact expands beyond safe limit",
                    description=f"Decompressed size exceeds {MAX_DECOMPRESSED_BYTES} bytes.",
                    severity=Severity.HIGH,
                    target=filepath,
                    cwe_ids=["CWE-400"],
                    confidence=0.95,
                )
            ]

        inner_suffix = self._inner_suffix(path)
        if not inner_suffix:
            return [
                Finding.artifact(
                    rule_id="COMPRESSED-003",
                    title="Compressed artifact has no detectable inner extension",
                    description="The wrapper was decompressed, but the inner artifact type cannot be routed safely.",
                    severity=Severity.MEDIUM,
                    target=filepath,
                    confidence=0.75,
                )
            ]

        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=inner_suffix,
                prefix="sentinel-inner-",
                delete=False,
            ) as handle:
                handle.write(data)
                tmp_path = Path(handle.name)

            from sentinel.artifact import scan_file

            findings = scan_file(tmp_path, fail_closed=True)
            for finding in findings:
                finding.target = f"{filepath}!{tmp_path.name}"
            return findings
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @staticmethod
    def _decompress(raw: bytes, suffix: str) -> bytes:
        if suffix == ".gz":
            return gzip.decompress(raw)
        if suffix == ".bz2":
            return bz2.decompress(raw)
        if suffix == ".xz":
            return lzma.decompress(raw)
        if suffix == ".zlib":
            return zlib.decompress(raw)
        raise ValueError(f"unsupported wrapper: {suffix}")

    @staticmethod
    def _inner_suffix(path: Path) -> str:
        suffixes = path.suffixes
        if len(suffixes) < 2:
            return ""
        return suffixes[-2].lower()
