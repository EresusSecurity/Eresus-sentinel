"""Pickle byte-stream scanner — public API.

Delegates to:
  analyzer.py  — deep opcode analysis
  findings.py  — finding generation
  raw_scan.py  — crash-resilient fallback
  formats.py   — format detection helpers
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import BinaryIO, Optional

from .._pickle_ops import PickleAnalysis
from .._pickle_rules import load_default_rules
from ...finding import Finding, Severity
from ...scan_safety import safe_read_bytes, FileTooLargeError
from .analyzer import deep_analyze
from .findings import build_findings

logger = logging.getLogger(__name__)


class PickleScanner:
    """Pickle byte-stream scanner with crash-resilient opcode analysis."""

    def __init__(
        self,
        blocklist: Optional[dict[str, list[str]]] = None,
        allowlist: Optional[dict[str, list[str]]] = None,
    ):
        if blocklist:
            self._blocklist = blocklist
            self._allowlist = allowlist or {}
        else:
            self._blocklist, self._allowlist = load_default_rules()

    # ─── Public API ───────────────────────────────────────────

    def scan_bytes(
        self,
        data: bytes,
        source: str = "<bytes>",
    ) -> list[Finding]:
        """Scan a pickle byte stream and return findings."""
        analysis = self._deep_analyze(data, source)
        return build_findings(analysis, source)

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """Scan a pickle file from disk."""
        path = Path(file_path)
        if not path.exists():
            logger.warning("File not found: %s", path)
            return []
        try:
            data = safe_read_bytes(path)
        except FileTooLargeError as e:
            logger.warning("File too large to scan: %s", e)
            return [Finding.artifact(
                rule_id="PICKLE-SIZE",
                title="File too large to scan safely",
                description=str(e),
                severity=Severity.HIGH,
                target=str(path),
                cwe_ids=["CWE-400"],
            )]
        return self.scan_bytes(data, source=str(path))

    def scan_stream(self, stream: BinaryIO, source: str = "<stream>") -> list[Finding]:
        """Scan a pickle from a file-like object."""
        data = stream.read()
        return self.scan_bytes(data, source=source)

    def scan_zip_entry(
        self,
        zip_file: zipfile.ZipFile,
        entry_name: str,
        source: str = "<zip>",
    ) -> list[Finding]:
        """Scan a single entry from a ZIP archive."""
        data = zip_file.read(entry_name)
        return self.scan_bytes(data, source=f"{source}!{entry_name}")

    def raw_analysis(self, data: bytes, source: str = "<bytes>") -> PickleAnalysis:
        """Return raw PickleAnalysis without converting to findings."""
        return self._deep_analyze(data, source)

    # ─── Internal ─────────────────────────────────────────────

    def _deep_analyze(self, data: bytes, source: str) -> PickleAnalysis:
        return deep_analyze(data, source, self._blocklist, self._allowlist)
