"""Pickle byte-stream scanner — public API.

Delegates to:
  analyzer.py  — deep opcode analysis
  findings.py  — finding generation
  raw_scan.py  — crash-resilient fallback
  formats.py   — format detection helpers

Falls back to Rust engine (sentinel_pickle) when available for faster scanning.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from ...finding import Finding, Severity
from ...scan_safety import FileTooLargeError, safe_read_bytes
from .._pickle_rules import load_default_rules
from .analyzer import deep_analyze
from .findings import build_findings
from .protocol_detector import PickleProtocolDetector

if TYPE_CHECKING:
    import zipfile

    from .._pickle_ops import PickleAnalysis

logger = logging.getLogger(__name__)

try:
    from sentinel_pickle import PickleScanner as RustPickleScanner
    HAS_RUST_ENGINE = True
    logger.debug("Rust pickle engine available")
except ImportError:
    HAS_RUST_ENGINE = False


class PickleScanner:
    """Pickle byte-stream scanner with crash-resilient opcode analysis."""

    def __init__(
        self,
        blocklist: dict[str, list[str]] | None = None,
        allowlist: dict[str, list[str]] | None = None,
        prefer_rust: bool = True,
    ):
        if blocklist:
            self._blocklist = blocklist
            self._allowlist = allowlist or {}
        else:
            self._blocklist, self._allowlist = load_default_rules()
        self._prefer_rust = prefer_rust and HAS_RUST_ENGINE
        self._rust_scanner = RustPickleScanner() if self._prefer_rust else None
        self._protocol_detector = PickleProtocolDetector()

    # ─── Public API ───────────────────────────────────────────

    def scan_bytes(
        self,
        data: bytes,
        source: str = "<bytes>",
    ) -> list[Finding]:
        """Scan a pickle byte stream and return findings."""
        # ZIP archives (e.g. PyTorch .pt, Keras .keras) are not raw pickle —
        # skip to avoid false positives from misinterpreting container bytes.
        if data[:4] == b"PK\x03\x04":
            return []
        if self._rust_scanner:
            try:
                rust_findings = self._scan_with_rust(data, source)
                if rust_findings:
                    return rust_findings
                logger.debug("Rust engine returned no findings; running Python analyzer")
            except Exception as e:
                logger.debug("Rust engine failed, falling back to Python: %s", e)
        analysis = self._deep_analyze(data, source)
        findings = build_findings(analysis, source)
        # Protocol-specific gadget scan (complements opcode analysis)
        proto_findings = self._protocol_detector.scan(
            data, source, protocol=analysis.protocol_version
        )
        # Deduplicate by rule_id + target
        seen = {(f.rule_id, f.target) for f in findings}
        for pf in proto_findings:
            if (pf.rule_id, pf.target) not in seen:
                findings.append(pf)
                seen.add((pf.rule_id, pf.target))
        return findings

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

    @property
    def engine(self) -> str:
        return "rust" if self._rust_scanner else "python"

    # ─── Internal ─────────────────────────────────────────────

    def _deep_analyze(self, data: bytes, source: str) -> PickleAnalysis:
        return deep_analyze(data, source, self._blocklist, self._allowlist)

    def _scan_with_rust(self, data: bytes, source: str) -> list[Finding]:
        rust_findings = self._rust_scanner.scan_data(data)
        findings: list[Finding] = []
        for rf in rust_findings:
            severity_str = getattr(rf, "severity", "HIGH").upper()
            sev = getattr(Severity, severity_str, Severity.HIGH)
            findings.append(Finding.artifact(
                rule_id=getattr(rf, "rule_id", "PICKLE-RUST"),
                title=getattr(rf, "title", "Pickle finding (Rust)"),
                description=getattr(rf, "description", ""),
                severity=sev,
                target=source,
                evidence=getattr(rf, "evidence", ""),
                cwe_ids=getattr(rf, "cwe_ids", []),
            ))
        return findings
