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
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from ...finding import Finding, Severity
from ...scan_safety import FileTooLargeError, safe_read_bytes
from .._pickle_rules import _check_list, load_default_rules
from .analyzer import deep_analyze
from .findings import build_findings
from .protocol_detector import PickleProtocolDetector

if TYPE_CHECKING:
    import zipfile

    from .._pickle_ops import PickleAnalysis

logger = logging.getLogger(__name__)

PickleBackend = Literal["auto", "rust", "python"]

try:
    import sentinel_pickle as _sentinel_pickle
    from sentinel_pickle import PickleScanner as RustPickleScanner
    HAS_RUST_REPORT_API = (
        hasattr(_sentinel_pickle, "scan_bytes_report")
        and hasattr(RustPickleScanner, "scan_bytes_report")
    )
    HAS_RUST_ENGINE = True
    logger.debug("Rust pickle engine available (report_api=%s)", HAS_RUST_REPORT_API)
except ImportError:
    HAS_RUST_ENGINE = False
    HAS_RUST_REPORT_API = False


class PickleScanner:
    """Pickle byte-stream scanner with crash-resilient opcode analysis."""

    def __init__(
        self,
        blocklist: dict[str, list[str]] | None = None,
        allowlist: dict[str, list[str]] | None = None,
        prefer_rust: bool = True,
        backend: PickleBackend | str | None = None,
    ):
        if blocklist:
            self._blocklist = blocklist
            self._allowlist = allowlist or {}
        else:
            self._blocklist, self._allowlist = load_default_rules()
        self._requested_backend = self._resolve_backend(backend, prefer_rust=prefer_rust)
        if self._requested_backend == "rust" and not HAS_RUST_ENGINE:
            raise RuntimeError(
                "SENTINEL_PICKLE_BACKEND=rust was requested, but the sentinel_pickle "
                "Rust extension is not importable. Build/install rust/sentinel-pickle "
                "with maturin or use backend='auto'/'python'."
            )
        self._prefer_rust = self._requested_backend in {"auto", "rust"} and HAS_RUST_ENGINE
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
        rust_findings: list[Finding] = []
        if self._rust_scanner:
            try:
                rust_findings = self._scan_with_rust(data, source)
                if rust_findings and self._requested_backend == "rust":
                    return rust_findings
                if rust_findings:
                    logger.debug("Rust engine returned findings; running Python parity analyzer")
                else:
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
        return self._merge_rust_findings(rust_findings, findings)

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

    @property
    def rust_available(self) -> bool:
        return HAS_RUST_ENGINE

    @property
    def requested_backend(self) -> PickleBackend:
        return self._requested_backend

    # ─── Internal ─────────────────────────────────────────────

    @staticmethod
    def _resolve_backend(backend: PickleBackend | str | None, *, prefer_rust: bool) -> PickleBackend:
        raw = backend or os.environ.get("SENTINEL_PICKLE_BACKEND") or os.environ.get(
            "SENTINEL_PICKLE_ENGINE"
        )
        value = (raw or ("auto" if prefer_rust else "python")).strip().lower()
        aliases = {
            "native": "rust",
            "rs": "rust",
            "py": "python",
            "pure-python": "python",
        }
        resolved = aliases.get(value, value)
        if resolved not in {"auto", "rust", "python"}:
            raise ValueError(
                "pickle backend must be one of 'auto', 'rust', or 'python' "
                f"(got {raw!r})"
            )
        return resolved  # type: ignore[return-value]

    def _deep_analyze(self, data: bytes, source: str) -> PickleAnalysis:
        return deep_analyze(data, source, self._blocklist, self._allowlist)

    def _scan_with_rust(self, data: bytes, source: str) -> list[Finding]:
        findings: list[Finding] = []

        if HAS_RUST_REPORT_API:
            report = self._rust_scanner.scan_bytes_report(data)
            verdict = getattr(report, "verdict", None)
            verdict_str = str(verdict) if verdict is not None else "unknown"

            # Fail-closed: if the scan was incomplete, surface a finding
            # so the caller knows the result cannot be trusted as "clean".
            if verdict_str == "unknown" or getattr(report, "aborted", False):
                findings.append(Finding.artifact(
                    rule_id="PICKLE-INCONCLUSIVE",
                    title="Pickle scan inconclusive",
                    description=(
                        "The Rust pickle engine could not complete a trusted scan "
                        "because it exhausted a budget or encountered malformed structure. "
                        "The file cannot be declared clean; "
                        "treat as potentially malicious."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"opcode_count={getattr(report, 'opcode_count', '?')}",
                    cwe_ids=["CWE-400"],
                ))

            raw_findings = getattr(report, "findings", [])
        else:
            raw_findings = self._rust_scanner.scan_bytes_py(data)

        for rf in raw_findings:
            severity_str = getattr(rf, "severity", "HIGH").upper()
            sev = getattr(Severity, severity_str, Severity.HIGH)
            findings.append(Finding.artifact(
                rule_id=getattr(rf, "rule_id", "PICKLE-RUST"),
                title=getattr(rf, "title", "Pickle finding (Rust)"),
                description=getattr(rf, "description", ""),
                severity=sev,
                target=source,
                evidence=getattr(rf, "evidence", ""),
                cwe_ids=getattr(rf, "cwe_ids", []) or ["CWE-502"],
            ))
        return findings

    def _merge_rust_findings(self, rust_findings: list[Finding], python_findings: list[Finding]) -> list[Finding]:
        if not rust_findings:
            return python_findings

        merged = list(python_findings)
        seen = {(finding.rule_id, finding.target, finding.evidence) for finding in merged}
        for finding in rust_findings:
            if finding.rule_id == "PICKLE-UNK":
                if python_findings or self._is_allowlisted_unknown(finding):
                    continue
            key = (finding.rule_id, finding.target, finding.evidence)
            if key not in seen:
                merged.append(finding)
                seen.add(key)
        return merged

    def _is_allowlisted_unknown(self, finding: Finding) -> bool:
        subject_text = f"{finding.title} {finding.evidence}"
        match = re.search(r"import:\s*([A-Za-z0-9_][A-Za-z0-9_\.]*)", subject_text)
        subject = match.group(1) if match else subject_text.rsplit(" ", 1)[-1].strip()
        module, sep, name = subject.partition(".")
        if not sep:
            return False
        parts = subject.split(".")
        for index in range(1, len(parts)):
            candidate_module = ".".join(parts[:index])
            candidate_name = ".".join(parts[index:])
            if _check_list(candidate_module, candidate_name, self._allowlist):
                return True
        return _check_list(module, name, self._allowlist)
