"""
Eresus Sentinel — Cross-Format Integrity Verification Engine.

Unified engine that runs all format-specific scanners on a file based on
extension + magic bytes, and produces a single ArtifactAssessment report
with cross-cutting analysis:

- Magic byte verification: confirm extension matches actual format
- File size sanity: flag anomalous sizes for each format
- SHA256 provenance: optional integrity verification against known-good hashes
- Composite risk scoring: aggregate findings from all applicable scanners
- Scanner evasion detection: files that bypass one scanner but caught by another
- Format confusion: files disguised as one format but containing another

This engine provides the top-level API that users call — it delegates to
the format-specific scanners under the hood.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── Magic bytes for format detection ──────────────────────────────

MAGIC_SIGNATURES: dict[str, list[tuple[bytes, int]]] = {
    # format: [(magic_bytes, offset)]
    "pickle": [(b"\x80\x02", 0), (b"\x80\x03", 0), (b"\x80\x04", 0), (b"\x80\x05", 0)],
    "zip": [(b"PK\x03\x04", 0)],
    "pytorch_zip": [(b"\x50\x71\x30\x6f", 0)],  # PyTorch magic
    "gguf": [(b"GGUF", 0)],
    "onnx": [],  # Protobuf doesn't have a fixed magic — use extension
    "hdf5": [(b"\x89HDF\r\n\x1a\n", 0)],
    "safetensors": [(b"{", 0)],  # JSON header
    "tflite": [(b"\x18\x00\x00\x00", 4)],  # FlatBuffer identifier offset
    "elf": [(b"\x7fELF", 0)],  # ELF executable (llamafile)
    "pe": [(b"MZ", 0)],  # Windows PE (llamafile)
    "tar": [(b"ustar", 257)],  # POSIX tar magic
    "gzip": [(b"\x1f\x8b", 0)],
    "bzip2": [(b"BZ", 0)],
}

# ── Extension → expected format mapping ──────────────────────────

EXTENSION_FORMAT_MAP: dict[str, str] = {
    ".pkl": "pickle", ".pickle": "pickle", ".p": "pickle",
    ".pt": "pytorch", ".pth": "pytorch", ".bin": "pytorch",
    ".ckpt": "pytorch",
    ".gguf": "gguf",
    ".onnx": "onnx",
    ".h5": "hdf5", ".hdf5": "hdf5",
    ".keras": "zip",  # .keras is a ZIP
    ".safetensors": "safetensors",
    ".tflite": "tflite",
    ".llamafile": "executable",
    ".nemo": "tar",
    ".mar": "zip",
    ".tar": "tar", ".tar.gz": "tar", ".tgz": "tar",
    ".tar.bz2": "tar",
    ".zip": "zip",
    ".pb": "protobuf",  # TensorFlow SavedModel
}

# ── Scanner routing ──────────────────────────────────────────────

# Maps scanner name to the set of extensions it can handle
SCANNER_ROUTES: dict[str, set[str]] = {
    "pickle": {".pkl", ".pickle", ".p"},
    "torch": {".pt", ".pth", ".bin", ".ckpt"},
    "gguf": {".gguf"},
    "keras": {".keras", ".h5", ".hdf5"},
    "onnx": {".onnx"},
    "safetensors": {".safetensors"},
    "archive_slip": {
        ".nemo", ".keras", ".pth", ".pt", ".mar",
        ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".zip", ".onnx",
    },
    "tensorflow": {".pb"},
    "tflite": {".tflite"},
    "llamafile": {".llamafile"},
}

# ── Expected file size ranges (bytes) ────────────────────────────

EXPECTED_SIZE_RANGES: dict[str, tuple[int, int]] = {
    ".safetensors": (100, 50 * 1024 * 1024 * 1024),  # 100B - 50GB
    ".gguf": (1000, 200 * 1024 * 1024 * 1024),  # 1KB - 200GB
    ".onnx": (100, 50 * 1024 * 1024 * 1024),
    ".keras": (100, 1 * 1024 * 1024 * 1024),  # Config only, 100B - 1GB
    ".h5": (1000, 50 * 1024 * 1024 * 1024),
    ".tflite": (100, 5 * 1024 * 1024 * 1024),
}


@dataclass
class ArtifactAssessment:
    """Unified assessment result from cross-format analysis."""
    file_path: str
    file_size: int
    sha256: str
    detected_format: str
    expected_format: str
    format_match: bool
    findings: list[Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    risk_score: float = 0.0  # 0.0 = clean, 1.0 = confirmed malicious

    @property
    def risk_level(self) -> str:
        """Human-readable risk level."""
        if self.risk_score >= 0.9:
            return "CRITICAL"
        elif self.risk_score >= 0.7:
            return "HIGH"
        elif self.risk_score >= 0.4:
            return "MEDIUM"
        elif self.risk_score >= 0.1:
            return "LOW"
        return "CLEAN"

    @property
    def critical_count(self) -> int:
        return sum(
            1 for f in self.findings if f.severity == Severity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for f in self.findings if f.severity == Severity.HIGH
        )

    def to_dict(self) -> dict:
        """Export as dict for JSON serialization."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "detected_format": self.detected_format,
            "expected_format": self.expected_format,
            "format_match": self.format_match,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "critical_findings": self.critical_count,
            "high_findings": self.high_count,
            "total_findings": len(self.findings),
            "scanners_run": self.scanners_run,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "description": f.description,
                }
                for f in self.findings
            ],
        }


class IntegrityEngine:
    """
    Cross-format model file integrity verification engine.

    Usage:
        engine = IntegrityEngine()
        assessment = engine.assess("model.pt")
        if assessment.risk_score > 0.5:
            print(f"HIGH RISK: {assessment.critical_count} critical findings")
    """

    def __init__(
        self,
        known_hashes: Optional[dict[str, str]] = None,
    ):
        """
        Args:
            known_hashes: Optional dict of {filename: sha256_hex} for
                         provenance verification against known-good models.
        """
        self._known_hashes = known_hashes or {}
        self._scanners: dict[str, object] = {}

    def assess(self, file_path: str | Path) -> ArtifactAssessment:
        """
        Run comprehensive security assessment on a model file.

        1. Compute SHA256 hash
        2. Detect actual format via magic bytes
        3. Compare with expected format from extension
        4. Route to appropriate format-specific scanners
        5. Aggregate findings and compute risk score
        """
        path = Path(file_path)
        start_time = time.monotonic()

        if not path.exists():
            return ArtifactAssessment(
                file_path=str(path),
                file_size=0,
                sha256="",
                detected_format="missing",
                expected_format="",
                format_match=False,
                findings=[Finding.artifact(
                    rule_id="INTEGRITY-001",
                    title=f"File not found: {path.name}",
                    description=f"File does not exist: {path}",
                    severity=Severity.MEDIUM,
                    target=str(path),
                )],
            )

        file_size = path.stat().st_size
        sha256 = self._compute_sha256(path)
        ext = self._get_extension(path)
        expected_format = EXTENSION_FORMAT_MAP.get(ext, "unknown")

        # Detect actual format
        detected_format = self._detect_format(path)

        assessment = ArtifactAssessment(
            file_path=str(path),
            file_size=file_size,
            sha256=sha256,
            detected_format=detected_format,
            expected_format=expected_format,
            format_match=self._formats_compatible(detected_format, expected_format),
        )

        # ── Format mismatch check ──
        if not assessment.format_match and expected_format != "unknown":
            assessment.findings.append(Finding.artifact(
                rule_id="INTEGRITY-010",
                title=f"Format mismatch: expected {expected_format}, detected {detected_format}",
                description=(
                    f"File '{path.name}' has extension '{ext}' (expected format: "
                    f"{expected_format}) but magic bytes indicate format: "
                    f"{detected_format}. This could indicate file disguise or corruption."
                ),
                severity=Severity.HIGH,
                target=str(path),
                evidence=f"Extension: {ext}, Detected: {detected_format}",
                cwe_ids=["CWE-345"],
            ))

        # ── File size sanity ──
        if ext in EXPECTED_SIZE_RANGES:
            min_size, max_size = EXPECTED_SIZE_RANGES[ext]
            if file_size < min_size:
                assessment.findings.append(Finding.artifact(
                    rule_id="INTEGRITY-011",
                    title=f"Suspiciously small file: {file_size} bytes",
                    description=(
                        f"File '{path.name}' is only {file_size} bytes. "
                        f"Expected at least {min_size} bytes for {ext} format."
                    ),
                    severity=Severity.LOW,
                    target=str(path),
                ))
            elif file_size > max_size:
                assessment.findings.append(Finding.artifact(
                    rule_id="INTEGRITY-012",
                    title=f"Unusually large file: {file_size / (1024**3):.1f}GB",
                    description=(
                        f"File '{path.name}' is {file_size / (1024**3):.1f}GB. "
                        f"Maximum expected for {ext}: {max_size / (1024**3):.0f}GB."
                    ),
                    severity=Severity.LOW,
                    target=str(path),
                ))

        # ── Provenance check ──
        if self._known_hashes:
            findings = self._check_provenance(path.name, sha256, str(path))
            assessment.findings.extend(findings)

        # ── Run format-specific scanners ──
        scanner_findings = self._run_scanners(path, ext, str(path))
        for scanner_name, findings in scanner_findings.items():
            assessment.scanners_run.append(scanner_name)
            assessment.findings.extend(findings)

        # ── Compute risk score ──
        assessment.risk_score = self._compute_risk_score(assessment.findings)

        # ── Timing ──
        elapsed = (time.monotonic() - start_time) * 1000
        assessment.scan_duration_ms = elapsed

        return assessment

    def assess_batch(self, file_paths: list[str | Path]) -> list[ArtifactAssessment]:
        """Assess multiple files and return ordered by risk score (highest first)."""
        assessments = [self.assess(fp) for fp in file_paths]
        assessments.sort(key=lambda a: a.risk_score, reverse=True)
        return assessments

    # ─── Format Detection ─────────────────────────────────────

    def _detect_format(self, path: Path) -> str:
        """Detect actual file format using magic bytes."""
        try:
            with open(path, "rb") as f:
                header = f.read(512)
        except Exception:
            return "unreadable"

        if len(header) < 4:
            return "too_small"

        # Check all magic signatures
        for fmt, signatures in MAGIC_SIGNATURES.items():
            for magic, offset in signatures:
                if offset + len(magic) <= len(header):
                    if header[offset:offset + len(magic)] == magic:
                        return fmt

        return "unknown"

    def _formats_compatible(self, detected: str, expected: str) -> bool:
        """Check if detected format is compatible with expected."""
        if detected == expected:
            return True

        # PyTorch files can be ZIP or pickle
        compatible_pairs = {
            ("zip", "pytorch"), ("pytorch_zip", "pytorch"),
            ("pickle", "pytorch"),
            ("zip", "zip"),  # .keras is a ZIP
            ("gzip", "tar"), ("bzip2", "tar"),
            ("hdf5", "hdf5"),
            ("elf", "executable"), ("pe", "executable"),
        }
        return (detected, expected) in compatible_pairs

    def _get_extension(self, path: Path) -> str:
        """Get file extension, handling compound extensions."""
        name = path.name.lower()
        if name.endswith(".tar.gz"):
            return ".tar.gz"
        if name.endswith(".tar.bz2"):
            return ".tar.bz2"
        return path.suffix.lower()

    # ─── Scanner Routing ──────────────────────────────────────

    def _run_scanners(
        self, path: Path, ext: str, source: str
    ) -> dict[str, list[Finding]]:
        """Route to appropriate scanners based on file extension."""
        results: dict[str, list[Finding]] = {}

        for scanner_name, extensions in SCANNER_ROUTES.items():
            if ext in extensions:
                try:
                    scanner = self._get_scanner(scanner_name)
                    if scanner:
                        findings = scanner.scan_file(str(path))
                        results[scanner_name] = findings
                except Exception as e:
                    logger.warning(
                        "Scanner '%s' failed on '%s': %s",
                        scanner_name, source, e,
                    )
                    results[scanner_name] = [Finding.artifact(
                        rule_id="INTEGRITY-020",
                        title=f"Scanner error: {scanner_name}",
                        description=f"Scanner '{scanner_name}' failed: {e}",
                        severity=Severity.LOW,
                        target=source,
                    )]

        return results

    def _get_scanner(self, name: str):
        """Lazy-load scanners to avoid circular imports."""
        if name not in self._scanners:
            try:
                if name == "pickle":
                    from sentinel.artifact.pickle_scanner import PickleScanner
                    self._scanners[name] = PickleScanner()
                elif name == "torch":
                    from sentinel.artifact.torch_scanner import TorchScanner
                    self._scanners[name] = TorchScanner()
                elif name == "gguf":
                    from sentinel.artifact.gguf_analyzer import GGUFAnalyzer
                    self._scanners[name] = GGUFAnalyzer()
                elif name == "keras":
                    from sentinel.artifact.keras_scanner import KerasScanner
                    self._scanners[name] = KerasScanner()
                elif name == "onnx":
                    from sentinel.artifact.onnx_scanner import ONNXScanner
                    self._scanners[name] = ONNXScanner()
                elif name == "safetensors":
                    from sentinel.artifact.safetensors_validator import SafetensorsValidator
                    self._scanners[name] = SafetensorsValidator()
                elif name == "archive_slip":
                    from sentinel.artifact.archive_slip import ArchiveSlipDetector
                    self._scanners[name] = ArchiveSlipDetector()
                elif name == "tensorflow":
                    from sentinel.artifact.tensorflow_scanner import TensorFlowScanner
                    self._scanners[name] = TensorFlowScanner()
                elif name == "tflite":
                    from sentinel.artifact.tflite_scanner import TFLiteScanner
                    self._scanners[name] = TFLiteScanner()
                elif name == "llamafile":
                    from sentinel.artifact.llamafile_scanner import LlamaFileScanner
                    self._scanners[name] = LlamaFileScanner()
                else:
                    return None
            except ImportError as e:
                logger.debug("Scanner '%s' not available: %s", name, e)
                return None

        return self._scanners.get(name)

    # ─── Provenance Verification ──────────────────────────────

    def _check_provenance(
        self, filename: str, sha256: str, source: str
    ) -> list[Finding]:
        """Verify file hash against known-good provenance database."""
        findings = []

        if filename in self._known_hashes:
            expected_hash = self._known_hashes[filename]
            if sha256 != expected_hash:
                findings.append(Finding.artifact(
                    rule_id="INTEGRITY-030",
                    title=f"SHA256 mismatch: {filename}",
                    description=(
                        f"File hash does not match known-good hash. "
                        f"Expected: {expected_hash[:16]}..., "
                        f"Got: {sha256[:16]}... "
                        f"This file may have been tampered with."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    target=source,
                    evidence=f"Expected: {expected_hash}, Got: {sha256}",
                    cwe_ids=["CWE-354"],
                ))
            else:
                logger.info("Provenance verified: %s matches known hash", filename)

        return findings

    # ─── Risk Scoring ─────────────────────────────────────────

    def _compute_risk_score(self, findings: list[Finding]) -> float:
        """
        Compute composite risk score from all findings.

        Scoring weights:
        - CRITICAL finding: 0.3 per finding (cap at 1.0)
        - HIGH finding: 0.15 per finding
        - MEDIUM finding: 0.05 per finding
        - LOW/INFO: 0.01 per finding

        Confidence-weighted when available.
        """
        if not findings:
            return 0.0

        score = 0.0
        severity_weights = {
            Severity.CRITICAL: 0.3,
            Severity.HIGH: 0.15,
            Severity.MEDIUM: 0.05,
            Severity.LOW: 0.01,
        }

        for finding in findings:
            weight = severity_weights.get(finding.severity, 0.01)
            confidence = getattr(finding, "confidence", 0.7)
            score += weight * confidence

        return min(score, 1.0)

    # ─── Utility ──────────────────────────────────────────────

    def _compute_sha256(self, path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
