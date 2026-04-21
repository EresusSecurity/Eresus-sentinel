"""
Eresus Sentinel — XGBoost / LightGBM / Sklearn Model Scanner.

Scans tree-based ML model files for:
  - Pickle deserialization risks (XGBoost .pkl, Sklearn .pkl/.joblib)
  - XGBoost native format tampering (.xgb, .ubj, .json, .model)
  - LightGBM text format injection (.lgb, .txt model files)
  - Joblib serialization risks (.joblib)
  - Suspicious metadata and feature name injection

Supported formats:
  - XGBoost: .xgb, .ubj (Universal Binary JSON), .json, .model
  - LightGBM: .lgb, .txt (text model format)
  - Sklearn: .joblib (via joblib serialization)
  - All: .pkl/.pickle fallback (deferred to PickleScanner)
"""

from __future__ import annotations

import json
import logging
import struct
from pathlib import Path
from typing import List

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── XGBoost binary magic bytes ────────────────────────────────────
# XGBoost native binary format header (binf)
XGBOOST_BINARY_MAGIC = b"binf"
# Universal Binary JSON marker
UBJ_MARKERS = {b"{", b"["}

# ── Suspicious patterns in any text-based model ───────────────────
SUSPICIOUS_TEXT_PATTERNS = [
    # Code execution
    "__import__", "os.system", "subprocess", "eval(", "exec(",
    "compile(", "marshal.loads", "marshal.load",
    # Shell commands
    "/bin/sh", "/bin/bash", "curl ", "wget ", "nc ",
    "python -c", "python3 -c", "bash -i",
    # Network
    "socket.socket", "connect(", "reverse", "shell",
    # Encoding bypass
    "base64.b64decode", "codecs.decode",
    # File operations
    "open(", "write(", "read(",
    # Script injection in feature names
    "<script", "javascript:", "onerror=",
]

# Known XGBoost model JSON keys
XGB_REQUIRED_KEYS = {"learner", "version"}
XGBOOST_LEARNER_KEYS = {"learner_model_param", "gradient_booster", "objective"}

# LightGBM header markers
LGBM_HEADER_MARKERS = [
    "tree", "version=", "num_class=", "num_tree_per_iteration=",
    "label_index=", "max_feature_idx=",
]


class XGBoostScanner:
    """Scan XGBoost, LightGBM, and Sklearn model files for security risks."""

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a tree-based model file."""
        p = Path(path)
        suffix = p.suffix.lower()
        stem = p.stem.lower()

        if suffix in (".xgb", ".model"):
            return self._scan_xgboost_binary(p)
        elif suffix == ".ubj":
            return self._scan_xgboost_ubj(p)
        elif suffix == ".json" and ("xgb" in stem or "boost" in stem):
            return self._scan_xgboost_json(p)
        elif suffix == ".lgb" or (suffix == ".txt" and ("lgb" in stem or "lightgbm" in stem)):
            return self._scan_lightgbm_text(p)
        elif suffix == ".joblib":
            return self._scan_joblib(p)
        return []

    # ─── XGBoost binary (.xgb, .model) ────────────────────────

    def _scan_xgboost_binary(self, path: Path) -> List[Finding]:
        """Scan XGBoost native binary format."""
        findings: List[Finding] = []
        source = str(path)

        try:
            with open(path, "rb") as f:
                header = f.read(4)

                if header != XGBOOST_BINARY_MAGIC:
                    findings.append(Finding.artifact(
                        rule_id="XGBT-001",
                        title="Invalid XGBoost binary header",
                        description=(
                            f"File '{path.name}' does not start with XGBoost binary magic "
                            f"'binf'. Got: {header!r}. File may be corrupted, a different "
                            f"format in disguise, or intentionally tampered."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"Header bytes: {header.hex()}",
                    ))
                    return findings

                # Read file size for sanity
                file_size = path.stat().st_size

                # Check for embedded executable code
                f.seek(0)
                content = f.read(min(file_size, 10 * 1024 * 1024))  # Cap at 10MB

                findings.extend(self._scan_bytes_for_code(content, source))

                # Validate structure
                if file_size < 32:
                    findings.append(Finding.artifact(
                        rule_id="XGBT-002",
                        title="XGBoost file too small",
                        description=(
                            f"File is only {file_size} bytes. A valid XGBoost model "
                            f"should be significantly larger."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                    ))

        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="XGBT-099",
                title="XGBoost scan error",
                description=f"Failed to scan XGBoost binary: {e}",
                severity=Severity.LOW,
                target=source,
                evidence=str(e),
            ))

        return findings

    # ─── XGBoost UBJ (.ubj) ───────────────────────────────────

    def _scan_xgboost_ubj(self, path: Path) -> List[Finding]:
        """Scan XGBoost Universal Binary JSON models."""
        findings: List[Finding] = []
        source = str(path)

        try:
            with open(path, "rb") as f:
                marker = f.read(1)
                if marker not in UBJ_MARKERS:
                    findings.append(Finding.artifact(
                        rule_id="XGBT-010",
                        title="Invalid UBJ format marker",
                        description=(
                            f"File does not start with a valid UBJ container marker. "
                            f"Expected '{{' or '[', got: {marker!r}."
                        ),
                        severity=Severity.MEDIUM,
                        target=source,
                    ))

                f.seek(0)
                content = f.read(min(path.stat().st_size, 10 * 1024 * 1024))
                findings.extend(self._scan_bytes_for_code(content, source))

        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="XGBT-099",
                title="XGBoost UBJ scan error",
                description=f"Failed to scan UBJ file: {e}",
                severity=Severity.LOW,
                target=source,
            ))

        return findings

    # ─── XGBoost JSON (.json) ─────────────────────────────────

    def _scan_xgboost_json(self, path: Path) -> List[Finding]:
        """Scan XGBoost JSON model format for injection and tampering."""
        findings: List[Finding] = []
        source = str(path)

        try:
            text = path.read_text(encoding="utf-8", errors="replace")

            # Size limit
            if len(text) > 500 * 1024 * 1024:
                findings.append(Finding.artifact(
                    rule_id="XGBT-020",
                    title="Oversized XGBoost JSON model",
                    description="Model JSON exceeds 500MB — possible DoS vector.",
                    severity=Severity.MEDIUM,
                    target=source,
                ))
                return findings

            data = json.loads(text)

            # Validate expected structure
            if isinstance(data, dict):
                if not XGBOOST_LEARNER_KEYS.intersection(data.get("learner", {}).keys()):
                    if "learner" not in data:
                        findings.append(Finding.artifact(
                            rule_id="XGBT-021",
                            title="Non-standard XGBoost JSON structure",
                            description=(
                                "JSON model lacks expected 'learner' key. "
                                "This may not be a legitimate XGBoost model."
                            ),
                            severity=Severity.MEDIUM,
                            target=source,
                            evidence=f"Top-level keys: {list(data.keys())[:10]}",
                        ))

                # Check feature names for injection
                learner = data.get("learner", {})
                feature_names = learner.get("feature_names", [])
                if isinstance(feature_names, list):
                    for i, fname in enumerate(feature_names):
                        if isinstance(fname, str):
                            for pattern in SUSPICIOUS_TEXT_PATTERNS:
                                if pattern in fname:
                                    findings.append(Finding.artifact(
                                        rule_id="XGBT-022",
                                        title=f"Feature name injection: {pattern}",
                                        description=(
                                            f"Feature name at index {i} contains suspicious "
                                            f"pattern '{pattern}'. Feature names can be used "
                                            f"as injection vectors when displayed in UIs or "
                                            f"logged without sanitization."
                                        ),
                                        severity=Severity.HIGH,
                                        target=source,
                                        evidence=f"Feature[{i}]: {fname[:200]}",
                                        cwe_ids=["CWE-79"],
                                    ))
                                    break

            # Scan full text for embedded code
            findings.extend(self._scan_text_for_code(text, source, "XGBT"))

        except json.JSONDecodeError as e:
            findings.append(Finding.artifact(
                rule_id="XGBT-023",
                title="Invalid XGBoost JSON",
                description=f"Failed to parse model JSON: {e}",
                severity=Severity.MEDIUM,
                target=source,
            ))
        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="XGBT-099",
                title="XGBoost JSON scan error",
                description=f"Failed to scan XGBoost JSON: {e}",
                severity=Severity.LOW,
                target=source,
            ))

        return findings

    # ─── LightGBM text (.lgb, .txt) ───────────────────────────

    def _scan_lightgbm_text(self, path: Path) -> List[Finding]:
        """Scan LightGBM text model format for injection and tampering."""
        findings: List[Finding] = []
        source = str(path)

        try:
            text = path.read_text(encoding="utf-8", errors="replace")

            # Validate LightGBM header
            first_lines = text[:2000].lower()
            header_matches = sum(1 for m in LGBM_HEADER_MARKERS if m in first_lines)
            if header_matches < 2:
                findings.append(Finding.artifact(
                    rule_id="LGBM-001",
                    title="Non-standard LightGBM model header",
                    description=(
                        f"File lacks expected LightGBM header markers. "
                        f"Found {header_matches}/{len(LGBM_HEADER_MARKERS)} expected markers. "
                        f"This may not be a legitimate LightGBM model."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                ))

            # Check feature names in LightGBM format
            for line in text.split("\n"):
                stripped = line.strip()
                if stripped.startswith("feature_names="):
                    feature_str = stripped[len("feature_names="):]
                    features = feature_str.split(" ")
                    for i, fname in enumerate(features):
                        for pattern in SUSPICIOUS_TEXT_PATTERNS:
                            if pattern in fname:
                                findings.append(Finding.artifact(
                                    rule_id="LGBM-002",
                                    title=f"Feature name injection in LightGBM: {pattern}",
                                    description=(
                                        f"Feature '{fname[:100]}' contains suspicious pattern "
                                        f"'{pattern}'. Feature names are rendered in explanations "
                                        f"and dashboards — injection here can lead to XSS or "
                                        f"log poisoning."
                                    ),
                                    severity=Severity.HIGH,
                                    target=source,
                                    evidence=f"feature[{i}]: {fname[:200]}",
                                    cwe_ids=["CWE-79"],
                                ))
                                break
                    break

            # Scan full text for embedded code
            findings.extend(self._scan_text_for_code(text, source, "LGBM"))

        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="LGBM-099",
                title="LightGBM scan error",
                description=f"Failed to scan LightGBM model: {e}",
                severity=Severity.LOW,
                target=source,
            ))

        return findings

    # ─── Joblib (.joblib) — Sklearn ───────────────────────────

    def _scan_joblib(self, path: Path) -> List[Finding]:
        """Scan Sklearn joblib files for deserialization risks."""
        findings: List[Finding] = []
        source = str(path)

        # Joblib uses pickle internally — always flag as risk
        findings.append(Finding.artifact(
            rule_id="SKLN-001",
            title="Joblib/Pickle deserialization risk",
            description=(
                "Joblib files use Python's pickle protocol internally and can execute "
                "arbitrary code on load. joblib.load() is equivalent to pickle.load() "
                "from a security perspective. Never load joblib files from untrusted sources."
            ),
            severity=Severity.HIGH,
            target=source,
            cwe_ids=["CWE-502"],
            remediation=(
                "Convert to ONNX format using sklearn-onnx or export model parameters "
                "as JSON/safetensors. Alternatively, use skops.io for safer serialization."
            ),
        ))

        # Joblib uses pickle internally — run deep pickle opcode analysis
        try:
            from .pickle_scanner import PickleScanner
            pickle_findings = PickleScanner().scan_file(path)
            findings.extend(pickle_findings)
        except Exception as e:
            logger.debug("Joblib pickle deep scan error: %s", e)

        try:
            with open(path, "rb") as f:
                content = f.read(min(path.stat().st_size, 10 * 1024 * 1024))
                findings.extend(self._scan_bytes_for_code(content, source))
        except Exception as e:
            logger.debug("Joblib scan error: %s", e)

        return findings

    # ─── Common helpers ───────────────────────────────────────

    def _scan_bytes_for_code(self, content: bytes, source: str) -> List[Finding]:
        """Scan raw bytes for suspicious code signatures."""
        findings = []
        text = content.decode("utf-8", errors="replace")

        # Check for executable signatures
        dangerous_byte_patterns = [
            (b"__reduce__", "Pickle __reduce__ (arbitrary code execution)"),
            (b"__import__", "Python __import__ call"),
            (b"os.system", "os.system call"),
            (b"subprocess", "subprocess module reference"),
            (b"eval(", "eval() call"),
            (b"exec(", "exec() call"),
            (b"marshal.loads", "marshal.loads (bytecode execution)"),
            (b"/bin/sh", "Shell path reference"),
            (b"socket.socket", "Socket creation"),
        ]

        for pattern, desc in dangerous_byte_patterns:
            if pattern in content:
                findings.append(Finding.artifact(
                    rule_id="MLMOD-010",
                    title=f"Embedded code detected: {desc}",
                    description=(
                        f"Binary model file contains '{pattern.decode()}' which "
                        f"indicates potential code execution during model loading."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"Pattern: {desc}",
                    cwe_ids=["CWE-502"],
                ))

        return findings

    def _scan_text_for_code(
        self, text: str, source: str, prefix: str
    ) -> List[Finding]:
        """Scan text content for suspicious code patterns."""
        findings = []

        for pattern in SUSPICIOUS_TEXT_PATTERNS:
            if pattern in text:
                findings.append(Finding.artifact(
                    rule_id=f"{prefix}-050",
                    title=f"Suspicious content in model file: {pattern}",
                    description=(
                        f"Model file contains suspicious pattern '{pattern}'. "
                        f"This could indicate tampering or embedded code."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"Pattern: {pattern}",
                    cwe_ids=["CWE-94"],
                ))
                break  # One finding per file for text patterns

        return findings
