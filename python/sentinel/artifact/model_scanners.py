"""Model file scanners — H5 (HDF5), Keras, TensorFlow SavedModel.

Extends sentinel's artifact scanning to cover model formats
beyond pickle/safetensors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class ModelScanResult:
    path: str = ""
    format: str = ""
    safe: bool = True
    issues: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class H5ModelScanner:
    """Scans HDF5 (.h5) model files for unsafe operations.

    Note: The canonical HDF5 scanner is ``sentinel.artifact.h5_scanner.H5Scanner``.
    This class is kept for backward-compatible ``ModelScanResult`` callers only
    and intentionally omits ``scan_file`` so the plugin auto-discovery in
    ``_plugins.py`` does **not** register it (avoiding key collision with the
    canonical scanner).
    """

    HDF5_MAGIC = b'\x89HDF\r\n\x1a\n'
    DANGEROUS_ATTRS = ["custom_objects", "lambda", "exec", "eval", "__import__"]

    def scan(self, path: str) -> ModelScanResult:
        result = ModelScanResult(path=path, format="h5")
        p = Path(path)
        if not p.exists():
            result.issues.append({"severity": "error", "message": "File not found"})
            result.safe = False
            return result

        with open(path, "rb") as f:
            magic = f.read(8)
            if magic != self.HDF5_MAGIC:
                result.issues.append({"severity": "error", "message": "Not a valid HDF5 file"})
                result.safe = False
                return result

        try:
            import h5py
            with h5py.File(path, "r") as f:
                self._scan_group(f, result)
                if "model_config" in f.attrs:
                    config = f.attrs["model_config"]
                    if isinstance(config, bytes):
                        config = config.decode("utf-8", errors="replace")
                    self._check_config(str(config), result)
        except ImportError:
            with open(path, "rb") as f:
                content = f.read()
                self._scan_bytes(content, result)

        return result

    def _scan_group(self, group: Any, result: ModelScanResult) -> None:
        for attr_name in group.attrs:
            val = str(group.attrs[attr_name])
            for danger in self.DANGEROUS_ATTRS:
                if danger in val.lower():
                    result.safe = False
                    result.issues.append(
                        {
                            "severity": "critical",
                            "message": f"Dangerous attribute '{danger}' in {attr_name}",
                            "location": group.name,
                        }
                    )

    def _check_config(self, config: str, result: ModelScanResult) -> None:
        config_lower = config.lower()
        if "lambda" in config_lower:
            result.safe = False
            result.issues.append(
                {
                    "severity": "critical",
                    "message": "Lambda layer detected in model config",
                }
            )
        if "custom_objects" in config_lower:
            result.issues.append(
                {
                    "severity": "warning",
                    "message": "Custom objects in model config — verify safety",
                }
            )

    def _scan_bytes(self, content: bytes, result: ModelScanResult) -> None:
        dangerous_patterns = [
            b"lambda",
            b"exec(",
            b"eval(",
            b"__import__",
            b"os.system",
            b"subprocess",
        ]
        for pat in dangerous_patterns:
            if pat in content:
                result.safe = False
                result.issues.append(
                    {
                        "severity": "critical",
                        "message": f"Dangerous pattern '{pat.decode()}' found in file bytes",
                    }
                )


class KerasLayerScanner:
    """Scans Keras model files (.keras, .h5) for unsafe layers and configs."""

    UNSAFE_LAYERS = ["Lambda", "custom_layer"]
    UNSAFE_ACTIVATIONS = ["lambda x:"]

    def scan_file(self, filepath: str) -> list[Finding]:
        """Artifact scanner API compatibility wrapper.

        The canonical Keras scanner is deeper and YAML-rule integrated, so this
        compatibility layer delegates to it and keeps ``scan()`` for legacy
        modelaudit-style callers.
        """
        from sentinel.artifact.keras_scanner import KerasScanner as NativeKerasScanner

        findings = NativeKerasScanner().scan_file(filepath)
        if findings:
            return findings
        return _result_to_findings(self.scan(filepath), "ARTIFACT-KERAS")

    def scan(self, path: str) -> ModelScanResult:
        result = ModelScanResult(path=path, format="keras")
        p = Path(path)
        if not p.exists():
            result.issues.append({"severity": "error", "message": "File not found"})
            result.safe = False
            return result

        if p.suffix == ".keras":
            self._scan_keras_v3(path, result)
        else:
            scanner = H5ModelScanner()
            h5_result = scanner.scan(path)
            result.issues.extend(h5_result.issues)
            result.safe = h5_result.safe

        return result

    def _scan_keras_v3(self, path: str, result: ModelScanResult) -> None:
        import zipfile
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".json"):
                        content = zf.read(name).decode("utf-8", errors="replace")
                        content_lower = content.lower()
                        for unsafe in self.UNSAFE_LAYERS:
                            if unsafe.lower() in content_lower:
                                result.safe = False
                                result.issues.append(
                                    {
                                        "severity": "critical",
                                        "message": f"Unsafe layer '{unsafe}' in {name}",
                                    }
                                )
                        if "lambda" in content_lower:
                            result.safe = False
                            result.issues.append(
                                {
                                    "severity": "critical",
                                    "message": f"Lambda detected in {name}",
                                }
                            )
        except zipfile.BadZipFile:
            result.issues.append(
                {"severity": "error", "message": "Invalid .keras file (not a zip)"}
            )
            result.safe = False


class SavedModelScanner:
    """Scans TensorFlow SavedModel directories."""

    def scan_file(self, filepath: str) -> list[Finding]:
        """Artifact scanner API compatibility wrapper."""
        from sentinel.artifact.tensorflow_scanner import TensorFlowScanner

        findings = TensorFlowScanner().scan_file(filepath)
        if findings:
            return findings
        return _result_to_findings(self.scan(filepath), "ARTIFACT-SAVEDMODEL")

    def scan(self, path: str) -> ModelScanResult:
        result = ModelScanResult(path=path, format="saved_model")
        p = Path(path)
        if not p.is_dir():
            result.issues.append({"severity": "error", "message": "Not a directory"})
            result.safe = False
            return result

        saved_model_pb = p / "saved_model.pb"
        if not saved_model_pb.exists():
            result.issues.append({"severity": "error", "message": "saved_model.pb not found"})
            result.safe = False
            return result

        content = saved_model_pb.read_bytes()
        dangerous_ops = [b"PyFunc", b"ReadFile", b"WriteFile", b"ShellCommand", b"subprocess"]
        for op in dangerous_ops:
            if op in content:
                result.safe = False
                result.issues.append(
                    {
                        "severity": "critical",
                        "message": f"Dangerous TF op '{op.decode()}' in saved_model.pb",
                    }
                )

        variables_dir = p / "variables"
        if variables_dir.exists():
            for _var_file in variables_dir.glob("*.index"):
                result.metadata["has_variables"] = True
            for var_file in variables_dir.glob("*.data-*"):
                size_mb = var_file.stat().st_size / (1024 * 1024)
                if size_mb > 5000:
                    result.issues.append(
                        {
                            "severity": "info",
                            "message": f"Large variable file: {size_mb:.0f}MB",
                        }
                    )

        assets_dir = p / "assets"
        if assets_dir.exists():
            for asset in assets_dir.rglob("*"):
                if asset.suffix in (".py", ".sh", ".bat", ".ps1"):
                    result.safe = False
                    result.issues.append(
                        {
                            "severity": "critical",
                            "message": f"Executable asset found: {asset.name}",
                        }
                    )

        return result


class AnomalyDetector:
    """Detects anomalies in model weight distributions."""

    def analyze(self, weights: list[float]) -> dict:
        if not weights:
            return {"anomalous": False, "reason": "empty"}
        import math
        mean = sum(weights) / len(weights)
        variance = sum((w - mean) ** 2 for w in weights) / len(weights)
        std = math.sqrt(variance) if variance > 0 else 0
        max_val = max(abs(w) for w in weights)
        anomalous = max_val > mean + 10 * std if std > 0 else False
        return {
            "anomalous": anomalous,
            "mean": mean,
            "std": std,
            "max_abs": max_val,
            "count": len(weights),
        }


class EntropyAnalyzer:
    """Analyzes entropy of model file sections to detect hidden payloads."""

    def analyze(self, data: bytes, block_size: int = 4096) -> list[dict]:
        blocks: list[dict] = []
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            entropy = self._shannon_entropy(block)
            blocks.append(
                {
                    "offset": i,
                    "size": len(block),
                    "entropy": entropy,
                    "suspicious": entropy > 7.5,
                }
            )
        return blocks

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq: dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


def _result_to_findings(result: ModelScanResult, rule_prefix: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, issue in enumerate(result.issues, 1):
        severity = _issue_severity(str(issue.get("severity", "medium")))
        findings.append(
            Finding.artifact(
                rule_id=f"{rule_prefix}-{index:03d}",
                title=issue.get("title") or "Model artifact security issue",
                description=str(issue.get("message", "Model scanner reported an issue.")),
                severity=severity,
                target=result.path,
                evidence=str(issue.get("location", issue.get("evidence", ""))),
                confidence=0.85,
            )
        )
    return findings


def _issue_severity(value: str) -> Severity:
    normalized = value.upper()
    if normalized == "ERROR":
        return Severity.HIGH
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }.get(normalized, Severity.MEDIUM)


def H5Scanner():  # noqa: N802
    """Backward-compatible factory — returns the canonical H5Scanner."""
    from sentinel.artifact.h5_scanner import H5Scanner as _CanonicalH5Scanner
    return _CanonicalH5Scanner()


__all__ = [
    "ModelScanResult",
    "H5ModelScanner",
    "H5Scanner",
    "KerasLayerScanner",
    "SavedModelScanner",
    "AnomalyDetector",
    "EntropyAnalyzer",
]
