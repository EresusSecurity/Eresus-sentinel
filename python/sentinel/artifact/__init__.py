"""
 Artifact Scanner Module (20 format scanners + 3 analyzers)

Comprehensive model file security analysis covering:
- Pickle (.pkl, .pickle) — opcode disassembly
- PyTorch (.pt, .pth, .bin) — ZIP/pickle extraction
- Safetensors (.safetensors) — header/metadata validation
- GGUF (.gguf) — metadata prompt injection
- Keras (.keras, .h5, .hdf5) — Lambda layer, config injection
- ONNX (.onnx) — custom ops, external data
- XGBoost (.xgb, .ubj, .json, .model) — binary header, feature name injection
- LightGBM (.lgb, .txt) — text format injection, feature name injection
- Sklearn (.joblib) — joblib deserialization risk
- NumPy (.npy, .npz) — pickle dtype detection, header injection
- Archive Slip — ZipSlip/TarSlip in model archives
- HuggingFace — repo-level security audit
- TensorFlow SavedModel (.pb) — backdoor ops, function defs, assets
- TorchScript (.pt, .torchscript) — code analysis, pickle, custom ops
- TFLite/LiteRT (.tflite) — FlatBuffer validation, custom ops, tensor overflow
- TorchMobile (.ptl) — bytecode analysis, pickle, native lib detection
- LlamaFile (.llamafile) — executable envelope + embedded GGUF analysis
- Trojan Detector — weight distribution anomaly analysis
- Binary Tail Scanner — PE/ELF/Mach-O/shell detection in file tails
- CVE Detector — known ML/AI CVE pattern matching
"""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sentinel.finding import Finding, Severity

from ._pickle_ops import DangerousImport, PickleAnalysis
from .archive_slip import ArchiveSlipDetector
from .binary_tail_scanner import BinaryTailScanner
from .catboost_scanner import CatBoostScanner
from .coreml_scanner import CoreMLScanner
from .cve_detector import CVEDetector
from .flax_scanner import FlaxScanner
from .gguf_analyzer import GGUFAnalyzer
from .huggingface_scanner import HuggingFaceScanner
from .integrity_engine import IntegrityEngine
from .keras_scanner import KerasScanner
from .lightgbm_scanner import LightGBMScanner
from .llamafile_scanner import LlamaFileScanner
from .model_scanners import (
    AnomalyDetector,
    EntropyAnalyzer,
    H5Scanner,
    ModelScanResult,
    SavedModelScanner,
)
from .mxnet_scanner import MXNetScanner
from .nemo_scanner import NeMoScanner
from .numpy_scanner import NumpyScanner
from .oci_scanner import OCIScanner
from .onnx_scanner import ONNXScanner
from .openvino_scanner import OpenVINOScanner
from .paddle_scanner import PaddleScanner
from .pickle_scanner import PickleScanner
from .pmml_scanner import PMMLScanner
from .r_serialized_scanner import RSerializedScanner
from .safetensors_validator import SafetensorsValidator
from .sevenz_scanner import SevenZipScanner
from .skops_scanner import SkopsScanner
from .tensorflow_scanner import TensorFlowScanner
from .tflite_scanner import TFLiteScanner
from .torch_scanner import TorchScanner
from .torchmobile_scanner import TorchMobileScanner
from .torchscript_scanner import TorchScriptScanner
from .torchserve_scanner import ExecuTorchScanner, TensorRTScanner, Torch7Scanner, TorchServeScanner
from .trojan_detector import TrojanDetector
from .xgboost_scanner import XGBoostScanner
from .yaml_scanner import YamlScanner


@dataclass(frozen=True)
class ArtifactScanOptions:
    """Public options for deterministic artifact scanning."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    strict: bool = False
    cache: bool = False
    fail_closed: bool = False
    expected_sha256: str | None = None
    recursive: bool = True
    max_files: int = 10000


@dataclass(frozen=True)
class ArtifactScannerSpec:
    key: str
    extensions: tuple[str, ...]
    scanner_cls: type
    unsafe_serialization: bool = False


_SCAN_CACHE: dict[tuple[str, str, tuple], tuple[Finding, ...]] = {}


def _scanner_catalog() -> tuple[ArtifactScannerSpec, ...]:
    return (
        ArtifactScannerSpec("pickle", (".pkl", ".pickle", ".p", ".dill", ".dat", ".data", ".joblib"), PickleScanner, True),
        ArtifactScannerSpec("torch", (".pt", ".pth", ".bin", ".ckpt"), TorchScanner, True),
        ArtifactScannerSpec("safetensors", (".safetensors",), SafetensorsValidator),
        ArtifactScannerSpec("gguf", (".gguf",), GGUFAnalyzer),
        ArtifactScannerSpec("tensorflow", (".pb",), TensorFlowScanner),
        ArtifactScannerSpec("torchscript", (".torchscript", ".ptc"), TorchScriptScanner, True),
        ArtifactScannerSpec("tflite", (".tflite",), TFLiteScanner),
        ArtifactScannerSpec("torchmobile", (".ptl",), TorchMobileScanner, True),
        ArtifactScannerSpec("llamafile", (".llamafile",), LlamaFileScanner),
        ArtifactScannerSpec("onnx", (".onnx",), ONNXScanner),
        ArtifactScannerSpec("keras", (".keras", ".h5", ".hdf5"), KerasScanner, True),
        ArtifactScannerSpec("xgboost", (".xgb", ".ubj", ".model"), XGBoostScanner),
        ArtifactScannerSpec("numpy", (".npy", ".npz"), NumpyScanner, True),
        ArtifactScannerSpec("archive", (".zip", ".tar", ".tar.gz", ".tgz"), ArchiveSlipDetector),
        ArtifactScannerSpec("7z", (".7z",), SevenZipScanner),
        ArtifactScannerSpec("yaml", (".yaml", ".yml"), YamlScanner),
        ArtifactScannerSpec("catboost", (".cbm",), CatBoostScanner),
        ArtifactScannerSpec("coreml", (".mlmodel", ".mlpackage"), CoreMLScanner),
        ArtifactScannerSpec("flax", (".msgpack", ".orbax", ".flax"), FlaxScanner),
        ArtifactScannerSpec("lightgbm", (".lgb", ".lightgbm"), LightGBMScanner),
        ArtifactScannerSpec("mxnet", (".params",), MXNetScanner),
        ArtifactScannerSpec("nemo", (".nemo",), NeMoScanner, True),
        ArtifactScannerSpec("openvino", (".xml",), OpenVINOScanner),
        ArtifactScannerSpec("paddle", (".pdmodel", ".pdiparams", ".pdparams"), PaddleScanner),
        ArtifactScannerSpec("pmml", (".pmml",), PMMLScanner),
        ArtifactScannerSpec("r-serialized", (".rds", ".rda", ".rdata"), RSerializedScanner, True),
        ArtifactScannerSpec("skops", (".skops",), SkopsScanner),
        ArtifactScannerSpec("torchserve", (".mar",), TorchServeScanner, True),
        ArtifactScannerSpec("torch7", (".t7", ".th"), Torch7Scanner, True),
        ArtifactScannerSpec("executorch", (".pte",), ExecuTorchScanner),
        ArtifactScannerSpec("tensorrt", (".engine", ".plan", ".trt"), TensorRTScanner),
        ArtifactScannerSpec("oci", (".oci",), OCIScanner),
    )


def _normalize_tokens(values: str | Iterable[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    return tuple(str(value).lower().strip() for value in values if str(value).strip())


def _coerce_options(
    options: ArtifactScanOptions | None,
    *,
    include: str | Iterable[str] | None = None,
    exclude: str | Iterable[str] | None = None,
    strict: bool | None = None,
    cache: bool | None = None,
    fail_closed: bool | None = None,
    expected_sha256: str | None = None,
) -> ArtifactScanOptions:
    base = options or ArtifactScanOptions()
    return ArtifactScanOptions(
        include=_normalize_tokens(include) or _normalize_tokens(base.include),
        exclude=_normalize_tokens(exclude) or _normalize_tokens(base.exclude),
        strict=base.strict if strict is None else strict,
        cache=base.cache if cache is None else cache,
        fail_closed=base.fail_closed if fail_closed is None else fail_closed,
        expected_sha256=expected_sha256 if expected_sha256 is not None else base.expected_sha256,
        recursive=base.recursive,
        max_files=base.max_files,
    )


def _matches_extension(path: Path, extensions: tuple[str, ...]) -> str:
    name = path.name.lower()
    for extension in sorted(extensions, key=len, reverse=True):
        if name.endswith(extension):
            return extension
    return ""


def _find_scanner_spec(path: Path) -> ArtifactScannerSpec | None:
    for spec in _scanner_catalog():
        if _matches_extension(path, spec.extensions):
            return spec
    return None


def _scanner_selected(spec: ArtifactScannerSpec, options: ArtifactScanOptions) -> bool:
    tokens = {spec.key, spec.scanner_cls.__name__.lower(), *spec.extensions}
    include = set(options.include)
    exclude = set(options.exclude)
    if include and tokens.isdisjoint(include):
        return False
    return tokens.isdisjoint(exclude)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_findings(path: Path, actual_sha256: str, options: ArtifactScanOptions) -> list[Finding]:
    expected = (options.expected_sha256 or "").lower().strip()
    if not expected or expected == actual_sha256:
        return []
    return [
        Finding.artifact(
            rule_id="ARTIFACT-092",
            title="Artifact content hash mismatch",
            description="The artifact digest does not match the expected SHA-256 value.",
            severity=Severity.HIGH,
            target=str(path),
            evidence=f"expected={expected} actual={actual_sha256}",
            confidence=1.0,
            remediation="Re-download the artifact from the trusted source and verify provenance before loading.",
        )
    ]


def _format_risk_findings(path: Path, spec: ArtifactScannerSpec) -> list[Finding]:
    if not spec.unsafe_serialization:
        return []
    extension = _matches_extension(path, spec.extensions) or path.suffix.lower()
    return [
        Finding.artifact(
            rule_id="ARTIFACT-090",
            title="Unsafe model serialization format",
            description=(
                "This artifact uses a format that may embed executable object graphs "
                "or loader-time behavior. Scan findings should be reviewed before loading."
            ),
            severity=Severity.HIGH,
            target=str(path),
            evidence=f"scanner={spec.key} extension={extension}",
            confidence=0.9,
            remediation="Prefer code-free tensor formats for distribution, and load this artifact only in a sandbox.",
        )
    ]


def _unsupported_format_finding(path: Path, options: ArtifactScanOptions) -> list[Finding]:
    if not (options.strict or options.fail_closed):
        return []
    severity = Severity.HIGH if options.fail_closed else Severity.MEDIUM
    return [
        Finding.artifact(
            rule_id="ARTIFACT-091",
            title="Unsupported artifact format",
            description="No artifact scanner is registered for this file type.",
            severity=severity,
            target=str(path),
            evidence=f"filename={path.name}",
            confidence=0.85,
            remediation="Add an explicit scanner include/exclude decision or convert the artifact to a supported format.",
        )
    ]


def _coerce_findings(result) -> list[Finding]:
    """Normalize scanner return types to a plain list of Finding objects."""
    if result is None:
        return []
    if isinstance(result, list):
        return result
    findings = getattr(result, "findings", None)
    if isinstance(findings, list):
        return findings
    return []


def _scan_error(path: Path, exc: Exception) -> list[Finding]:
    return [
        Finding.artifact(
            rule_id="ARTIFACT-SCAN-ERROR",
            title="Artifact scanner failed",
            description=f"{type(exc).__name__}: {exc}",
            severity=Severity.MEDIUM,
            target=str(path),
            confidence=0.8,
        )
    ]


def scan_file(
    filepath: str | Path,
    options: ArtifactScanOptions | None = None,
    *,
    include: str | Iterable[str] | None = None,
    exclude: str | Iterable[str] | None = None,
    strict: bool | None = None,
    cache: bool | None = None,
    fail_closed: bool | None = None,
    expected_sha256: str | None = None,
) -> list[Finding]:
    """Scan a model artifact file without deserializing it.

    This is the stable public artifact-scanner API used by benchmark scripts,
    integrations, and parity checks. It intentionally mirrors the CLI
    dispatcher while remaining importable from ``sentinel.artifact``.
    """
    from sentinel.scan_safety import FileTooLargeError, check_file_size

    resolved_options = _coerce_options(
        options,
        include=include,
        exclude=exclude,
        strict=strict,
        cache=cache,
        fail_closed=fail_closed,
        expected_sha256=expected_sha256,
    )
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return []

    try:
        check_file_size(path)
    except FileTooLargeError as exc:
        return [
            Finding.artifact(
                rule_id="SCAN-SIZE",
                title="File too large to scan safely",
                description=str(exc),
                severity=Severity.HIGH,
                target=str(path),
                cwe_ids=["CWE-400"],
            )
        ]

    actual_sha256 = _sha256_file(path) if (resolved_options.cache or resolved_options.expected_sha256) else ""
    option_key = (
        resolved_options.include,
        resolved_options.exclude,
        resolved_options.strict,
        resolved_options.fail_closed,
        resolved_options.expected_sha256,
    )
    if resolved_options.cache:
        cache_key = (actual_sha256, str(path.resolve()), option_key)
        if cache_key in _SCAN_CACHE:
            return list(_SCAN_CACHE[cache_key])

    findings = _hash_findings(path, actual_sha256, resolved_options) if actual_sha256 else []
    spec = _find_scanner_spec(path)
    if spec is None:
        findings.extend(_unsupported_format_finding(path, resolved_options))
    elif _scanner_selected(spec, resolved_options):
        findings.extend(_format_risk_findings(path, spec))
        try:
            findings.extend(_coerce_findings(spec.scanner_cls().scan_file(str(path))))
        except Exception as exc:
            if resolved_options.fail_closed:
                findings.extend(_scan_error(path, exc))
            else:
                return findings + _scan_error(path, exc)

    if resolved_options.cache:
        _SCAN_CACHE[(actual_sha256, str(path.resolve()), option_key)] = tuple(findings)
    return findings


def scan_directory(
    directory: str | Path,
    options: ArtifactScanOptions | None = None,
    *,
    include: str | Iterable[str] | None = None,
    exclude: str | Iterable[str] | None = None,
    strict: bool | None = None,
    cache: bool | None = None,
    fail_closed: bool | None = None,
    expected_sha256: str | None = None,
) -> list[Finding]:
    """Scan every file under a directory with the public artifact API."""
    resolved_options = _coerce_options(
        options,
        include=include,
        exclude=exclude,
        strict=strict,
        cache=cache,
        fail_closed=fail_closed,
        expected_sha256=expected_sha256,
    )
    root = Path(directory)
    if not root.exists() or not root.is_dir():
        return []

    iterator = root.rglob("*") if resolved_options.recursive else root.iterdir()
    findings: list[Finding] = []
    scanned = 0
    for path in iterator:
        if not path.is_file():
            continue
        scanned += 1
        if scanned > resolved_options.max_files:
            findings.append(
                Finding.artifact(
                    rule_id="ARTIFACT-093",
                    title="Artifact directory scan budget exceeded",
                    description="The artifact directory contains more files than the configured scan budget.",
                    severity=Severity.MEDIUM,
                    target=str(root),
                    evidence=f"max_files={resolved_options.max_files}",
                    confidence=0.9,
                )
            )
            break
        findings.extend(scan_file(path, resolved_options))
    return findings


__all__ = [
    "scan_file",
    "scan_directory",
    "ArtifactScanOptions",
    "ArtifactScannerSpec",
    "PickleAnalysis",
    "DangerousImport",
    "PickleScanner",
    "TorchScanner",
    "SafetensorsValidator",
    "GGUFAnalyzer",
    "KerasScanner",
    "ModelScanResult",
    "H5Scanner",
    "SavedModelScanner",
    "AnomalyDetector",
    "EntropyAnalyzer",
    "ONNXScanner",
    "ArchiveSlipDetector",
    "IntegrityEngine",
    "HuggingFaceScanner",
    "TensorFlowScanner",
    "TorchScriptScanner",
    "TFLiteScanner",
    "TorchMobileScanner",
    "LlamaFileScanner",
    "XGBoostScanner",
    "NumpyScanner",
    "TrojanDetector",
    "BinaryTailScanner",
    "CVEDetector",
    "CatBoostScanner",
    "CoreMLScanner",
    "FlaxScanner",
    "LightGBMScanner",
    "MXNetScanner",
    "NeMoScanner",
    "OpenVINOScanner",
    "PaddleScanner",
    "PMMLScanner",
    "RSerializedScanner",
    "SkopsScanner",
    "TorchServeScanner",
    "Torch7Scanner",
    "ExecuTorchScanner",
    "TensorRTScanner",
    "OCIScanner",
    "SevenZipScanner",
    "YamlScanner",
]
