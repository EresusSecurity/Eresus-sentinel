"""
Format detection middleware — auto-detect model format and route to scanner.

Uses file extension + magic bytes to identify the format, then dispatches
to the appropriate scanner.  Provides a single entry point for scanning
any supported model file.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding

_log = logging.getLogger("sentinel.artifact.format_middleware")


# Magic bytes → format name
_MAGIC_TABLE: list[tuple[bytes, int, str]] = [
    (b"\x89HDF\r\n\x1a\n", 0, "hdf5"),
    (b"GGUF", 0, "gguf"),
    (b"PK\x03\x04", 0, "zip"),    # ZIP (PyTorch, Keras, etc.)
    (b"\x80\x02", 0, "pickle"),    # Pickle proto 2
    (b"\x80\x03", 0, "pickle"),
    (b"\x80\x04", 0, "pickle"),
    (b"\x80\x05", 0, "pickle"),
    (b"\x93NUMPY", 0, "numpy"),
    (b"{\n", 0, "json"),           # JSON-based formats
    (b'{"', 0, "json"),
    (b"\x08\x00", 0, "protobuf"),  # TF SavedModel / ONNX
    (b"PMML", 0, "pmml"),
    (b"T7\x00\x00", 0, "torch7"),  # Torch7 legacy Lua serialization
]

# ExecuTorch FlatBuffer: bytes[4:6] == b"ET", validated at dispatch time
_ET_IDENT_OFFSET = 4

# Extension → format name (lower priority than magic)
_EXT_TABLE: dict[str, str] = {
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".bin": "pytorch",  # HF format
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".h5": "hdf5",
    ".hdf5": "hdf5",
    ".keras": "keras",
    ".tflite": "tflite",
    ".pb": "tensorflow",
    ".pbtxt": "tensorflow",
    ".gguf": "gguf",
    ".joblib": "joblib",
    ".npy": "numpy",
    ".npz": "numpy",
    ".json": "json",
    ".msgpack": "msgpack",
    ".mlmodel": "coreml",
    ".skops": "skops",
    ".nemo": "nemo",
    ".xml": "openvino",
    ".xgb": "xgboost",
    ".ubj": "xgboost",
    ".txt": "lightgbm",
    ".cbm": "catboost",
    ".t7": "torch7",
    ".th": "torch7",
    ".net": "torch7",
    ".md": "model_card",
    ".rst": "model_card",
    ".markdown": "model_card",
    ".engine": "tensorrt",
    ".plan": "tensorrt",
    ".trt": "tensorrt",
    ".pte": "executorch",
    ".ptl": "executorch",
}


def detect_format(filepath: str) -> Optional[str]:
    """Detect model format from file extension and magic bytes.

    Returns a format identifier string (e.g., "pickle", "hdf5", "gguf")
    or None if format is unknown.
    """
    path = Path(filepath)

    # Try magic bytes first (more reliable)
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        for magic, offset, fmt in _MAGIC_TABLE:
            if header[offset:offset + len(magic)] == magic:
                # Refine: ZIP could be PyTorch, Keras, etc.
                if fmt == "zip":
                    return _refine_zip_format(filepath, path.suffix.lower())
                return fmt
    except OSError:
        pass

    # Fall back to extension
    ext = path.suffix.lower()
    return _EXT_TABLE.get(ext)


def _refine_zip_format(filepath: str, ext: str) -> str:
    """Distinguish between ZIP-based formats (PyTorch, Keras, MLflow, etc.)."""
    import zipfile
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = zf.namelist()
            if any("data.pkl" in n for n in names):
                return "pytorch"
            if any(n.endswith(".safetensors") for n in names):
                return "safetensors"
            if any(n.endswith(".keras") or n.endswith(".h5") for n in names):
                return "keras"
            if any("MLmodel" in n for n in names):
                return "mlflow"
            if any(n.endswith(".skops") for n in names):
                return "skops"
    except (zipfile.BadZipFile, OSError):
        pass
    if ext in (".pt", ".pth"):
        return "pytorch"
    return "zip"


def scan_file(filepath: str) -> list[Finding]:
    """Auto-detect format and scan with the appropriate scanner.

    Falls back to generic pattern scanning if no specific scanner matches.
    """
    fmt = detect_format(filepath)
    if fmt is None:
        _log.debug("Unknown format for %s — skipping", filepath)
        return []

    _log.debug("Detected format %s for %s", fmt, filepath)

    # Import scanners lazily to avoid circular imports
    if fmt == "hdf5":
        from sentinel.artifact.h5_scanner import H5Scanner
        return H5Scanner().scan_file(filepath)

    if fmt in ("pickle", "pytorch", "joblib"):
        from sentinel.artifact.pickle_scanner import PickleScanner
        return PickleScanner().scan_file(filepath)

    if fmt == "gguf":
        from sentinel.artifact.gguf_scanner import GGUFScanner
        return GGUFScanner().scan_file(filepath)

    if fmt == "safetensors":
        from sentinel.artifact.safetensors_scanner import SafeTensorsScanner
        return SafeTensorsScanner().scan_file(filepath)

    if fmt == "onnx":
        from sentinel.artifact.onnx_scanner import ONNXScanner
        return ONNXScanner().scan_file(filepath)

    if fmt in ("keras", "tensorflow"):
        from sentinel.artifact.keras_scanner import KerasScanner
        return KerasScanner().scan_file(filepath)

    if fmt == "tflite":
        from sentinel.artifact.tflite_scanner import TFLiteScanner
        return TFLiteScanner().scan_file(filepath)

    if fmt == "json":
        # Could be tokenizer.json or other config
        from sentinel.artifact.tokenizer_scanner import TokenizerScanner
        return TokenizerScanner().scan_file(filepath)

    if fmt == "torch7":
        from sentinel.artifact.torch7_scanner import Torch7Scanner
        return Torch7Scanner().scan_file(filepath)

    if fmt == "model_card":
        from sentinel.artifact.model_card_scanner import ModelCardScanner
        return ModelCardScanner().scan_file(filepath)

    if fmt == "tensorrt":
        from sentinel.artifact.tensorrt_scanner import TensorRTScanner
        return TensorRTScanner().scan_file(filepath)

    if fmt == "executorch":
        from sentinel.artifact.executorch_scanner import ExecuTorchScanner
        return ExecuTorchScanner().scan_file(filepath)

    # Generic fallback: pattern scan
    from sentinel.analysis.integrated import PatternDetector
    return PatternDetector().scan_file(filepath)
