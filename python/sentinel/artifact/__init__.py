"""
 Artifact Scanner Module (17 format scanners)

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
"""

from .pickle_scanner import PickleScanner
from ._pickle_ops import PickleAnalysis, DangerousImport
from .torch_scanner import TorchScanner
from .safetensors_validator import SafetensorsValidator
from .gguf_analyzer import GGUFAnalyzer
from .keras_scanner import KerasScanner
from .onnx_scanner import ONNXScanner
from .archive_slip import ArchiveSlipDetector
from .integrity_engine import IntegrityEngine
from .huggingface_scanner import HuggingFaceScanner
from .tensorflow_scanner import TensorFlowScanner
from .torchscript_scanner import TorchScriptScanner
from .tflite_scanner import TFLiteScanner
from .torchmobile_scanner import TorchMobileScanner
from .llamafile_scanner import LlamaFileScanner
from .xgboost_scanner import XGBoostScanner
from .numpy_scanner import NumpyScanner

__all__ = [
    "PickleScanner",
    "TorchScanner",
    "SafetensorsValidator",
    "GGUFAnalyzer",
    "KerasScanner",
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
]
