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
from .trojan_detector import TrojanDetector
from .binary_tail_scanner import BinaryTailScanner
from .cve_detector import CVEDetector
from .catboost_scanner import CatBoostScanner
from .coreml_scanner import CoreMLScanner
from .flax_scanner import FlaxScanner
from .lightgbm_scanner import LightGBMScanner
from .mxnet_scanner import MXNetScanner
from .nemo_scanner import NeMoScanner
from .openvino_scanner import OpenVINOScanner
from .paddle_scanner import PaddleScanner
from .pmml_scanner import PMMLScanner
from .r_serialized_scanner import RSerializedScanner
from .skops_scanner import SkopsScanner
from .torchserve_scanner import TorchServeScanner, Torch7Scanner, ExecuTorchScanner, TensorRTScanner
from .oci_scanner import OCIScanner
from .sevenz_scanner import SevenZipScanner
from .yaml_scanner import YamlScanner

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
