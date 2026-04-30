"""
Known-good opcode patterns per ML framework.

Provides baseline opcode sequences and module/attribute pairs that are
expected in legitimate models for PyTorch, sklearn, joblib, TensorFlow, etc.
Used by the anomaly detector and unified context for scoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FrameworkProfile:
    """Known-good profile for a specific ML framework."""
    name: str
    safe_modules: frozenset[str] = field(default_factory=frozenset)
    expected_opcodes: frozenset[int] = field(default_factory=frozenset)
    typical_extensions: tuple[str, ...] = ()
    description: str = ""


PYTORCH = FrameworkProfile(
    name="pytorch",
    safe_modules=frozenset({
        "torch._utils", "torch.nn.modules", "torch.nn.parameter",
        "torch.storage", "torch", "torch.cuda",
        "collections", "collections.OrderedDict",
        "_codecs", "codecs",
    }),
    expected_opcodes=frozenset({
        0x80, 0x95, 0x8C, 0x93, 0x52, 0x81, 0x7D, 0x5D,
        0x71, 0x68, 0x8A, 0x4B, 0x88, 0x89, 0x4E, 0x47,
        0x85, 0x86, 0x87, 0x29, 0x75, 0x65, 0x62, 0x2E,
    }),
    typical_extensions=(".pt", ".pth", ".bin"),
    description="PyTorch model checkpoint",
)

SKLEARN = FrameworkProfile(
    name="sklearn",
    safe_modules=frozenset({
        "sklearn.linear_model", "sklearn.ensemble", "sklearn.tree",
        "sklearn.svm", "sklearn.neighbors", "sklearn.pipeline",
        "sklearn.preprocessing", "sklearn.decomposition",
        "sklearn.cluster", "sklearn.metrics",
        "numpy", "numpy.core", "numpy.core.multiarray",
        "scipy.sparse",
    }),
    expected_opcodes=frozenset({
        0x80, 0x95, 0x8C, 0x93, 0x52, 0x81, 0x7D, 0x5D,
        0x71, 0x68, 0x8A, 0x4B, 0x88, 0x89, 0x4E, 0x47,
        0x29, 0x75, 0x65, 0x62, 0x2E,
    }),
    typical_extensions=(".pkl", ".pickle", ".joblib"),
    description="Scikit-learn model",
)

JOBLIB = FrameworkProfile(
    name="joblib",
    safe_modules=frozenset({
        "numpy", "numpy.core", "numpy.core.multiarray",
        "numpy.core.numeric", "numpy.dtype",
        "joblib.numpy_pickle",
    }),
    expected_opcodes=frozenset({
        0x80, 0x95, 0x8C, 0x93, 0x52, 0x81, 0x7D, 0x5D,
        0x71, 0x68, 0x2E,
    }),
    typical_extensions=(".joblib", ".pkl"),
    description="Joblib-serialized model",
)

XGBOOST = FrameworkProfile(
    name="xgboost",
    safe_modules=frozenset({
        "xgboost.core", "xgboost.sklearn",
        "numpy", "numpy.core",
    }),
    expected_opcodes=frozenset({
        0x80, 0x95, 0x8C, 0x93, 0x52, 0x81, 0x7D,
        0x71, 0x68, 0x2E,
    }),
    typical_extensions=(".pkl", ".json", ".ubj"),
    description="XGBoost model",
)

LIGHTGBM = FrameworkProfile(
    name="lightgbm",
    safe_modules=frozenset({
        "lightgbm.basic", "lightgbm.sklearn",
        "numpy", "numpy.core",
    }),
    expected_opcodes=frozenset({
        0x80, 0x95, 0x8C, 0x93, 0x52, 0x81, 0x7D,
        0x71, 0x68, 0x2E,
    }),
    typical_extensions=(".pkl", ".txt"),
    description="LightGBM model",
)

TENSORFLOW = FrameworkProfile(
    name="tensorflow",
    safe_modules=frozenset({
        "tensorflow", "tensorflow.python",
        "keras", "keras.layers", "keras.models",
    }),
    expected_opcodes=frozenset({
        0x80, 0x95, 0x8C, 0x93, 0x52, 0x81, 0x7D,
        0x71, 0x68, 0x2E,
    }),
    typical_extensions=(".h5", ".pb", ".keras", ".tflite"),
    description="TensorFlow/Keras model",
)

# Registry of all framework profiles
ALL_PROFILES: dict[str, FrameworkProfile] = {
    p.name: p for p in [PYTORCH, SKLEARN, JOBLIB, XGBOOST, LIGHTGBM, TENSORFLOW]
}


def detect_framework(modules_seen: set[str]) -> str | None:
    """Detect framework from a set of module names seen in a pickle.

    Returns the framework name or None if no match.
    """
    best_name: str | None = None
    best_overlap = 0
    for name, profile in ALL_PROFILES.items():
        overlap = len(modules_seen & profile.safe_modules)
        if overlap > best_overlap:
            best_overlap = overlap
            best_name = name
    return best_name if best_overlap >= 2 else None


def is_safe_module(module: str, framework: str | None = None) -> bool:
    """Check if a module is in the safe list for a given framework (or any)."""
    if framework and framework in ALL_PROFILES:
        return module in ALL_PROFILES[framework].safe_modules
    return any(module in p.safe_modules for p in ALL_PROFILES.values())
