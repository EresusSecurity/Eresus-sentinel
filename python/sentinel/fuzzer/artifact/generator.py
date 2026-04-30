"""Artifact format generator for ML and agent supply-chain files.

Public entry-point.  Byte generation lives in the ``generators`` subpackage,
split by format family:

- ``binary_formats``    — GGUF, SafeTensors, NPY/NPZ, ONNX, TFLite
- ``pickle_formats``    — PyTorch, joblib, cloudpickle, dill, marshal
- ``archive_formats``   — Keras, CoreML, Skops, NeMo, ZIP-slip
- ``inference_formats`` — OpenVINO, PMML, XGBoost, LightGBM, CatBoost
- ``ml_frameworks``     — MLflow, TorchScript, Flax/JAX, LoRA, Tokenizer, Paddle
- ``agentic_formats``  — Ollama Modelfile, LlamaFile
"""

from __future__ import annotations

import random

from ..base import Generator
from .generators import agentic_formats as _agent
from .generators import archive_formats as _arc
from .generators import binary_formats as _bin
from .generators import inference_formats as _inf
from .generators import ml_frameworks as _ml
from .generators import pickle_formats as _pkl


class ArtifactGenerator(Generator):
    """Generates adversarial ML artifact files.

    Supports binary model formats, archive/container formats, text model
    manifests, and legacy serialization containers.
    """

    _BASE_FORMATS = (
        "gguf",
        "safetensors",
        "pytorch",
        "zip",
        "onnx",
        "keras",
        "keras_h5",
        "tflite",
        "coreml",
        "mlmodel",
        "skops",
        "nemo",
        "openvino_xml",
        "pmml",
        "npy",
        "npz",
        "joblib",
        "cloudpickle",
        "dill",
        "marshal",
        "onnx_external",
        "xgboost",
        "lightgbm",
        "catboost",
        "mlflow",
        "torchscript",
        "flax_checkpoint",
        "lora_adapter",
        "tokenizer_json",
        "ollama_modelfile",
        "paddle",
        "llamafile",
    )

    _FORMAT_ALIASES = {
        "h5": "keras_h5",
        "hdf5": "keras_h5",
        "keras_zip": "keras",
        "keras_v3": "keras",
        "litert": "tflite",
        "mlpackage": "coreml",
        "coreml_package": "coreml",
        "openvino": "openvino_xml",
        "openvino_ir": "openvino_xml",
        "numpy": "npy",
        "npy_pickle": "npy",
        "npz_pickle": "npz",
        "pkl": "pytorch",
        "pickle": "pytorch",
        "external_data": "onnx_external",
        "onnx_external_data": "onnx_external",
        "xgb": "xgboost",
        "lgb": "lightgbm",
        "cbm": "catboost",
        "mlflow_model": "mlflow",
        "torchscript_pt": "torchscript",
        "pt": "torchscript",
        "flax": "flax_checkpoint",
        "jax": "flax_checkpoint",
        "lora": "lora_adapter",
        "tokenizer": "tokenizer_json",
        "hf_tokenizer": "tokenizer_json",
        "ollama": "ollama_modelfile",
        "modelfile": "ollama_modelfile",
        "paddlepaddle": "paddle",
        "pdparams": "paddle",
        "llama": "llamafile",
        "llamafile_bin": "llamafile",
    }

    # Dispatch table: format → module-level function
    _GENERATORS = {
        # binary
        "gguf":            _bin.gen_gguf,
        "safetensors":     _bin.gen_safetensors,
        "onnx":            _bin.gen_onnx_stub,
        "tflite":          _bin.gen_tflite_stub,
        "npy":             _bin.gen_numpy_npy,
        "npz":             _bin.gen_numpy_npz,
        "onnx_external":   _bin.gen_onnx_external_data,
        # pickle-based
        "pytorch":         _pkl.gen_pytorch_zip,
        "zip":             _pkl.gen_zip_slip,
        "joblib":          _pkl.gen_joblib_stream,
        "cloudpickle":     _pkl.gen_cloudpickle_stream,
        "dill":            _pkl.gen_dill_stream,
        "marshal":         _pkl.gen_marshal_blob,
        # archive/container
        "keras":           _arc.gen_keras_zip,
        "keras_h5":        _arc.gen_keras_h5_stub,
        "coreml":          _arc.gen_coreml_package,
        "mlmodel":         _arc.gen_coreml_model,
        "skops":           _arc.gen_skops_zip,
        "nemo":            _arc.gen_nemo_archive,
        # inference
        "openvino_xml":    _inf.gen_openvino_xml,
        "pmml":            _inf.gen_pmml_xml,
        "xgboost":         _inf.gen_xgboost_binary,
        "lightgbm":        _inf.gen_lightgbm_text,
        "catboost":        _inf.gen_catboost_binary,
        # ml frameworks
        "mlflow":          _ml.gen_mlflow_model,
        "torchscript":     _ml.gen_torchscript,
        "flax_checkpoint": _ml.gen_flax_checkpoint,
        "lora_adapter":    _ml.gen_lora_adapter,
        "tokenizer_json":  _ml.gen_tokenizer_json,
        "paddle":          _ml.gen_paddle_model,
        # agentic
        "ollama_modelfile": _agent.gen_ollama_modelfile,
        "llamafile":        _agent.gen_llamafile,
    }

    def __init__(self, format: str = "random", seed: int | None = None):  # noqa: A002
        self._format = format
        self._seed = seed

    @classmethod
    def supported_formats(cls) -> tuple[str, ...]:
        """Return canonical artifact format names accepted by the generator."""
        return cls._BASE_FORMATS

    def generate(self, seed: int | None = None) -> bytes:
        rng = random.Random(self._seed if seed is None else seed)  # noqa: S311
        fmt = self._normalize_format(self._format)
        if fmt == "random":
            fmt = rng.choice(self._BASE_FORMATS)
        gen_fn = self._GENERATORS.get(fmt, _bin.gen_gguf)
        return gen_fn(rng)

    def generate_from_bytes(self, data: bytes) -> bytes:
        seed = int.from_bytes(data[:8].ljust(8, b"\x00"), "little")
        return self.generate(seed=seed)

    @classmethod
    def _normalize_format(cls, fmt: str) -> str:
        normalized = fmt.strip().lower().replace("-", "_")
        return cls._FORMAT_ALIASES.get(normalized, normalized)
