"""Artifact format generator submodules.

Each module groups related adversarial generators by format family.
The main ArtifactGenerator class dispatches to these.

Submodules
----------
binary_formats    — GGUF, SafeTensors, NPY/NPZ, ONNX, TFLite
pickle_formats    — PyTorch, joblib, cloudpickle, dill, marshal, ZIP-slip
archive_formats   — Keras, CoreML, Skops, NeMo
inference_formats — OpenVINO, PMML, XGBoost, LightGBM, CatBoost
ml_frameworks     — MLflow, TorchScript, Flax/JAX, LoRA, Tokenizer, Paddle
agentic_formats   — Ollama Modelfile, LlamaFile
"""

from . import (  # noqa: F401
    agentic_formats,
    archive_formats,
    base,
    binary_formats,
    inference_formats,
    ml_frameworks,
    pickle_formats,
)
