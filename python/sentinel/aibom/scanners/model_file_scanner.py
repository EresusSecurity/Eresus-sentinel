"""Detect model files and link them as BOM components."""
from __future__ import annotations

import hashlib
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_MODEL_EXTENSIONS = {
    ".safetensors": "safetensors",
    ".gguf": "gguf",
    ".onnx": "onnx",
    ".h5": "keras-h5",
    ".pb": "tensorflow-pb",
    ".tflite": "tensorflow-lite",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".bin": "model-weights",
    ".mlmodel": "coreml",
    ".mlpackage": "coreml",
    ".pkl": "pickle-model",
    ".joblib": "joblib-model",
    ".pmml": "pmml",
    ".ckpt": "checkpoint",
    ".mar": "torchserve",
    ".savedmodel": "tensorflow-saved",
}

_MIN_MODEL_SIZE = 1024


class ModelFileScanner(BaseAIBOMScanner):
    name = "model-file-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=tuple(_MODEL_EXTENSIONS.keys())):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size < _MIN_MODEL_SIZE:
                continue
            ext = p.suffix.lower()
            framework = _MODEL_EXTENSIONS.get(ext, "unknown")
            hashes = {}
            try:
                data = p.read_bytes()
                hashes["sha256"] = hashlib.sha256(data).hexdigest()
            except Exception:
                pass
            out.append(AIComponent(
                type=AIComponentType.MODEL_LLM,
                name=p.name,
                path=str(p),
                description=f"Model file ({framework}): {p.name} ({size:,} bytes)",
                evidence=[framework],
                hashes=hashes,
                properties={"format": framework, "size_bytes": size, "extension": ext},
            ))
        return out
