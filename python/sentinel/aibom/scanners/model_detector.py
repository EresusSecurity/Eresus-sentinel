"""Detect model files + model imports in source."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_MODEL_SUFFIXES = (
    ".pt", ".pth", ".pkl", ".safetensors", ".onnx", ".h5", ".keras",
    ".pb", ".tflite", ".gguf", ".bin", ".ckpt", ".cbm", ".lgb", ".xgb",
    ".mlmodel",
)

_MODEL_CALL_RE = re.compile(
    r"(openai|anthropic|google|cohere|mistral|huggingface_hub|transformers|"
    r"llama_cpp|ollama|bedrock|vertexai|genai|groq|replicate|together|"
    r"fireworks|nvidia|xai)\b",
    re.IGNORECASE,
)


class ModelDetector(BaseAIBOMScanner):
    name = "model-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        components: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=_MODEL_SUFFIXES):
            try:
                sha = hashlib.sha256(p.read_bytes()).hexdigest()
            except Exception:
                sha = ""
            components.append(
                AIComponent(
                    type=AIComponentType.MODEL_LLM,
                    name=p.name,
                    path=str(p),
                    properties={"size_bytes": p.stat().st_size, "extension": p.suffix},
                    hashes={"sha256": sha} if sha else {},
                    evidence=[f"model file {p.suffix}"],
                )
            )
        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            for m in _MODEL_CALL_RE.finditer(text):
                components.append(
                    AIComponent(
                        type=AIComponentType.MODEL_LLM,
                        name=m.group(1).lower(),
                        path=str(p),
                        description="Inferred model vendor from import / SDK usage",
                        evidence=[m.group(0)],
                    )
                )
                break
        return components
