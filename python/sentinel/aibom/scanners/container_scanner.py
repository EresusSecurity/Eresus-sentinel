"""Detect AI-related artifacts in Dockerfiles."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_DOCKER_HINT = re.compile(
    r"\b(openai|anthropic|huggingface|transformers|torch|tensorflow|ollama|"
    r"vllm|tgi|llama_cpp|cuda|nvidia)\b",
    re.IGNORECASE,
)


class ContainerScanner(BaseAIBOMScanner):
    name = "container-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, names=("Dockerfile",)):
            text = self._read(p)
            if _DOCKER_HINT.search(text):
                out.append(AIComponent(
                    type=AIComponentType.CONTAINER,
                    name=p.parent.name or "Dockerfile",
                    path=str(p),
                    description="Container image with AI components",
                    evidence=["Dockerfile hints"],
                ))
        return out
