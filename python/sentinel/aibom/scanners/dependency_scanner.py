"""Parse Python dependency manifests and flag AI-related packages."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_AI_PKGS = {
    "openai", "anthropic", "cohere", "mistralai", "together", "groq",
    "ollama", "llama-index", "llama_index", "langchain", "langchain-core",
    "langgraph", "langsmith", "transformers", "sentence-transformers",
    "huggingface-hub", "huggingface_hub", "torch", "tensorflow",
    "jax", "flax", "peft", "bitsandbytes", "vllm", "tgi",
    "chromadb", "faiss", "faiss-cpu", "faiss-gpu", "pinecone-client",
    "weaviate-client", "qdrant-client", "milvus", "redis",
    "guardrails-ai", "nemo-guardrails", "litellm",
    "instructor", "dspy", "crewai", "autogen", "agno",
}


class DependencyScanner(BaseAIBOMScanner):
    name = "dependency-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, names=("requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock", "uv.lock")):
            text = self._read(p)
            for pkg in _AI_PKGS:
                if re.search(rf"\b{re.escape(pkg)}\b", text, re.IGNORECASE):
                    out.append(
                        AIComponent(
                            type=AIComponentType.PLUGIN,
                            name=pkg,
                            path=str(p),
                            description="AI-related dependency",
                            evidence=[f"{pkg} in {p.name}"],
                        )
                    )
        return out
