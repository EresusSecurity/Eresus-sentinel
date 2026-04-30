"""Scan workspace-level dependency manifests for AI/ML package references."""
from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_AI_PYTHON_PACKAGES = frozenset({
    "torch", "tensorflow", "transformers", "langchain", "openai", "anthropic",
    "langchain-core", "langchain-community", "langgraph", "crewai", "autogen",
    "smolagents", "pydantic-ai", "chromadb", "pinecone-client", "weaviate-client",
    "qdrant-client", "faiss-cpu", "faiss-gpu", "sentence-transformers",
    "llama-index", "huggingface-hub", "safetensors", "onnxruntime", "vllm",
    "keras", "jax", "flax", "datasets", "evaluate", "accelerate",
    "trl", "peft", "bitsandbytes", "triton",
})

_AI_JS_PACKAGES = frozenset({
    "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core",
    "@langchain/community", "@langchain/openai", "ai", "@ai-sdk/openai",
    "llamaindex", "chromadb", "@pinecone-database/pinecone",
    "@weaviate/weaviate-client", "cohere-ai",
})


class WorkspaceDepScanner(BaseAIBOMScanner):
    name = "workspace-dep-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []

        for p in self._iter_files(root, names=("pyproject.toml",)):
            self._scan_pyproject(p, out)
        for p in self._iter_files(root, names=("requirements.txt",)):
            self._scan_requirements(p, out)
        for p in self._iter_files(root, names=("Pipfile",)):
            self._scan_requirements(p, out)
        for p in self._iter_files(root, names=("package.json",)):
            self._scan_package_json(p, out)

        return out

    def _scan_pyproject(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        in_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and "dependencies" in stripped.lower():
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
            if in_deps:
                pkg = re.split(r"[=<>!~;\[,\"]", stripped)[0].strip().strip("\"' ")
                if pkg.lower() in _AI_PYTHON_PACKAGES:
                    out.append(self._make_component(p, pkg, "pyproject.toml"))

    def _scan_requirements(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            pkg = re.split(r"[=<>!~;\[]", line)[0].strip().lower()
            if pkg in _AI_PYTHON_PACKAGES:
                out.append(self._make_component(p, pkg, p.name))

    def _scan_package_json(self, p: Path, out: list[AIComponent]) -> None:
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                if pkg in _AI_JS_PACKAGES:
                    out.append(self._make_component(p, pkg, "package.json", version=str(ver)))

    @staticmethod
    def _make_component(p: Path, pkg: str, source: str, version: str = "") -> AIComponent:
        return AIComponent(
            type=AIComponentType.TOOL,
            name=f"workspace-dep:{pkg}",
            version=version,
            path=str(p),
            description=f"Workspace AI dependency: {pkg}",
            evidence=[f"{source}-ai-dep"],
            properties={"source": source, "package": pkg},
        )
