"""Map known vulnerabilities from dependency manifests to BOM components."""
from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_AI_PACKAGES = frozenset({
    "torch", "tensorflow", "transformers", "langchain", "openai",
    "anthropic", "numpy", "scipy", "pandas", "scikit-learn", "sklearn",
    "onnx", "onnxruntime", "safetensors", "huggingface-hub",
    "sentence-transformers", "faiss-cpu", "faiss-gpu", "chromadb",
    "pinecone-client", "weaviate-client", "qdrant-client",
    "llama-index", "crewai", "autogen", "pydantic-ai",
    "langchain-core", "langchain-community", "langgraph",
    "vllm", "triton", "keras", "jax", "flax",
})

_VERSION_RE = re.compile(r"[=<>!~]+(.+)")


class VulnScanner(BaseAIBOMScanner):
    name = "vuln-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, names=("requirements.txt", "setup.cfg", "pyproject.toml")):
            self._scan_requirements(p, out)
        for p in self._iter_files(root, names=("package.json",)):
            self._scan_package_json(p, out)
        return out

    def _scan_requirements(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            pkg = re.split(r"[=<>!~;\[]", line)[0].strip().lower()
            if pkg in _AI_PACKAGES:
                version_match = _VERSION_RE.search(line)
                version = version_match.group(1).strip() if version_match else ""
                out.append(AIComponent(
                    type=AIComponentType.TOOL,
                    name=pkg,
                    version=version,
                    path=str(p),
                    description=f"AI/ML dependency: {pkg}",
                    evidence=["requirements-ai-dep"],
                    risks=[f"Version {version} — check CVE databases" if version else "Unpinned version"],
                    properties={"source": "requirements", "pinned": bool(version)},
                ))

    def _scan_package_json(self, p: Path, out: list[AIComponent]) -> None:
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        js_ai_packages = {"openai", "@anthropic-ai/sdk", "langchain", "@langchain/core",
                          "ai", "@ai-sdk/openai", "llamaindex", "chromadb"}
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                if pkg.lower() in js_ai_packages or "ai" in pkg.lower():
                    out.append(AIComponent(
                        type=AIComponentType.TOOL,
                        name=pkg,
                        version=str(ver),
                        path=str(p),
                        description=f"AI/ML JS dependency: {pkg}",
                        evidence=["package-json-ai-dep"],
                        properties={"source": "package.json", "section": section},
                    ))
