"""Detect AI/ML usage across multiple programming languages."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns

_EXT_TO_LANG = {
    ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".mjs": "javascript", ".go": "go",
    ".java": "java", ".rb": "ruby", ".cs": "csharp",
}
_LANG_KEY = {
    "javascript": "javascript", "typescript": "javascript",
    "go": "go", "java": "java", "ruby": "ruby", "csharp": "csharp",
}
_SUFFIXES = tuple(_EXT_TO_LANG.keys())
_INLINE_MODEL_RE = re.compile(
    r"\b(?:model|model_id|deployment|deployment_name)\s*[:=]\s*[\"']([A-Za-z0-9_./:-]{3,120})[\"']"
)
_VECTOR_STORE_RE = re.compile(r"\b(?:pinecone|qdrant|weaviate|milvus|chroma|faiss)\b", re.IGNORECASE)
_EMBEDDING_RE = re.compile(r"\b(?:embedding|embedQuery|embedDocuments|text-embedding-[A-Za-z0-9-]+)\b", re.IGNORECASE)


class MultiLanguageScanner(BaseAIBOMScanner):
    name = "multi-language-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        rules = load_aibom_patterns()["multi_language"]
        out: list[AIComponent] = []
        seen: set[tuple[str, str]] = set()
        for p in self._iter_files(root, suffixes=_SUFFIXES):
            lang = _EXT_TO_LANG.get(p.suffix.lower())
            if not lang:
                continue
            lang_key = _LANG_KEY.get(lang, lang)
            patterns = rules.get(lang_key, [])
            if not patterns:
                continue
            text = self._read(p)
            for rx, label, *_ in patterns:
                if rx.search(text):
                    key = (str(p), label)
                    if key not in seen:
                        seen.add(key)
                        out.append(AIComponent(
                            type=_component_type_for_label(label),
                            name=f"{lang}-ai:{label}", path=str(p),
                            description=f"AI/ML usage in {lang}: {label}",
                            evidence=[label],
                            properties={"language": lang, "pattern": label, "parser": "tree-sitter-compatible-regex"},
                        ))
            self._scan_inline_models(p, lang, text, seen, out)
        return out

    def _scan_inline_models(self, p: Path, lang: str, text: str, seen: set[tuple[str, str]], out: list[AIComponent]) -> None:
        for match in _INLINE_MODEL_RE.finditer(text):
            model_name = match.group(1)
            key = (str(p), f"model:{model_name}")
            if key in seen:
                continue
            seen.add(key)
            out.append(AIComponent(
                type=AIComponentType.MODEL_LLM,
                name=model_name,
                path=str(p),
                description=f"Inline model reference in {lang}",
                evidence=[match.group(0)[:160]],
                properties={"language": lang, "component_source": "inline-model-string"},
            ))
        if _VECTOR_STORE_RE.search(text):
            key = (str(p), "vector-store")
            if key not in seen:
                seen.add(key)
                out.append(AIComponent(
                    type=AIComponentType.VECTOR_STORE,
                    name=f"{lang}-vector-store",
                    path=str(p),
                    description=f"Vector store usage in {lang}",
                    evidence=["vector-store-keyword"],
                    properties={"language": lang},
                ))
        if _EMBEDDING_RE.search(text):
            key = (str(p), "embedding")
            if key not in seen:
                seen.add(key)
                out.append(AIComponent(
                    type=AIComponentType.MODEL_EMBEDDING,
                    name=f"{lang}-embedding",
                    path=str(p),
                    description=f"Embedding usage in {lang}",
                    evidence=["embedding-keyword"],
                    properties={"language": lang},
                ))


def _component_type_for_label(label: str) -> AIComponentType:
    lower = label.lower()
    if "vector" in lower:
        return AIComponentType.VECTOR_STORE
    if "embedding" in lower:
        return AIComponentType.MODEL_EMBEDDING
    if "client" in lower or "completion" in lower:
        return AIComponentType.ENDPOINT
    return AIComponentType.TOOL
