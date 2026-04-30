"""Detect vector store components and deduplicate overlapping references."""
from __future__ import annotations

from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType

_VECTOR_TECH_ALIASES: dict[str, str] = {
    "weaviate": "weaviate",
    "pinecone": "pinecone",
    "qdrant": "qdrant",
    "chromadb": "chromadb",
    "chroma": "chromadb",
    "milvus": "milvus",
    "pgvector": "pgvector",
    "faiss": "faiss",
    "redis": "redis-vector",
    "opensearch": "opensearch-vector",
    "elasticsearch": "elasticsearch-vector",
}


def identify_vector_stores(result: AIBOMResult) -> list[AIComponent]:
    """Find all vector store components in the BOM."""
    return [c for c in result.components if c.type == AIComponentType.VECTOR_STORE]


def deduplicate_vector_stores(result: AIBOMResult) -> int:
    """Merge duplicate vector store references, keeping the richest metadata."""
    vs_components = identify_vector_stores(result)
    if len(vs_components) <= 1:
        return 0

    groups: dict[str, list[AIComponent]] = {}
    for comp in vs_components:
        tech = _normalize_technology(comp)
        groups.setdefault(tech, []).append(comp)

    removed = 0
    for tech, group in groups.items():
        if len(group) <= 1:
            continue
        primary = max(group, key=lambda c: len(c.evidence) + len(c.properties))
        for other in group:
            if other is primary:
                continue
            primary.evidence = list(set(primary.evidence + other.evidence))
            for k, v in other.properties.items():
                if k not in primary.properties:
                    primary.properties[k] = v
            result.components.remove(other)
            removed += 1

    return removed


def _normalize_technology(comp: AIComponent) -> str:
    name_lower = comp.name.lower()
    for alias, canonical in _VECTOR_TECH_ALIASES.items():
        if alias in name_lower:
            return canonical
    desc_lower = comp.description.lower()
    for alias, canonical in _VECTOR_TECH_ALIASES.items():
        if alias in desc_lower:
            return canonical
    return comp.name.lower()
