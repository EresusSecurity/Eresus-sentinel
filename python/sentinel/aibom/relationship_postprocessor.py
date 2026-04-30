"""Post-process BOM relationships: normalize, deduplicate, and validate."""
from __future__ import annotations

import logging

from sentinel.aibom.models import AIBOMResult, Relationship, RelationshipType

logger = logging.getLogger(__name__)


def postprocess_relationships(result: AIBOMResult) -> AIBOMResult:
    """Run all relationship post-processing passes."""
    _deduplicate_relationships(result)
    _remove_dangling(result)
    _infer_transitive(result)
    return result


def _deduplicate_relationships(result: AIBOMResult) -> None:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Relationship] = []
    for rel in result.relationships:
        key = (rel.source_id, rel.target_id, rel.type.value)
        if key not in seen:
            seen.add(key)
            unique.append(rel)
    removed = len(result.relationships) - len(unique)
    if removed:
        logger.debug("Removed %d duplicate relationships", removed)
    result.relationships = unique


def _remove_dangling(result: AIBOMResult) -> None:
    component_ids = {c.id for c in result.components}
    valid: list[Relationship] = []
    dangling = 0
    for rel in result.relationships:
        if rel.source_id in component_ids and rel.target_id in component_ids:
            valid.append(rel)
        else:
            dangling += 1
    if dangling:
        logger.debug("Removed %d dangling relationships", dangling)
    result.relationships = valid


def _infer_transitive(result: AIBOMResult) -> None:
    by_source: dict[str, list[Relationship]] = {}
    for rel in result.relationships:
        by_source.setdefault(rel.source_id, []).append(rel)

    new_rels: list[Relationship] = []
    existing = {(r.source_id, r.target_id, r.type.value) for r in result.relationships}

    for rel in result.relationships:
        if rel.type == RelationshipType.DEPENDS_ON:
            for transitive in by_source.get(rel.target_id, []):
                if transitive.type == RelationshipType.DEPENDS_ON:
                    key = (rel.source_id, transitive.target_id, RelationshipType.DEPENDS_ON.value)
                    if key not in existing:
                        existing.add(key)
                        new_rels.append(Relationship(
                            source_id=rel.source_id,
                            target_id=transitive.target_id,
                            type=RelationshipType.DEPENDS_ON,
                            metadata={"inferred": True},
                        ))

    if new_rels:
        logger.debug("Inferred %d transitive relationships", len(new_rels))
        result.relationships.extend(new_rels)
