"""AIBOM result normalization and deduplication."""

from __future__ import annotations

from sentinel.aibom.models import AIBOMResult, AIComponent, Relationship


def component_key(component: AIComponent) -> str:
    """Stable key used to collapse overlapping scanner hits."""
    return "|".join(
        [
            component.type.value,
            component.name.strip().lower(),
            component.path.strip(),
        ]
    )


def normalize_result(result: AIBOMResult) -> AIBOMResult:
    """Deduplicate components and relationships in-place, returning result."""
    by_key: dict[str, AIComponent] = {}
    normalized: list[AIComponent] = []
    id_remap: dict[str, str] = {}

    for component in result.components:
        key = component_key(component)
        existing = by_key.get(key)
        if not existing:
            by_key[key] = component
            normalized.append(component)
            continue
        id_remap[component.id] = existing.id
        _merge_component(existing, component)

    result.components = normalized
    result.relationships = _dedup_relationships(result.relationships, id_remap)
    result.metadata["deduplicated_components"] = len(id_remap)
    return result


def _merge_component(target: AIComponent, source: AIComponent) -> None:
    if not target.version and source.version:
        target.version = source.version
    if not target.description and source.description:
        target.description = source.description
    if not target.vendor and source.vendor:
        target.vendor = source.vendor
    if not target.license and source.license:
        target.license = source.license
    target.properties = {**source.properties, **target.properties}
    target.hashes = {**source.hashes, **target.hashes}
    target.evidence = _merge_list(target.evidence, source.evidence)
    target.risks = _merge_list(target.risks, source.risks)


def _merge_list(left: list[str], right: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return merged


def _dedup_relationships(
    relationships: list[Relationship],
    id_remap: dict[str, str],
) -> list[Relationship]:
    out: list[Relationship] = []
    seen: set[tuple[str, str, str]] = set()
    for relationship in relationships:
        relationship.source_id = id_remap.get(relationship.source_id, relationship.source_id)
        relationship.target_id = id_remap.get(relationship.target_id, relationship.target_id)
        key = (relationship.source_id, relationship.target_id, relationship.type.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(relationship)
    return out
