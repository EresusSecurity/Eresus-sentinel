"""BOM diff comparison — compare two AIBOM results and report changes."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.aibom.models import AIBOMResult, AIComponent


@dataclass
class ComponentDiff:
    added: list[AIComponent] = field(default_factory=list)
    removed: list[AIComponent] = field(default_factory=list)
    modified: list[tuple[AIComponent, AIComponent, list[str]]] = field(default_factory=list)


@dataclass
class BOMDiff:
    components: ComponentDiff = field(default_factory=ComponentDiff)
    metadata_changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.components.added
            or self.components.removed
            or self.components.modified
            or self.metadata_changes
        )

    def summary(self) -> dict[str, int]:
        return {
            "added": len(self.components.added),
            "removed": len(self.components.removed),
            "modified": len(self.components.modified),
            "metadata_changes": len(self.metadata_changes),
        }


def diff_bom(old: AIBOMResult, new: AIBOMResult) -> BOMDiff:
    """Compare two BOM results and return structured diff."""
    result = BOMDiff()

    old_index = _index_components(old)
    new_index = _index_components(new)

    old_keys = set(old_index.keys())
    new_keys = set(new_index.keys())

    for key in new_keys - old_keys:
        result.components.added.append(new_index[key])

    for key in old_keys - new_keys:
        result.components.removed.append(old_index[key])

    for key in old_keys & new_keys:
        old_comp = old_index[key]
        new_comp = new_index[key]
        changes = _compare_components(old_comp, new_comp)
        if changes:
            result.components.modified.append((old_comp, new_comp, changes))

    for mkey in set(old.metadata.keys()) | set(new.metadata.keys()):
        old_val = old.metadata.get(mkey)
        new_val = new.metadata.get(mkey)
        if old_val != new_val:
            result.metadata_changes[mkey] = (old_val, new_val)

    return result


def load_bom_json(path: str | Path) -> AIBOMResult:
    """Load an Eresus AIBOM JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("AIBOM JSON must be an object")
    return AIBOMResult.from_dict(data)


def format_diff_json(diff: BOMDiff) -> dict[str, Any]:
    """Format a BOMDiff as a stable JSON payload."""
    return {
        "schema_version": "aibom.diff.v1",
        "summary": diff.summary(),
        "has_changes": diff.has_changes,
        "components": {
            "added": [component.as_dict() for component in diff.components.added],
            "removed": [component.as_dict() for component in diff.components.removed],
            "modified": [
                {
                    "old": old.as_dict(),
                    "new": new.as_dict(),
                    "changes": changes,
                }
                for old, new, changes in diff.components.modified
            ],
        },
        "metadata_changes": {
            key: {"old": old, "new": new}
            for key, (old, new) in diff.metadata_changes.items()
        },
    }


def _index_components(bom: AIBOMResult) -> dict[str, AIComponent]:
    index: dict[str, AIComponent] = {}
    for comp in bom.components:
        key = f"{comp.type.value}:{comp.name}:{comp.path}"
        index[key] = comp
    return index


def _compare_components(old: AIComponent, new: AIComponent) -> list[str]:
    changes: list[str] = []
    if old.version != new.version:
        changes.append(f"version: {old.version!r} -> {new.version!r}")
    if old.description != new.description:
        changes.append("description changed")
    if set(old.evidence) != set(new.evidence):
        changes.append("evidence changed")
    if old.properties != new.properties:
        changes.append("properties changed")
    if set(old.risks) != set(new.risks):
        changes.append("risks changed")
    return changes


def format_diff_markdown(diff: BOMDiff) -> str:
    """Format a BOMDiff as a Markdown report."""
    lines = ["# AIBOM Diff Report\n"]
    s = diff.summary()
    lines.append(f"**Added:** {s['added']} | **Removed:** {s['removed']} | **Modified:** {s['modified']}\n")

    if diff.components.added:
        lines.append("## Added Components\n")
        for comp in diff.components.added:
            lines.append(f"- `{comp.type.value}` **{comp.name}** ({comp.path})")

    if diff.components.removed:
        lines.append("\n## Removed Components\n")
        for comp in diff.components.removed:
            lines.append(f"- `{comp.type.value}` **{comp.name}** ({comp.path})")

    if diff.components.modified:
        lines.append("\n## Modified Components\n")
        for old, new, changes in diff.components.modified:
            lines.append(f"- **{new.name}**: {'; '.join(changes)}")

    return "\n".join(lines) + "\n"
