"""Annotate BOM findings with additional context and cross-references."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.aibom.models import AIComponent


@dataclass
class Annotation:
    component_id: str
    key: str
    value: Any
    source: str = ""
    confidence: float = 1.0


class AnnotationStore:
    """Store and retrieve annotations for BOM components."""

    def __init__(self) -> None:
        self._annotations: dict[str, list[Annotation]] = {}

    def annotate(
        self,
        component: AIComponent,
        key: str,
        value: Any,
        source: str = "",
        confidence: float = 1.0,
    ) -> Annotation:
        ann = Annotation(
            component_id=component.id,
            key=key,
            value=value,
            source=source,
            confidence=confidence,
        )
        self._annotations.setdefault(component.id, []).append(ann)
        return ann

    def get(self, component: AIComponent) -> list[Annotation]:
        return self._annotations.get(component.id, [])

    def get_by_key(self, component: AIComponent, key: str) -> list[Annotation]:
        return [a for a in self.get(component) if a.key == key]

    def apply_to_properties(self, component: AIComponent) -> None:
        for ann in self.get(component):
            component.properties[f"annotation:{ann.key}"] = ann.value

    def apply_all(self, components: list[AIComponent]) -> None:
        for comp in components:
            self.apply_to_properties(comp)

    @property
    def size(self) -> int:
        return sum(len(v) for v in self._annotations.values())

    def clear(self) -> None:
        self._annotations.clear()
