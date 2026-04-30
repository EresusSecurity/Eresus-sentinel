"""AI asset catalog database for enriching BOM components with known metadata."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_BUILTIN_CATALOG_PATH = Path(__file__).parent / "data" / "builtin_catalog.json"


@dataclass
class CatalogEntry:
    name: str
    vendor: str = ""
    license: str = ""
    category: str = ""
    description: str = ""
    url: str = ""
    tags: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


class CatalogDB:
    """In-memory catalog of known AI/ML assets for BOM enrichment."""

    def __init__(self) -> None:
        self._entries: dict[str, CatalogEntry] = {}

    def load_builtin(self) -> int:
        return self.load_file(_BUILTIN_CATALOG_PATH)

    def load_file(self, path: Path) -> int:
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to load catalog %s: %s", path, e)
            return 0
        return self.load_entries(data)

    def load_entries(self, data: list[dict[str, Any]] | dict[str, Any]) -> int:
        if isinstance(data, dict):
            data = data.get("entries", [])
        count = 0
        for entry_data in data:
            if not isinstance(entry_data, dict) or "name" not in entry_data:
                continue
            entry = CatalogEntry(
                name=entry_data["name"],
                vendor=entry_data.get("vendor", ""),
                license=entry_data.get("license", ""),
                category=entry_data.get("category", ""),
                description=entry_data.get("description", ""),
                url=entry_data.get("url", ""),
                tags=entry_data.get("tags", []),
                properties=entry_data.get("properties", {}),
            )
            self._entries[entry.name.lower()] = entry
            count += 1
        return count

    def lookup(self, name: str) -> Optional[CatalogEntry]:
        return self._entries.get(name.lower())

    def enrich(self, component_name: str) -> dict[str, Any]:
        entry = self.lookup(component_name)
        if not entry:
            return {}
        enrichment: dict[str, Any] = {}
        if entry.vendor:
            enrichment["vendor"] = entry.vendor
        if entry.license:
            enrichment["license"] = entry.license
        if entry.category:
            enrichment["category"] = entry.category
        if entry.description:
            enrichment["catalog_description"] = entry.description
        if entry.url:
            enrichment["url"] = entry.url
        if entry.tags:
            enrichment["tags"] = entry.tags
        return enrichment

    @property
    def size(self) -> int:
        return len(self._entries)

    def all_names(self) -> list[str]:
        return sorted(self._entries.keys())
