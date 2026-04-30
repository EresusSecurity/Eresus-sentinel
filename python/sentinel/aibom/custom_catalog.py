"""Custom catalog loader for user-defined AI asset metadata."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from sentinel.aibom.catalog_db import CatalogDB

logger = logging.getLogger(__name__)

_DEFAULT_CUSTOM_PATHS = [
    Path("aibom-catalog.json"),
    Path(".sentinel/aibom-catalog.json"),
    Path("config/aibom-catalog.json"),
]


def load_custom_catalog(
    db: CatalogDB,
    paths: list[Path] | None = None,
    auto_discover: bool = True,
) -> int:
    """Load custom catalog entries into the given CatalogDB.

    Returns the total number of entries loaded.
    """
    total = 0
    search_paths = list(paths or [])
    if auto_discover:
        search_paths.extend(_DEFAULT_CUSTOM_PATHS)

    for p in search_paths:
        if p.exists():
            loaded = db.load_file(p)
            if loaded:
                logger.info("Loaded %d custom catalog entries from %s", loaded, p)
                total += loaded

    return total


def export_catalog(db: CatalogDB, output: Path) -> None:
    """Export current catalog state to a JSON file."""
    entries = []
    for name in db.all_names():
        entry = db.lookup(name)
        if entry:
            entries.append({
                "name": entry.name,
                "vendor": entry.vendor,
                "license": entry.license,
                "category": entry.category,
                "description": entry.description,
                "url": entry.url,
                "tags": entry.tags,
                "properties": entry.properties,
            })
    output.write_text(json.dumps({"entries": entries}, indent=2), encoding="utf-8")
    logger.info("Exported %d catalog entries to %s", len(entries), output)
