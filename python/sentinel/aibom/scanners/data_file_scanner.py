"""Detect datasets and embedding index files."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_DATASET_EXT = (".jsonl", ".parquet", ".arrow", ".csv", ".tsv", ".xlsx")
_INDEX_EXT = (".faiss", ".index", ".chroma", ".qdrant", ".lance")


class DataFileScanner(BaseAIBOMScanner):
    name = "data-file-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=_DATASET_EXT):
            if p.stat().st_size < 1024:
                continue
            out.append(AIComponent(
                type=AIComponentType.DATASET,
                name=p.name,
                path=str(p),
                properties={"size_bytes": p.stat().st_size},
                evidence=[p.suffix],
            ))
        for p in self._iter_files(root, suffixes=_INDEX_EXT):
            out.append(AIComponent(
                type=AIComponentType.EMBEDDING_INDEX,
                name=p.name,
                path=str(p),
                evidence=[p.suffix],
            ))
        return out
