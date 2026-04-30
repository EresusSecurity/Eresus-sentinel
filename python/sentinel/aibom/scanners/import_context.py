"""Extract import context to classify file roles in the AI pipeline."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns


class ImportContext(BaseAIBOMScanner):
    name = "import-context"

    def scan(self, root: Path) -> list[AIComponent]:
        rules = load_aibom_patterns()["import_context"]
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            if not text:
                continue
            cats = self._classify(text, rules)
            if cats:
                out.append(AIComponent(
                    type=AIComponentType.CONFIG,
                    name=f"import-context:{p.name}", path=str(p),
                    description=f"File role: {', '.join(cats)}",
                    evidence=cats, properties={"categories": cats, "file": p.name},
                ))
        return out

    @staticmethod
    def _classify(text, rules):
        cats: list[str] = []
        for _group, patterns in rules.items():
            for rx, label, *_ in patterns:
                if rx.search(text) and label not in cats:
                    cats.append(label)
        return cats
