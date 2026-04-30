"""Detect AI/ML usage across multiple programming languages (JS/TS, Go, Java, Ruby)."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns

_EXT_TO_LANG = {
    ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".mjs": "javascript", ".go": "go",
    ".java": "java", ".rb": "ruby",
}
_LANG_KEY = {
    "javascript": "javascript", "typescript": "javascript",
    "go": "go", "java": "java", "ruby": "ruby",
}
_SUFFIXES = tuple(_EXT_TO_LANG.keys())


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
                            type=AIComponentType.TOOL,
                            name=f"{lang}-ai:{label}", path=str(p),
                            description=f"AI/ML usage in {lang}: {label}",
                            evidence=[label],
                            properties={"language": lang, "pattern": label},
                        ))
        return out
