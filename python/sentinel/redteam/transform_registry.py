"""Prompt/output transform registry for redteam evaluation pipelines."""
from __future__ import annotations

import base64
import logging
import re
from collections.abc import Callable

logger = logging.getLogger(__name__)

TransformFn = Callable[[str], str]


class TransformRegistry:
    """Registry of prompt/output transforms for evaluation pipelines."""

    def __init__(self) -> None:
        self._transforms: dict[str, TransformFn] = {}
        self._register_builtins()

    def _register_builtins(self) -> None:
        self._transforms["lowercase"] = str.lower
        self._transforms["uppercase"] = str.upper
        self._transforms["strip"] = str.strip
        self._transforms["base64_encode"] = lambda s: base64.b64encode(s.encode()).decode()
        self._transforms["base64_decode"] = lambda s: base64.b64decode(s.encode()).decode()
        self._transforms["reverse"] = lambda s: s[::-1]
        self._transforms["remove_whitespace"] = lambda s: re.sub(r"\s+", " ", s).strip()
        self._transforms["first_line"] = lambda s: s.split("\n")[0]
        self._transforms["last_line"] = lambda s: s.rstrip("\n").split("\n")[-1]
        self._transforms["strip_tags"] = lambda s: re.sub(r"<[^>]+>", "", s)
        self._transforms["normalize_quotes"] = lambda s: (
            s.replace("\u201c", '"').replace("\u201d", '"')
            .replace("\u2018", "'").replace("\u2019", "'")
        )

    def register(self, name: str, fn: TransformFn) -> None:
        self._transforms[name] = fn

    def apply(self, name: str, text: str) -> str:
        fn = self._transforms.get(name)
        if fn is None:
            raise KeyError(f"Unknown transform: {name}")
        return fn(text)

    def apply_chain(self, names: list[str], text: str) -> str:
        for name in names:
            text = self.apply(name, text)
        return text

    @property
    def transform_count(self) -> int:
        return len(self._transforms)

    def all_names(self) -> list[str]:
        return sorted(self._transforms.keys())
