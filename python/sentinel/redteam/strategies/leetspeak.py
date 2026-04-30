"""Leetspeak encoding bypass strategy."""
from __future__ import annotations

from sentinel.redteam.strategies.base import BaseStrategy

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1", "g": "9", "b": "8"}
LEET_MAP_HEAVY = {**LEET_MAP, "a": "@", "c": "(", "h": "#", "u": "v", "n": r"|\|"}


class LeetspeakStrategy(BaseStrategy):
    name = "leetspeak"
    description = "Convert payload to leetspeak to bypass keyword filters"

    def transform(self, prompt: str) -> list[str]:
        light = "".join(LEET_MAP.get(c.lower(), c) for c in prompt)
        heavy = "".join(LEET_MAP_HEAVY.get(c.lower(), c) for c in prompt)
        return [light, heavy]
