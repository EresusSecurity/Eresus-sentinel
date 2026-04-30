"""Tree-sitter CFG builder stub — produces a single entry/exit block when
tree-sitter is unavailable. Real multi-language CFGs can be added per grammar.
"""
from __future__ import annotations

from typing import Any

from sentinel.sast.static_analysis.cfg.builder import CFG, BasicBlock, Edge, EdgeKind


class TreeSitterCFGBuilder:
    """Language-agnostic CFG builder scaffold."""

    def __init__(self, language: str = "javascript") -> None:
        self.language = language

    def build(self, tree: Any, name: str = "<module>") -> CFG:
        entry = BasicBlock(0, label="entry")
        exit_ = BasicBlock(1, label="exit")
        cfg = CFG(
            name=name,
            entry=0,
            exit=1,
            blocks={0: entry, 1: exit_},
            edges=[Edge(0, 1, EdgeKind.FALL, label="fall")],
        )
        return cfg
