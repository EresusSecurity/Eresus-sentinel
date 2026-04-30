"""Available-expressions analysis (forward, must)."""
from __future__ import annotations

import ast
from typing import Set

from sentinel.sast.static_analysis.cfg.builder import CFG
from sentinel.sast.static_analysis.dataflow.forward_analysis import ForwardAnalysis


def _expr_key(node: ast.AST) -> str:
    try:
        return ast.dump(node, annotate_fields=False)
    except Exception:
        return repr(node)


class AvailableExpressions(ForwardAnalysis[Set[str]]):
    """Track syntactic expressions guaranteed to be computed on all paths."""

    def initial(self, cfg: CFG) -> Set[str]:
        return set()

    def bottom(self, cfg: CFG) -> Set[Set[str]]:  # type: ignore[override]
        # For a must-analysis, bottom is the universe. We approximate by
        # starting with an empty set and relying on meet=intersection after
        # initialization for non-entry blocks.
        return set()

    def meet(self, a: Set[str], b: Set[str]) -> Set[str]:
        return a & b if a and b else (a or b)

    def transfer(self, cfg: CFG, bid: int, inp: Set[str]) -> Set[str]:
        out = set(inp)
        for stmt in cfg.blocks[bid].statements:
            for node in ast.walk(stmt):
                if isinstance(node, (ast.BinOp, ast.Compare, ast.BoolOp)):
                    out.add(_expr_key(node))
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        for n in ast.walk(tgt):
                            if isinstance(n, ast.Name):
                                out = {e for e in out if n.id not in e}
        return out
