"""Reaching-definitions analysis."""
from __future__ import annotations

import ast
from typing import Set, Tuple

from sentinel.sast.static_analysis.cfg.builder import CFG
from sentinel.sast.static_analysis.dataflow.forward_analysis import ForwardAnalysis

Def = Tuple[str, int]  # (variable_name, ast_node_id)


class ReachingDefinitions(ForwardAnalysis[Set[Def]]):
    def initial(self, cfg: CFG) -> Set[Def]:
        return set()

    def bottom(self, cfg: CFG) -> Set[Def]:
        return set()

    def meet(self, a: Set[Def], b: Set[Def]) -> Set[Def]:
        return a | b

    def transfer(self, cfg: CFG, bid: int, inp: Set[Def]) -> Set[Def]:
        out = set(inp)
        for stmt in cfg.blocks[bid].statements:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        for n in ast.walk(tgt):
                            if isinstance(n, ast.Name):
                                out = {d for d in out if d[0] != n.id}
                                out.add((n.id, id(node)))
                elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                    out.add((node.target.id, id(node)))
        return out
