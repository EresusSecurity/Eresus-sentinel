"""Liveness (backward) analysis — dual of reaching definitions.

Implemented as a backward walk by reversing predecessors/successors inside
the transfer function; reuses the forward worklist by supplying meet over
successors manually.
"""
from __future__ import annotations

import ast
from typing import Set

from sentinel.sast.static_analysis.cfg.builder import CFG


class LivenessAnalysis:
    """Compute live-variable sets per block (backward dataflow)."""

    max_iterations: int = 10_000

    def run(self, cfg: CFG) -> dict[int, Set[str]]:
        live_out: dict[int, Set[str]] = {bid: set() for bid in cfg.blocks}
        live_in: dict[int, Set[str]] = {bid: set() for bid in cfg.blocks}

        worklist = list(cfg.blocks)
        it = 0
        while worklist and it < self.max_iterations:
            it += 1
            bid = worklist.pop(0)
            succ = cfg.successors(bid)
            new_out: Set[str] = set()
            for s in succ:
                new_out |= live_in[s]
            used, defined = self._use_def(cfg, bid)
            new_in = used | (new_out - defined)
            if new_in != live_in[bid] or new_out != live_out[bid]:
                live_in[bid] = new_in
                live_out[bid] = new_out
                for p in cfg.predecessors(bid):
                    if p not in worklist:
                        worklist.append(p)
        return live_in

    @staticmethod
    def _use_def(cfg: CFG, bid: int) -> tuple[Set[str], Set[str]]:
        used: Set[str] = set()
        defined: Set[str] = set()
        for stmt in cfg.blocks[bid].statements:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Load) and node.id not in defined:
                        used.add(node.id)
                    elif isinstance(node.ctx, ast.Store):
                        defined.add(node.id)
        return used, defined
