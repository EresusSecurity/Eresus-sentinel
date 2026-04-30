"""Simple constant-propagation analysis."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from sentinel.sast.static_analysis.cfg.builder import CFG
from sentinel.sast.static_analysis.dataflow.forward_analysis import ForwardAnalysis

_TOP = object()  # NAC (not a constant)


@dataclass(frozen=True)
class ConstLattice:
    env: tuple[tuple[str, Any], ...] = ()

    def get(self, name: str) -> Any:
        for k, v in self.env:
            if k == name:
                return v
        return None

    def set(self, name: str, value: Any) -> "ConstLattice":
        env = tuple((k, v) for k, v in self.env if k != name) + ((name, value),)
        return ConstLattice(env=env)

    def merge(self, other: "ConstLattice") -> "ConstLattice":
        out: dict[str, Any] = {k: v for k, v in self.env}
        for k, v in other.env:
            if k in out and out[k] != v:
                out[k] = _TOP
            else:
                out.setdefault(k, v)
        return ConstLattice(env=tuple(out.items()))


class ConstantPropagation(ForwardAnalysis[ConstLattice]):
    def initial(self, cfg: CFG) -> ConstLattice:
        return ConstLattice()

    def bottom(self, cfg: CFG) -> ConstLattice:
        return ConstLattice()

    def meet(self, a: ConstLattice, b: ConstLattice) -> ConstLattice:
        return a.merge(b)

    def transfer(self, cfg: CFG, bid: int, inp: ConstLattice) -> ConstLattice:
        env = inp
        for stmt in cfg.blocks[bid].statements:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name = stmt.targets[0].id
                value = self._eval(stmt.value, env)
                env = env.set(name, value)
        return env

    def _eval(self, node: ast.AST, env: ConstLattice) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            v = env.get(node.id)
            return v if v is not _TOP else _TOP
        return _TOP
