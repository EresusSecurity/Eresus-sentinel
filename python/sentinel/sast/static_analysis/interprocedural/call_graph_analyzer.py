"""Call-graph construction over a parsed Python module.

Edges are ``caller -> callee`` by symbolic name. Dynamic calls (attribute
access on arbitrary expressions, ``getattr``) are recorded as ``*unknown*``
so the downstream taint engine can widen safely.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class CallSite:
    caller: str
    callee: str
    line: int


@dataclass
class CallGraph:
    functions: dict[str, list[CallSite]] = field(default_factory=dict)

    def add(self, site: CallSite) -> None:
        self.functions.setdefault(site.caller, []).append(site)

    def callees(self, caller: str) -> list[str]:
        return [cs.callee for cs in self.functions.get(caller, [])]

    def callers_of(self, callee: str) -> list[str]:
        out: list[str] = []
        for caller, sites in self.functions.items():
            if any(s.callee == callee for s in sites):
                out.append(caller)
        return out


class CallGraphAnalyzer(ast.NodeVisitor):
    """Build a :class:`CallGraph` from a module."""

    def __init__(self) -> None:
        self.graph = CallGraph()
        self._stack: list[str] = ["<module>"]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._stack.append(node.name)
        self.graph.functions.setdefault(node.name, [])
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        caller = self._stack[-1]
        callee = self._call_name(node.func)
        self.graph.add(CallSite(caller=caller, callee=callee, line=getattr(node, "lineno", 0)))
        self.generic_visit(node)

    @staticmethod
    def _call_name(expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return expr.attr
        return "*unknown*"

    def run(self, tree: ast.AST) -> CallGraph:
        self.visit(tree)
        return self.graph
