"""Very small type inference pass.

Infers types for literals and simple assignments. Sufficient for picking
out strings and ints in taint/call-graph analysis; not a full checker.
"""
from __future__ import annotations

import ast
from typing import Any


class TypeAnalyzer(ast.NodeVisitor):
    """Infer a simple type name for each ``ast`` node."""

    def __init__(self) -> None:
        self.types: dict[int, str] = {}
        self.env: dict[str, str] = {}

    def infer(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant):
            t = type(node.value).__name__
            self.types[id(node)] = t
            return t
        if isinstance(node, ast.List):
            self.types[id(node)] = "list"
            return "list"
        if isinstance(node, ast.Dict):
            self.types[id(node)] = "dict"
            return "dict"
        if isinstance(node, ast.Tuple):
            self.types[id(node)] = "tuple"
            return "tuple"
        if isinstance(node, ast.Set):
            self.types[id(node)] = "set"
            return "set"
        if isinstance(node, ast.Name):
            return self.env.get(node.id, "Any")
        if isinstance(node, ast.JoinedStr) or (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "str"):
            return "str"
        return "Any"

    def visit_Assign(self, node: ast.Assign) -> Any:
        inferred = self.infer(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self.env[tgt.id] = inferred
        self.generic_visit(node)

    def run(self, tree: ast.AST) -> dict[str, str]:
        self.visit(tree)
        return dict(self.env)
