"""Symbol and name resolution for Python modules.

Builds a scope tree (module → class → function → nested) and resolves
every ``ast.Name`` reference to its declaring symbol when possible. This
feeds both the taint engine (to track aliases) and the interprocedural
call graph builder.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Symbol:
    name: str
    kind: str  # "var", "func", "class", "import", "param"
    line: int = 0
    scope: Optional["Scope"] = None


@dataclass
class Scope:
    kind: str  # "module", "class", "function", "comprehension"
    name: str
    parent: Optional["Scope"] = None
    symbols: dict[str, Symbol] = field(default_factory=dict)
    children: list["Scope"] = field(default_factory=list)

    def define(self, sym: Symbol) -> None:
        sym.scope = self
        self.symbols[sym.name] = sym

    def resolve(self, name: str) -> Optional[Symbol]:
        if name in self.symbols:
            return self.symbols[name]
        if self.parent is not None:
            return self.parent.resolve(name)
        return None


class NameResolver(ast.NodeVisitor):
    """Build and expose the scope tree for a Python module."""

    def __init__(self) -> None:
        self.module = Scope(kind="module", name="<module>")
        self._stack: list[Scope] = [self.module]

    @property
    def current(self) -> Scope:
        return self._stack[-1]

    # ---- scope mgmt ---------------------------------------------------
    def _push(self, kind: str, name: str) -> Scope:
        child = Scope(kind=kind, name=name, parent=self.current)
        self.current.children.append(child)
        self._stack.append(child)
        return child

    def _pop(self) -> None:
        self._stack.pop()

    # ---- visitors -----------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.current.define(Symbol(node.name, "func", node.lineno))
        self._push("function", node.name)
        for arg in node.args.args:
            self.current.define(Symbol(arg.arg, "param", arg.lineno))
        for stmt in node.body:
            self.visit(stmt)
        self._pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.current.define(Symbol(node.name, "class", node.lineno))
        self._push("class", node.name)
        for stmt in node.body:
            self.visit(stmt)
        self._pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.current.define(Symbol(alias.asname or alias.name.split(".")[0], "import", node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.current.define(Symbol(alias.asname or alias.name, "import", node.lineno))

    def visit_Assign(self, node: ast.Assign) -> None:
        for tgt in node.targets:
            for n in ast.walk(tgt):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    self.current.define(Symbol(n.id, "var", n.lineno))
        self.generic_visit(node)

    def run(self, tree: ast.AST) -> Scope:
        self.visit(tree)
        return self.module
