"""Cross-file analyzer.

Builds a module index from a directory tree, maps ``from X import Y``
statements to the defining module, and exposes a symbol lookup so the
taint engine can follow function calls into other files.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.sast.static_analysis.parser.python_parser import PythonParser


@dataclass
class ModuleInfo:
    path: str
    name: str
    tree: Optional[ast.AST] = None
    imports: dict[str, str] = field(default_factory=dict)  # local_name -> module
    symbols: dict[str, ast.AST] = field(default_factory=dict)


@dataclass
class ModuleIndex:
    modules: dict[str, ModuleInfo] = field(default_factory=dict)

    def lookup(self, fqname: str) -> Optional[ast.AST]:
        """Return the AST node for a fully-qualified name like ``pkg.mod.fn``."""
        if "." not in fqname:
            for m in self.modules.values():
                if fqname in m.symbols:
                    return m.symbols[fqname]
            return None
        mod, _, sym = fqname.rpartition(".")
        m = self.modules.get(mod)
        return m.symbols.get(sym) if m else None


class CrossFileAnalyzer:
    """Walk a directory and build a :class:`ModuleIndex`."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.parser = PythonParser()

    def build(self) -> ModuleIndex:
        idx = ModuleIndex()
        for py in self.root.rglob("*.py"):
            unit = self.parser.parse_file(py)
            if not unit.ok or unit.tree is None:
                continue
            mod_name = self._module_name(py)
            info = ModuleInfo(path=str(py), name=mod_name, tree=unit.tree)
            self._collect(info, unit.tree)
            idx.modules[mod_name] = info
        return idx

    def _module_name(self, path: Path) -> str:
        rel = path.relative_to(self.root)
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) if parts else path.stem

    @staticmethod
    def _collect(info: ModuleInfo, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    info.imports[alias.asname or alias.name] = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    info.imports[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                info.symbols[node.name] = node
