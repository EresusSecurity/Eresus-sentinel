"""Lightweight code-quality inventory helpers for CI smoke checks."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImportEdge:
    importer: str
    imported: str


@dataclass(frozen=True)
class DeadCodeCandidate:
    module: str
    name: str
    line: int


def module_name_for(root: Path, path: Path, package: str = "sentinel") -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = rel.parts
    if parts and parts[0] == package:
        return ".".join(parts)
    return ".".join((package, *parts))


def collect_import_edges(root: Path, package: str = "sentinel") -> list[ImportEdge]:
    """Collect local import edges without importing project modules."""
    edges: list[ImportEdge] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        importer = module_name_for(root, path, package)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == package or alias.name.startswith(f"{package}."):
                        edges.append(ImportEdge(importer, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module == package or node.module.startswith(f"{package}."):
                    edges.append(ImportEdge(importer, node.module))
    return edges


def find_direct_import_cycles(edges: list[ImportEdge]) -> list[tuple[str, str]]:
    """Find two-node import cycles in an edge list."""
    edge_set = {(edge.importer, edge.imported) for edge in edges}
    cycles: set[tuple[str, str]] = set()
    for importer, imported in edge_set:
        if (imported, importer) in edge_set:
            cycles.add(tuple(sorted((importer, imported))))
    return sorted(cycles)


def dead_code_candidates(root: Path, package: str = "sentinel") -> list[DeadCodeCandidate]:
    """Return a conservative inventory of private top-level defs with no local references."""
    definitions: list[DeadCodeCandidate] = []
    references: set[str] = set()

    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except SyntaxError:
            continue
        module = module_name_for(root, path, package)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                references.add(node.id)
            elif isinstance(node, ast.Attribute):
                references.add(node.attr)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name.startswith("_") and not node.name.startswith("__"):
                    definitions.append(DeadCodeCandidate(module, node.name, node.lineno))

    return [candidate for candidate in definitions if candidate.name not in references]
