"""Dependency graph builder for AIBOM components."""
from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.aibom.models import AIBOMResult, AIComponent


@dataclass
class GraphNode:
    component: AIComponent
    in_edges: list[str] = field(default_factory=list)
    out_edges: list[str] = field(default_factory=list)


class DepGraph:
    """Directed acyclic graph of component dependencies."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}

    def build(self, result: AIBOMResult) -> DepGraph:
        for comp in result.components:
            self._nodes[comp.id] = GraphNode(component=comp)
        for rel in result.relationships:
            if rel.source_id in self._nodes and rel.target_id in self._nodes:
                self._nodes[rel.source_id].out_edges.append(rel.target_id)
                self._nodes[rel.target_id].in_edges.append(rel.source_id)
        return self

    def roots(self) -> list[AIComponent]:
        return [n.component for n in self._nodes.values() if not n.in_edges]

    def leaves(self) -> list[AIComponent]:
        return [n.component for n in self._nodes.values() if not n.out_edges]

    def dependents(self, component_id: str) -> list[AIComponent]:
        node = self._nodes.get(component_id)
        if not node:
            return []
        return [self._nodes[cid].component for cid in node.in_edges if cid in self._nodes]

    def dependencies(self, component_id: str) -> list[AIComponent]:
        node = self._nodes.get(component_id)
        if not node:
            return []
        return [self._nodes[cid].component for cid in node.out_edges if cid in self._nodes]

    def topological_sort(self) -> list[AIComponent]:
        visited: set[str] = set()
        order: list[AIComponent] = []

        def _visit(cid: str) -> None:
            if cid in visited or cid not in self._nodes:
                return
            visited.add(cid)
            for dep in self._nodes[cid].out_edges:
                _visit(dep)
            order.append(self._nodes[cid].component)

        for cid in self._nodes:
            _visit(cid)
        return list(reversed(order))

    def detect_cycles(self) -> list[list[str]]:
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {cid: WHITE for cid in self._nodes}
        cycles: list[list[str]] = []
        path: list[str] = []

        def _dfs(cid: str) -> None:
            color[cid] = GRAY
            path.append(cid)
            for dep in self._nodes[cid].out_edges:
                if dep not in color:
                    continue
                if color[dep] == GRAY:
                    idx = path.index(dep)
                    cycles.append(path[idx:] + [dep])
                elif color[dep] == WHITE:
                    _dfs(dep)
            path.pop()
            color[cid] = BLACK

        for cid in self._nodes:
            if color.get(cid) == WHITE:
                _dfs(cid)
        return cycles

    @property
    def size(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return sum(len(n.out_edges) for n in self._nodes.values())
