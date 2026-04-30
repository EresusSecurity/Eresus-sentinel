"""Control-flow graph builder over Python ``ast``.

A :class:`CFG` is constructed per function (or module top level). Nodes are
:class:`BasicBlock` objects (linear sequences of statements terminated by a
branch, return, raise, or loop edge). Edges carry a kind: fall-through,
branch-true/false, loop-back, exception, or return.

The builder is intentionally conservative: unknown node types produce a
single fall-through edge. This keeps downstream dataflow analyses sound.
"""
from __future__ import annotations

import ast
import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EdgeKind(str, Enum):
    FALL = "fall"
    BRANCH_TRUE = "branch_true"
    BRANCH_FALSE = "branch_false"
    LOOP_BACK = "loop_back"
    EXCEPTION = "exception"
    RETURN = "return"
    RAISE = "raise"
    CALL = "call"


@dataclass
class Edge:
    src: int
    dst: int
    kind: EdgeKind = EdgeKind.FALL
    label: str = ""


@dataclass
class BasicBlock:
    bid: int
    statements: list[ast.AST] = field(default_factory=list)
    label: str = ""

    @property
    def first_line(self) -> Optional[int]:
        for s in self.statements:
            if hasattr(s, "lineno"):
                return s.lineno
        return None

    @property
    def last_line(self) -> Optional[int]:
        for s in reversed(self.statements):
            if hasattr(s, "lineno"):
                return s.lineno
        return None


@dataclass
class CFG:
    name: str
    entry: int
    exit: int
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def successors(self, bid: int) -> list[int]:
        return [e.dst for e in self.edges if e.src == bid]

    def predecessors(self, bid: int) -> list[int]:
        return [e.src for e in self.edges if e.dst == bid]

    def reachable(self) -> set[int]:
        seen: set[int] = set()
        stack = [self.entry]
        while stack:
            b = stack.pop()
            if b in seen:
                continue
            seen.add(b)
            stack.extend(self.successors(b))
        return seen


class CFGBuilder:
    """Build per-function CFGs from a parsed Python module."""

    def __init__(self) -> None:
        self._ids = itertools.count()

    # ---- public -------------------------------------------------------
    def build_module(self, tree: ast.Module, name: str = "<module>") -> list[CFG]:
        graphs: list[CFG] = []
        # Module-level statements form a single CFG named <module>.
        graphs.append(self._build(tree.body, name=name))
        # Each function definition produces an additional CFG.
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                graphs.append(self._build(node.body, name=node.name))
        return graphs

    def build_function(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> CFG:
        return self._build(fn.body, name=fn.name)

    # ---- core ---------------------------------------------------------
    def _build(self, body: list[ast.stmt], name: str) -> CFG:
        self._ids = itertools.count()
        entry_id = next(self._ids)
        exit_id = next(self._ids)
        cfg = CFG(
            name=name,
            entry=entry_id,
            exit=exit_id,
            blocks={
                entry_id: BasicBlock(entry_id, label="entry"),
                exit_id: BasicBlock(exit_id, label="exit"),
            },
        )
        last = self._emit_sequence(cfg, body, entry_id, exit_id)
        if last is not None:
            cfg.edges.append(Edge(last, exit_id, EdgeKind.FALL))
        return cfg

    def _new_block(self, cfg: CFG, label: str = "") -> int:
        bid = next(self._ids)
        cfg.blocks[bid] = BasicBlock(bid, label=label)
        return bid

    def _emit_sequence(
        self,
        cfg: CFG,
        stmts: list[ast.stmt],
        current: int,
        exit_id: int,
    ) -> Optional[int]:
        """Emit a linear sequence of statements. Returns the trailing block
        or ``None`` if control flow does not fall through (e.g. return)."""
        for stmt in stmts:
            if current is None:
                # Dead code: create a new orphan block for source fidelity.
                current = self._new_block(cfg, label="unreachable")
            current = self._emit_stmt(cfg, stmt, current, exit_id)
        return current

    def _emit_stmt(
        self,
        cfg: CFG,
        stmt: ast.stmt,
        current: int,
        exit_id: int,
    ) -> Optional[int]:
        if isinstance(stmt, ast.If):
            return self._emit_if(cfg, stmt, current, exit_id)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self._emit_for(cfg, stmt, current, exit_id)
        if isinstance(stmt, ast.While):
            return self._emit_while(cfg, stmt, current, exit_id)
        if isinstance(stmt, ast.Try):
            return self._emit_try(cfg, stmt, current, exit_id)
        if isinstance(stmt, ast.Return):
            cfg.blocks[current].statements.append(stmt)
            cfg.edges.append(Edge(current, exit_id, EdgeKind.RETURN))
            return None
        if isinstance(stmt, ast.Raise):
            cfg.blocks[current].statements.append(stmt)
            cfg.edges.append(Edge(current, exit_id, EdgeKind.RAISE))
            return None
        # Regular statement: append to current block.
        cfg.blocks[current].statements.append(stmt)
        return current

    def _emit_if(self, cfg: CFG, stmt: ast.If, current: int, exit_id: int) -> Optional[int]:
        cfg.blocks[current].statements.append(stmt.test)
        then_id = self._new_block(cfg, "if_true")
        else_id = self._new_block(cfg, "if_false")
        join_id = self._new_block(cfg, "if_join")
        cfg.edges.append(Edge(current, then_id, EdgeKind.BRANCH_TRUE))
        cfg.edges.append(Edge(current, else_id, EdgeKind.BRANCH_FALSE))
        then_end = self._emit_sequence(cfg, stmt.body, then_id, exit_id)
        else_end = self._emit_sequence(cfg, stmt.orelse, else_id, exit_id)
        if then_end is not None:
            cfg.edges.append(Edge(then_end, join_id, EdgeKind.FALL))
        if else_end is not None:
            cfg.edges.append(Edge(else_end, join_id, EdgeKind.FALL))
        return join_id

    def _emit_while(self, cfg: CFG, stmt: ast.While, current: int, exit_id: int) -> Optional[int]:
        header = self._new_block(cfg, "while_head")
        body = self._new_block(cfg, "while_body")
        after = self._new_block(cfg, "while_after")
        cfg.edges.append(Edge(current, header, EdgeKind.FALL))
        cfg.blocks[header].statements.append(stmt.test)
        cfg.edges.append(Edge(header, body, EdgeKind.BRANCH_TRUE))
        cfg.edges.append(Edge(header, after, EdgeKind.BRANCH_FALSE))
        body_end = self._emit_sequence(cfg, stmt.body, body, exit_id)
        if body_end is not None:
            cfg.edges.append(Edge(body_end, header, EdgeKind.LOOP_BACK))
        return after

    def _emit_for(self, cfg: CFG, stmt: ast.For | ast.AsyncFor, current: int, exit_id: int) -> Optional[int]:
        header = self._new_block(cfg, "for_head")
        body = self._new_block(cfg, "for_body")
        after = self._new_block(cfg, "for_after")
        cfg.edges.append(Edge(current, header, EdgeKind.FALL))
        cfg.blocks[header].statements.extend([stmt.target, stmt.iter])
        cfg.edges.append(Edge(header, body, EdgeKind.BRANCH_TRUE))
        cfg.edges.append(Edge(header, after, EdgeKind.BRANCH_FALSE))
        body_end = self._emit_sequence(cfg, stmt.body, body, exit_id)
        if body_end is not None:
            cfg.edges.append(Edge(body_end, header, EdgeKind.LOOP_BACK))
        return after

    def _emit_try(self, cfg: CFG, stmt: ast.Try, current: int, exit_id: int) -> Optional[int]:
        try_block = self._new_block(cfg, "try")
        after = self._new_block(cfg, "try_after")
        cfg.edges.append(Edge(current, try_block, EdgeKind.FALL))
        try_end = self._emit_sequence(cfg, stmt.body, try_block, exit_id)
        if try_end is not None:
            cfg.edges.append(Edge(try_end, after, EdgeKind.FALL))
        for handler in stmt.handlers:
            hb = self._new_block(cfg, "except")
            cfg.edges.append(Edge(try_block, hb, EdgeKind.EXCEPTION))
            h_end = self._emit_sequence(cfg, handler.body, hb, exit_id)
            if h_end is not None:
                cfg.edges.append(Edge(h_end, after, EdgeKind.FALL))
        if stmt.finalbody:
            self._emit_sequence(cfg, stmt.finalbody, after, exit_id)
        return after
