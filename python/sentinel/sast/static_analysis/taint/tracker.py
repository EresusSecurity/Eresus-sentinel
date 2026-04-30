"""Unified taint engine (CFG-aware).

High-level algorithm:

1. Build a CFG per function.
2. For every assignment, mark the LHS variable as tainted if the RHS
   contains a matching source pattern.
3. Run a forward dataflow over variable names; at any sink call whose
   arguments contain a tainted name, emit a :class:`Finding`.
4. Path-sensitivity is approximate: branches are joined via set-union.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional, Set

from sentinel.finding import Finding, Location
from sentinel.sast.static_analysis.cfg.builder import CFG, CFGBuilder
from sentinel.sast.static_analysis.dataflow.forward_analysis import ForwardAnalysis
from sentinel.sast.static_analysis.taint.patterns import (
    SinkPattern,
    SourcePattern,
    default_sinks,
    default_sources,
)


@dataclass
class TaintFlow:
    source: str
    sink: str
    path: list[int] = field(default_factory=list)
    line: int = 0


@dataclass
class TaintResult:
    findings: list[Finding] = field(default_factory=list)
    flows: list[TaintFlow] = field(default_factory=list)


class _TaintVarAnalysis(ForwardAnalysis[Set[str]]):
    def __init__(self, sources: list[SourcePattern]) -> None:
        self.sources = sources

    def initial(self, cfg: CFG) -> Set[str]:
        return set()

    def bottom(self, cfg: CFG) -> Set[str]:
        return set()

    def meet(self, a: Set[str], b: Set[str]) -> Set[str]:
        return a | b

    def transfer(self, cfg: CFG, bid: int, inp: Set[str]) -> Set[str]:
        out = set(inp)
        for stmt in cfg.blocks[bid].statements:
            if not isinstance(stmt, (ast.Assign, ast.AugAssign)):
                continue
            rhs_src = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
            tainted = any(p.pattern.search(rhs_src) for p in self.sources) or self._rhs_uses(stmt, out)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            if tainted:
                out.update(names)
            else:
                for n in names:
                    out.discard(n)
        return out

    @staticmethod
    def _rhs_uses(stmt: ast.AST, tainted: Set[str]) -> bool:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Name) and n.id in tainted and isinstance(n.ctx, ast.Load):
                return True
        return False


class TaintEngine:
    """Public entrypoint. Combines CFG, dataflow, and sink detection."""

    def __init__(
        self,
        sources: Optional[list[SourcePattern]] = None,
        sinks: Optional[list[SinkPattern]] = None,
    ) -> None:
        self.sources = sources or default_sources()
        self.sinks = sinks or default_sinks()

    def analyze(self, tree: ast.AST, filename: str = "<string>") -> TaintResult:
        result = TaintResult()
        builder = CFGBuilder()
        cfgs = builder.build_module(tree, name=filename) if isinstance(tree, ast.Module) else []
        analysis = _TaintVarAnalysis(self.sources)
        for cfg in cfgs:
            df = analysis.run(cfg)
            for bid, tainted in df.outputs.items():
                for stmt in cfg.blocks[bid].statements:
                    for call in self._calls_in(stmt):
                        for sink in self.sinks:
                            if sink.pattern.search(self._call_text(call)):
                                args_tainted = self._args_use(call, tainted)
                                if args_tainted:
                                    result.findings.append(
                                        self._make_finding(call, sink, filename)
                                    )
                                    result.flows.append(
                                        TaintFlow(
                                            source="|".join(sorted(args_tainted)),
                                            sink=sink.name,
                                            path=[bid],
                                            line=getattr(call, "lineno", 0),
                                        )
                                    )
        return result

    # ---- helpers ------------------------------------------------------
    @staticmethod
    def _calls_in(stmt: ast.AST) -> list[ast.Call]:
        return [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]

    @staticmethod
    def _call_text(call: ast.Call) -> str:
        try:
            return ast.unparse(call)
        except Exception:
            return ""

    @staticmethod
    def _args_use(call: ast.Call, tainted: Set[str]) -> Set[str]:
        used: Set[str] = set()
        for arg in list(call.args) + [kw.value for kw in call.keywords]:
            for n in ast.walk(arg):
                if isinstance(n, ast.Name) and n.id in tainted:
                    used.add(n.id)
        return used

    @staticmethod
    def _make_finding(call: ast.Call, sink: SinkPattern, filename: str) -> Finding:
        return Finding.sast(
            rule_id=f"SAST-TAINT-{sink.name.upper().replace('.', '-')}",
            title=f"Tainted data reaches {sink.name}",
            description=(
                f"Untrusted data flows to '{sink.name}'. "
                f"{sink.description or ''}"
            ),
            severity=sink.severity,
            target=filename,
            evidence=TaintEngine._call_text(call),
            location=Location(file=filename, line_start=getattr(call, "lineno", None)),
            cwe_ids=[sink.cwe] if sink.cwe else [],
        )
