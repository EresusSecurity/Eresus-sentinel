"""
Eresus Sentinel — Inter-procedural (cross-file) Taint Analysis.

Builds a per-project call graph from Python AST nodes and propagates
taint across module boundaries.

Algorithm (two-pass):
  Pass 1 — Harvest:
    Walk every .py file and collect:
      • function definitions and their *return* taint status
      • module-level assignments that originate from taint sources
      • import mappings: which local name maps to which module.func

  Pass 2 — Propagate:
    Re-walk every file and, for any call whose callee is in the
    harvested tainted-function set, flag the calling site as a
    cross-file taint flow.

Limitations (known, acceptable for v1):
  - Does not resolve dynamic dispatch (obj.method calls where obj type
    is unknown require a type inference pass — out of scope).
  - __all__ re-exports are handled by name only (not by value type).
  - Does not follow *args/**kwargs forwarding into called functions.
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Location, Severity
from sentinel.sast.taint_tracker import TaintTracker, _load_rules

logger = logging.getLogger(__name__)

_SKIP_DIRS = {
    "__pycache__", ".git", ".svn", "node_modules",
    ".venv", "venv", "env", ".tox", "dist", "build",
}


@dataclass
class FunctionSig:
    """Lightweight function signature with taint metadata."""
    module_path: str       # absolute file path
    qualified_name: str    # e.g.  "mypackage.utils.get_user_data"
    local_name: str        # function name as defined in the file
    is_tainted: bool       # True if any return path returns tainted data
    taint_source: str      # originating source name (for reporting)
    taint_line: int        # line in source file where taint originates


@dataclass
class CrossFileTaintFlow:
    """A taint flow that crosses a module boundary."""
    caller_file: str
    caller_line: int
    caller_func: str        # local name of the called function
    callee_file: str
    callee_func: str        # qualified callee name
    taint_source: str
    taint_source_line: int
    sink_name: str
    severity: Severity
    cwe: str


class InterproceduralAnalyzer:
    """
    Cross-file taint analysis for Python projects.

    Usage:
        analyzer = InterproceduralAnalyzer()
        findings = analyzer.scan_project("/path/to/project")
    """

    def __init__(self, yaml_path: Optional[str] = None):
        self._tracker = TaintTracker(yaml_path)
        self._sources, self._sinks = _load_rules(
            Path(yaml_path) if yaml_path else None
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def scan_project(self, root: str) -> list[Finding]:
        """Full inter-procedural scan of a Python project tree."""
        py_files = self._collect_py_files(root)
        if not py_files:
            return []

        logger.debug("InterproceduralAnalyzer: harvesting %d files", len(py_files))
        tainted_funcs = self._harvest_tainted_functions(py_files)
        logger.debug(
            "InterproceduralAnalyzer: found %d tainted function signatures",
            len(tainted_funcs),
        )

        flows = self._propagate(py_files, tainted_funcs)
        return [self._flow_to_finding(f) for f in flows]

    # ------------------------------------------------------------------ #
    #  Pass 1 — Harvest                                                   #
    # ------------------------------------------------------------------ #

    def _harvest_tainted_functions(
        self, files: list[Path]
    ) -> dict[str, FunctionSig]:
        """
        Walk all files and record functions that return tainted data.

        Returns a dict keyed by local function name (not qualified, to keep
        lookup O(1) without a full type-inference pass).
        """
        result: dict[str, FunctionSig] = {}

        for fp in files:
            try:
                source = fp.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(fp))
            except (SyntaxError, OSError):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                taint_info = self._check_return_taint(node, source)
                if taint_info:
                    sig = FunctionSig(
                        module_path=str(fp),
                        qualified_name=f"{fp.stem}.{node.name}",
                        local_name=node.name,
                        is_tainted=True,
                        taint_source=taint_info[1],
                        taint_line=taint_info[0],
                    )
                    result[node.name] = sig

        return result

    def _check_return_taint(
        self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, source: str
    ) -> Optional[tuple[int, str]]:
        """Return (line, source_name) if any return statement yields tainted data."""
        for child in ast.walk(func_node):
            if not isinstance(child, ast.Return) or child.value is None:
                continue
            text = self._node_text(child.value, source)
            for src in self._sources:
                if src.pattern.search(text):
                    return (getattr(child, "lineno", 0), src.name)
        return None

    # ------------------------------------------------------------------ #
    #  Pass 2 — Propagate                                                 #
    # ------------------------------------------------------------------ #

    def _propagate(
        self,
        files: list[Path],
        tainted_funcs: dict[str, FunctionSig],
    ) -> list[CrossFileTaintFlow]:
        """
        Walk every file again; when a call to a tainted function is passed
        directly to a sink (or its result is assigned and later passed to
        a sink), emit a CrossFileTaintFlow.
        """
        flows: list[CrossFileTaintFlow] = []

        for fp in files:
            try:
                source = fp.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(fp))
            except (SyntaxError, OSError):
                continue

            flows.extend(self._scan_file_for_cross_flows(tree, source, fp, tainted_funcs))

        return flows

    def _scan_file_for_cross_flows(
        self,
        tree: ast.AST,
        source: str,
        fp: Path,
        tainted_funcs: dict[str, FunctionSig],
    ) -> list[CrossFileTaintFlow]:
        flows: list[CrossFileTaintFlow] = []
        # var → (line, sig) — variables holding the result of a tainted call
        tainted_locals: dict[str, tuple[int, FunctionSig]] = {}

        class Visitor(ast.NodeVisitor):
            def visit_Assign(self_, node: ast.Assign):
                if isinstance(node.value, ast.Call):
                    sig = self._call_to_sig(node.value, tainted_funcs)
                    if sig:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted_locals[target.id] = (node.lineno, sig)
                self_.generic_visit(node)

            def visit_AnnAssign(self_, node: ast.AnnAssign):
                if node.value and isinstance(node.value, ast.Call):
                    sig = self._call_to_sig(node.value, tainted_funcs)
                    if sig and isinstance(node.target, ast.Name):
                        tainted_locals[node.target.id] = (node.lineno, sig)
                self_.generic_visit(node)

            def visit_Call(self_, node: ast.Call):
                sink = self._check_is_sink_node(node, source)
                if not sink:
                    self_.generic_visit(node)
                    return

                # Direct: sink(tainted_func())
                if isinstance(node.func, ast.Name):
                    for arg in node.args:
                        if isinstance(arg, ast.Call):
                            sig = self._call_to_sig(arg, tainted_funcs)
                            if sig and sig.module_path != str(fp):
                                flows.append(CrossFileTaintFlow(
                                    caller_file=str(fp),
                                    caller_line=node.lineno,
                                    caller_func=node.func.id,
                                    callee_file=sig.module_path,
                                    callee_func=sig.qualified_name,
                                    taint_source=sig.taint_source,
                                    taint_source_line=sig.taint_line,
                                    sink_name=sink.name,
                                    severity=sink.severity,
                                    cwe=sink.cwe,
                                ))
                        # Indirect via local variable
                        elif isinstance(arg, ast.Name) and arg.id in tainted_locals:
                            _, sig = tainted_locals[arg.id]
                            if sig.module_path != str(fp):
                                flows.append(CrossFileTaintFlow(
                                    caller_file=str(fp),
                                    caller_line=node.lineno,
                                    caller_func=node.func.id,
                                    callee_file=sig.module_path,
                                    callee_func=sig.qualified_name,
                                    taint_source=sig.taint_source,
                                    taint_source_line=sig.taint_line,
                                    sink_name=sink.name,
                                    severity=sink.severity,
                                    cwe=sink.cwe,
                                ))
                self_.generic_visit(node)

        Visitor().visit(tree)
        return flows

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _call_to_sig(
        self, node: ast.Call, tainted_funcs: dict[str, FunctionSig]
    ) -> Optional[FunctionSig]:
        """Return the FunctionSig if the call target is a known tainted function."""
        if isinstance(node.func, ast.Name):
            return tainted_funcs.get(node.func.id)
        if isinstance(node.func, ast.Attribute):
            return tainted_funcs.get(node.func.attr)
        return None

    def _check_is_sink_node(self, node: ast.Call, source: str):
        """Return TaintSink if this call node matches a registered sink."""
        text = self._node_text(node, source)
        for sink in self._sinks:
            if sink.pattern.search(text):
                return sink
        return None

    @staticmethod
    def _node_text(node: ast.AST, source: str) -> str:
        try:
            return ast.get_source_segment(source, node) or ast.dump(node)
        except Exception:
            return ast.dump(node)

    @staticmethod
    def _collect_py_files(root: str) -> list[Path]:
        result: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".py"):
                    result.append(Path(dirpath) / fn)
        return result

    def _flow_to_finding(self, flow: CrossFileTaintFlow) -> Finding:
        return Finding(
            rule_id="SAST-XFILE-TAINT-001",
            module="sast.interprocedural",
            title=f"Cross-file taint: {flow.callee_func} → {flow.sink_name}",
            description=(
                f"Function '{flow.callee_func}' defined in '{flow.callee_file}' "
                f"returns untrusted data (source: '{flow.taint_source}', "
                f"line {flow.taint_source_line}). "
                f"Its return value flows to sink '{flow.sink_name}' "
                f"at {flow.caller_file}:{flow.caller_line}."
            ),
            severity=flow.severity,
            confidence=0.75,
            target=flow.caller_file,
            location=Location(
                file=flow.caller_file,
                line_start=flow.caller_line,
            ),
            evidence=(
                f"callee={flow.callee_func} in {os.path.basename(flow.callee_file)}, "
                f"sink={flow.sink_name}, taint_src={flow.taint_source}"
            ),
            cwe_ids=[flow.cwe],
            tags=["category:interprocedural-taint", "sast:cross-file"],
            remediation=(
                "Sanitize or validate the return value of the called function "
                "before passing it to the dangerous sink."
            ),
        )
