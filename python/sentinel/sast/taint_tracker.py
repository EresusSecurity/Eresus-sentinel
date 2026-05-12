"""
SAST Taint Tracker.

Simplified taint analysis for tracking untrusted data flow
from sources (user input, network) to sinks (exec, eval, SQL).

All sources and sinks loaded from rules/taint_rules.yaml.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Location, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"
_DEFAULT_YAML = _RULES_DIR / "taint_rules.yaml"

# Cache
_source_cache: Optional[list] = None
_sink_cache: Optional[list] = None
_cache_mtime: float = 0.0


@dataclass
class TaintSource:
    """A source of untrusted data."""
    name: str
    pattern: re.Pattern
    description: str


@dataclass
class TaintSink:
    """A dangerous function that consumes data."""
    name: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    description: str


@dataclass
class TaintFlow:
    """A detected taint flow from source to sink."""
    source: str
    source_line: int
    sink: str
    sink_line: int
    file: str
    severity: Severity
    cwe: str


def _load_rules(path: Optional[Path] = None) -> tuple[list[TaintSource], list[TaintSink]]:
    """Load taint sources and sinks from YAML."""
    global _source_cache, _sink_cache, _cache_mtime

    yaml_path = path or _DEFAULT_YAML
    if not yaml_path.exists():
        logger.warning("Taint rules YAML not found: %s", yaml_path)
        return [], []

    mtime = yaml_path.stat().st_mtime
    if _source_cache is not None and _sink_cache is not None and mtime == _cache_mtime:
        return _source_cache, _sink_cache

    try:
        import yaml
    except ImportError:
        logger.error("PyYAML required for loading taint rules")
        return [], []

    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    sources: list[TaintSource] = []
    for _category, entries in data.get("sources", {}).items():
        for entry in entries:
            try:
                sources.append(TaintSource(
                    name=entry["name"],
                    pattern=re.compile(entry["pattern"]),
                    description=entry.get("description", ""),
                ))
            except Exception as exc:
                logger.warning("Skipping invalid taint source %s: %s", entry.get("name"), exc)

    sinks: list[TaintSink] = []
    for _category, entries in data.get("sinks", {}).items():
        for entry in entries:
            try:
                sinks.append(TaintSink(
                    name=entry["name"],
                    pattern=re.compile(entry["pattern"]),
                    severity=_SEVERITY_MAP.get(entry.get("severity", "MEDIUM"), Severity.MEDIUM),
                    cwe=entry.get("cwe", "CWE-20"),
                    description=entry.get("description", ""),
                ))
            except Exception as exc:
                logger.warning("Skipping invalid taint sink %s: %s", entry.get("name"), exc)

    _source_cache = sources
    _sink_cache = sinks
    _cache_mtime = mtime
    logger.info("Loaded %d sources + %d sinks from %s", len(sources), len(sinks), yaml_path.name)
    return sources, sinks


def reload_rules(path: Optional[Path] = None) -> tuple[int, int]:
    """Force reload rules from YAML. Returns (source_count, sink_count)."""
    global _source_cache, _sink_cache, _cache_mtime
    _source_cache = None
    _sink_cache = None
    _cache_mtime = 0.0
    sources, sinks = _load_rules(path)
    return len(sources), len(sinks)


class TaintTracker:
    """
    AST-based intra-file taint analysis.
    All sources and sinks loaded from rules/taint_rules.yaml.

    Uses Python AST to track variable assignments and detect cases where
    untrusted data sources flow to dangerous sinks through variable aliasing.
    Falls back to proximity-based analysis for non-Python files.

    Tracks:
    - Direct source→sink flows (e.g., eval(request.args.get(...)))
    - Variable aliasing (e.g., x = request.args.get(...); eval(x))
    - Attribute access chains (e.g., data = req.body; exec(data))
    - Function call results as tainted (e.g., x = input(); eval(x))

    Usage:
        tracker = TaintTracker()
        findings = tracker.scan_file("app.py")
        flows = tracker.get_flows("app.py")
    """

    PROXIMITY_WINDOW = 15  # Lines within which source→sink is flagged (fallback)

    def __init__(self, yaml_path: Optional[str] = None):
        path = Path(yaml_path) if yaml_path else None
        self._sources, self._sinks = _load_rules(path)

    @property
    def source_count(self) -> int:
        return len(self._sources)

    @property
    def sink_count(self) -> int:
        return len(self._sinks)

    def scan_file(self, path: str) -> list[Finding]:
        """Scan a file for taint flows."""
        flows = self.get_flows(path)
        findings = []

        for flow in flows:
            findings.append(Finding(
                rule_id="SAST-TAINT-001",
                module="sast.taint",
                title=f"Taint flow: {flow.source} → {flow.sink}",
                description=(
                    f"Untrusted data from '{flow.source}' (line {flow.source_line}) "
                    f"flows to '{flow.sink}' (line {flow.sink_line}) without sanitization."
                ),
                severity=flow.severity,
                confidence=0.7,
                target=flow.file,
                location=Location(file=flow.file, line_start=flow.sink_line),
                evidence=f"Source: {flow.source} (L{flow.source_line}) → Sink: {flow.sink} (L{flow.sink_line})",
                cwe_ids=[flow.cwe],
                tags=["category:taint-analysis"],
                remediation="Sanitize or validate input before passing to dangerous operations.",
            ))

        return findings

    def get_flows(self, path: str) -> list[TaintFlow]:
        """Detect taint flows in a single file using AST analysis.

        Falls back to proximity-based analysis if AST parsing fails.
        """
        fp = Path(path)
        if not fp.exists():
            return []

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
        except Exception:
            return []

        # Try AST-based analysis first
        try:
            import ast
            tree = ast.parse(source_code, filename=str(fp))
            flows = self._ast_taint_analysis(tree, source_code, str(fp))
            if flows is not None:
                return flows
        except SyntaxError:
            pass  # Fall back to proximity
        except Exception as e:
            logger.debug("AST analysis failed for %s: %s", path, e)

        # Fallback: proximity-based analysis
        return self._proximity_analysis(source_code.splitlines(True), str(fp))

    def _ast_taint_analysis(
        self, tree, source_code: str, filepath: str
    ) -> list[TaintFlow] | None:
        """AST-based taint analysis with variable tracking."""
        import ast

        source_code.splitlines()
        flows: list[TaintFlow] = []

        # Step 1: Find tainted variables by walking the AST
        # A variable is tainted if it's assigned from a source pattern
        tainted_vars: dict[str, tuple[int, str]] = {}  # var_name → (line, source_name)

        # func_name → True means "calling this returns tainted data"
        tainted_funcs: dict[str, tuple[int, str]] = {}

        class TaintVisitor(ast.NodeVisitor):
            def __init__(self, sources, sinks):
                self.sources = sources
                self.sinks = sinks

            def _get_source_text(self, node: ast.AST) -> str:
                try:
                    return ast.get_source_segment(source_code, node) or ast.dump(node)
                except Exception:
                    return ast.dump(node)

            def _check_is_source(self, node: ast.AST, line: int) -> Optional[str]:
                text = self._get_source_text(node)
                for source in self.sources:
                    if source.pattern.search(text):
                        return source.name
                return None

            def _check_is_sink(self, node: ast.AST, line: int) -> Optional[TaintSink]:
                text = self._get_source_text(node)
                for sink in self.sinks:
                    if sink.pattern.search(text):
                        return sink
                return None

            def _is_tainted_expr(self, node: ast.AST) -> Optional[tuple[int, str]]:
                """Recursively check if any sub-expression is tainted."""
                line = getattr(node, "lineno", 0)

                # Direct source
                src = self._check_is_source(node, line)
                if src:
                    return (line, src)

                # Name reference
                if isinstance(node, ast.Name) and node.id in tainted_vars:
                    return tainted_vars[node.id]

                # Attribute on tainted variable: obj.attr
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id in tainted_vars:
                        return tainted_vars[node.value.id]

                # Subscript: tainted[key]
                if isinstance(node, ast.Subscript):
                    if isinstance(node.value, ast.Name) and node.value.id in tainted_vars:
                        return tainted_vars[node.value.id]

                # f-string: f"...{tainted_var}..."  (JoinedStr)
                if isinstance(node, ast.JoinedStr):
                    for value in node.values:
                        if isinstance(value, ast.FormattedValue):
                            t = self._is_tainted_expr(value.value)
                            if t:
                                return t

                # str.format(): "...".format(tainted) or tainted.format(...)
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                        # "template".format(tainted_var)
                        for arg in node.args:
                            t = self._is_tainted_expr(arg)
                            if t:
                                return t
                        # tainted_var.format(...)
                        t = self._is_tainted_expr(node.func.value)
                        if t:
                            return t

                    # %-formatting: "..." % tainted
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    if isinstance(node.left, ast.Constant):
                        t = self._is_tainted_expr(node.right)
                        if t:
                            return t

                # Interprocedural: call to a function we know returns tainted data
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    if func_name and func_name in tainted_funcs:
                        return tainted_funcs[func_name]
                    # Also propagate if any argument is tainted (wrapping function)
                    for arg in node.args:
                        t = self._is_tainted_expr(arg)
                        if t:
                            return t

                # Tuple/list/set literal containing tainted element
                if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                    for elt in node.elts:
                        t = self._is_tainted_expr(elt)
                        if t:
                            return t

                # BoolOp/BinOp: tainted or clean → propagate taint
                if isinstance(node, ast.BoolOp):
                    for val in node.values:
                        t = self._is_tainted_expr(val)
                        if t:
                            return t

                if isinstance(node, ast.BinOp):
                    for side in (node.left, node.right):
                        t = self._is_tainted_expr(side)
                        if t:
                            return t

                # IfExp (ternary): a if cond else b
                if isinstance(node, ast.IfExp):
                    for n in (node.body, node.orelse):
                        t = self._is_tainted_expr(n)
                        if t:
                            return t

                return None

            def _assign_taint_to_targets(
                self, targets: list[ast.AST], taint_info: tuple[int, str]
            ) -> None:
                """Assign taint to one or more assignment targets, handling tuple unpacking."""
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted_vars[target.id] = taint_info
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        # a, b = tainted_call() → both a and b are tainted
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                tainted_vars[elt.id] = taint_info
                    elif isinstance(target, ast.Starred):
                        if isinstance(target.value, ast.Name):
                            tainted_vars[target.value.id] = taint_info

            def visit_Assign(self, node: ast.Assign):
                taint_info = self._is_tainted_expr(node.value)
                if taint_info:
                    self._assign_taint_to_targets(node.targets, taint_info)
                self.generic_visit(node)

            def visit_AugAssign(self, node: ast.AugAssign):
                """x += tainted → x is tainted."""
                taint_info = self._is_tainted_expr(node.value)
                if taint_info and isinstance(node.target, ast.Name):
                    tainted_vars[node.target.id] = taint_info
                # Also if the variable itself was already tainted
                elif isinstance(node.target, ast.Name) and node.target.id in tainted_vars:
                    pass  # stays tainted
                self.generic_visit(node)

            def visit_AnnAssign(self, node: ast.AnnAssign):
                """x: str = tainted_source()"""
                if node.value:
                    taint_info = self._is_tainted_expr(node.value)
                    if taint_info and isinstance(node.target, ast.Name):
                        tainted_vars[node.target.id] = taint_info
                self.generic_visit(node)

            def visit_NamedExpr(self, node: ast.NamedExpr):
                """Walrus operator: (x := tainted_source())"""
                taint_info = self._is_tainted_expr(node.value)
                if taint_info and isinstance(node.target, ast.Name):
                    tainted_vars[node.target.id] = taint_info
                self.generic_visit(node)

            def visit_For(self, node: ast.For):
                """for x in tainted_iter: → x is tainted."""
                taint_info = self._is_tainted_expr(node.iter)
                if taint_info:
                    self._assign_taint_to_targets([node.target], taint_info)
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef):
                """Track function return values: if a function returns tainted data, mark it."""
                # Check return statements for tainted values
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        taint_info = self._is_tainted_expr(child.value)
                        if taint_info:
                            tainted_funcs[node.name] = taint_info
                            break
                self.generic_visit(node)

            visit_AsyncFunctionDef = visit_FunctionDef

            def _emit_flow(self, sink: TaintSink, taint_info: tuple[int, str], sink_line: int) -> None:
                src_line, src_name = taint_info
                # Deduplicate by (source, source_line, sink, sink_line)
                key = (src_name, src_line, sink.name, sink_line)
                if not any(
                    (f.source == src_name and f.source_line == src_line
                     and f.sink == sink.name and f.sink_line == sink_line)
                    for f in flows
                ):
                    flows.append(TaintFlow(
                        source=src_name,
                        source_line=src_line,
                        sink=sink.name,
                        sink_line=sink_line,
                        file=filepath,
                        severity=sink.severity,
                        cwe=sink.cwe,
                    ))

            def visit_Call(self, node: ast.Call):
                sink = self._check_is_sink(node, node.lineno)
                if sink:
                    # Check positional args
                    for arg in node.args:
                        taint_info = self._is_tainted_expr(arg)
                        if taint_info:
                            self._emit_flow(sink, taint_info, node.lineno)
                    # Check keyword args
                    for kw in node.keywords:
                        if kw.value:
                            taint_info = self._is_tainted_expr(kw.value)
                            if taint_info:
                                self._emit_flow(sink, taint_info, node.lineno)

                # Indirect call: fn = eval; fn(tainted)
                if isinstance(node.func, ast.Name) and node.func.id in tainted_vars:
                    taint_src_line, taint_src_name = tainted_vars[node.func.id]
                    if any(kw in taint_src_name.lower() for kw in ["eval", "exec", "system", "popen"]):
                        for _arg in node.args:
                            flows.append(TaintFlow(
                                source=f"indirect:{taint_src_name}",
                                source_line=taint_src_line,
                                sink=f"indirect_call:{node.func.id}",
                                sink_line=node.lineno,
                                file=filepath,
                                severity=Severity.HIGH,
                                cwe="CWE-94",
                            ))

                self.generic_visit(node)

        visitor = TaintVisitor(self._sources, self._sinks)
        visitor.visit(tree)
        return flows

    def _proximity_analysis(self, lines: list[str], filepath: str) -> list[TaintFlow]:
        """Fallback proximity-based analysis for non-Python files."""
        source_locations: list[tuple[int, str]] = []
        sink_locations: list[tuple[int, TaintSink]] = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for source in self._sources:
                if source.pattern.search(stripped):
                    source_locations.append((line_num, source.name))

            for sink in self._sinks:
                if sink.pattern.search(stripped):
                    sink_locations.append((line_num, sink))

        flows = []
        for src_line, src_name in source_locations:
            for sink_line, sink in sink_locations:
                if sink_line > src_line and (sink_line - src_line) <= self.PROXIMITY_WINDOW:
                    flows.append(TaintFlow(
                        source=src_name,
                        source_line=src_line,
                        sink=sink.name,
                        sink_line=sink_line,
                        file=filepath,
                        severity=sink.severity,
                        cwe=sink.cwe,
                    ))

        return flows

    def scan_directory(self, path: str) -> list[Finding]:
        """Scan a directory for taint flows."""
        root = Path(path)
        findings = []
        skip_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv"}

        for fp in sorted(root.rglob("*.py")):
            if not any(skip in fp.parts for skip in skip_dirs):
                findings.extend(self.scan_file(str(fp)))

        return findings
