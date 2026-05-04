"""
Eresus Sentinel — SAST Analyzer.

Line-level rules are loaded from rules/sast_rules.yaml. Cross-file taint checks
use a conservative built-in flow model for user-input helpers and unsafe sinks.
"""

import ast
import json
import os
from pathlib import Path
from typing import List, Optional

from ..finding import Finding, Location, Severity
from ..rules import load_sast_rules

# Severity mapping
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_FP_RISK_CONFIDENCE = {
    "LOW": 0.95,
    "MEDIUM": 0.75,
    "HIGH": 0.55,
}

# File extensions to scan
SCANNABLE_EXTENSIONS = {".py", ".pyi", ".pyw", ".ipynb"}

# Directories to skip
SKIP_DIRS = {
    "__pycache__", ".git", ".svn", "node_modules",
    ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", "dist", "build", "egg-info",
}


class SASTAnalyzer:
    """Static analysis for LLM application code — all rules from YAML."""

    def __init__(self, rules_override: Optional[List] = None):
        """Initialize with YAML rules or an override list."""
        if rules_override is not None:
            self._rules = rules_override
        else:
            try:
                self._rules = load_sast_rules()
            except FileNotFoundError:
                self._rules = []

    def scan_path(self, path: str) -> List[Finding]:
        """Scan a file or directory."""
        p = Path(path)
        if p.is_file():
            return self._scan_file(p)
        elif p.is_dir():
            return self._scan_directory(p)
        return []

    def _scan_directory(self, directory: Path) -> List[Finding]:
        """Recursively scan a directory."""
        findings = []
        source_files: list[Path] = []
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for f in files:
                fp = Path(root) / f
                if fp.suffix in SCANNABLE_EXTENSIONS:
                    if fp.suffix != ".ipynb":
                        source_files.append(fp)
                    findings.extend(self._scan_file(fp))
        findings.extend(self._scan_cross_file_taint(directory, source_files))
        return findings

    def _scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single file against all YAML rules."""
        if filepath.suffix == ".ipynb":
            return self._scan_notebook(filepath)
        return self._scan_source(filepath)

    def _scan_source(self, filepath: Path) -> List[Finding]:
        """Scan a plain source file."""
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            findings.extend(self._match_line(stripped, line_num, filepath))

        return findings

    def _scan_notebook(self, filepath: Path) -> List[Finding]:
        """Parse .ipynb and scan only code cells, skipping markdown/output/metadata."""
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                nb = json.load(f)
        except (json.JSONDecodeError, Exception):
            return findings

        cells = nb.get("cells", [])
        line_offset = 0
        for cell in cells:
            cell_type = cell.get("cell_type", "")
            source_lines = cell.get("source", [])

            if cell_type != "code":
                line_offset += len(source_lines)
                continue

            for i, line in enumerate(source_lines):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                cell_line = line_offset + i + 1
                findings.extend(self._match_line(stripped, cell_line, filepath, is_notebook=True))

            line_offset += len(source_lines)

        return findings

    @staticmethod
    def _match_is_in_string(line: str, match_pos: int) -> bool:
        """Check if a regex match position falls inside a string literal."""
        in_single = False
        in_double = False
        i = 0
        while i < match_pos and i < len(line):
            ch = line[i]
            if ch == '\\':
                i += 2  # skip escaped char
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            i += 1
        return in_single or in_double

    def _match_line(self, stripped: str, line_num: int, filepath: Path, is_notebook: bool = False) -> List[Finding]:
        """Match a single line against all rules, respecting fp_risk. Collect all matches, keep highest severity."""
        findings = []
        for rule in self._rules:
            m = rule["pattern"].search(stripped)
            if m and not self._match_is_in_string(stripped, m.start()):
                # Skip safe eval variants (ast.literal_eval, pd.eval, etc.)
                m.group(0)
                rule_id = rule["id"]
                if rule_id == "SAST-020" and self._is_safe_eval(stripped, m):
                    continue

                # Apply exclude_value_patterns: if the matched text or the
                # full line matches any exclusion pattern, suppress the finding
                matched_text = m.group(0)
                excl_pats = rule.get("exclude_value_patterns", [])
                if excl_pats and any(
                    ep.search(matched_text) or ep.search(stripped)
                    for ep in excl_pats
                ):
                    continue

                severity = _SEVERITY_MAP.get(rule["severity"], Severity.MEDIUM)
                fp_risk = rule.get("fp_risk", "LOW")
                confidence = _FP_RISK_CONFIDENCE.get(fp_risk, 0.95)
                if is_notebook:
                    confidence = max(0.3, confidence - 0.15)

                findings.append(Finding(
                    rule_id=rule["id"],
                    module="sast",
                    title=rule["name"],
                    description=rule["description"],
                    severity=severity,
                    confidence=confidence,
                    target=str(filepath),
                    location=Location(
                        file=str(filepath),
                        line_start=line_num,
                    ),
                    evidence=stripped[:200],
                    cwe_ids=rule.get("cwe_ids", []),
                    remediation=rule.get("fix_hint", ""),
                    tags=rule.get("references", []),
                ))

        # Deduplicate: if multiple rules fired, keep distinct rule_ids
        # Sort by severity (most severe first) for reporting
        findings.sort(key=lambda f: f.severity.sort_key)
        return findings

    @staticmethod
    def _is_safe_eval(line: str, match) -> bool:
        """Check if an eval/exec match is a known-safe variant."""
        # Look backwards from match position for safe prefixes
        prefix = line[:match.start()].rstrip()
        safe_prefixes = [
            "ast.literal_eval",
            "literal_eval",
            "pd.eval",
            "df.eval",
            "DataFrame.eval",
            "np.safe_eval",
        ]
        for sp in safe_prefixes:
            if prefix.endswith(sp.rsplit("(", 1)[0].rstrip()):
                return True
            # Also check if the full match context contains it
            ctx = line[max(0, match.start() - 30):match.end()]
            if sp.split("(")[0] in ctx:
                return True
        return False

    # ─── Cross-file taint tracker ─────────────────────────────

    _SINK_NAMES = {"eval", "exec", "compile"}
    _SINK_ATTRS = {
        "pickle.loads",
        "pickle.load",
        "yaml.load",
        "joblib.load",
        "marshal.loads",
    }

    def _scan_cross_file_taint(self, root: Path, source_files: list[Path]) -> list[Finding]:
        """Conservatively flag imported user-input helpers flowing into code/deser sinks."""
        parsed: dict[Path, tuple[str, ast.AST]] = {}
        source_by_module: dict[str, dict[str, tuple[Path, int]]] = {}

        for fp in source_files:
            try:
                source = fp.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
            except (SyntaxError, OSError):
                continue

            parsed[fp] = (source, tree)
            module_names = self._module_names(root, fp)
            tainted_functions = self._collect_tainted_source_functions(fp, tree)
            if not tainted_functions:
                continue
            for module_name in module_names:
                source_by_module[module_name] = tainted_functions

        if not source_by_module:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for fp, (source, tree) in parsed.items():
            imported_sources = self._collect_imported_taint_sources(tree, source_by_module)
            module_aliases = self._collect_tainted_module_aliases(tree, source_by_module)
            if not imported_sources and not module_aliases:
                continue
            findings.extend(
                self._find_cross_file_sinks(fp, source, tree, imported_sources, module_aliases, seen)
            )
        return findings

    @staticmethod
    def _module_names(root: Path, fp: Path) -> set[str]:
        names = {fp.stem}
        try:
            rel = fp.relative_to(root).with_suffix("")
            dotted = ".".join(rel.parts)
            if dotted:
                names.add(dotted)
        except ValueError:
            pass
        return names

    def _collect_tainted_source_functions(self, fp: Path, tree: ast.AST) -> dict[str, tuple[Path, int]]:
        sources: dict[str, tuple[Path, int]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(
                    isinstance(child, ast.Return) and self._expr_contains_user_input(child.value)
                    for child in ast.walk(node)
                ):
                    sources[node.name] = (fp, getattr(node, "lineno", 1))
        return sources

    def _expr_contains_user_input(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._call_name(child.func)
            if name in {"input", "sys.argv"}:
                return True
            if name in {
                "request.get_json",
                "flask.request.get_json",
                "request.args.get",
                "request.form.get",
                "request.values.get",
                "request.cookies.get",
            }:
                return True
        return False

    @staticmethod
    def _collect_imported_taint_sources(
        tree: ast.AST,
        source_by_module: dict[str, dict[str, tuple[Path, int]]],
    ) -> dict[str, tuple[Path, int, str]]:
        imported: dict[str, tuple[Path, int, str]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            module_sources = source_by_module.get(node.module)
            if not module_sources:
                continue
            for alias in node.names:
                if alias.name in module_sources:
                    local_name = alias.asname or alias.name
                    src_path, src_line = module_sources[alias.name]
                    imported[local_name] = (src_path, src_line, alias.name)
        return imported

    @staticmethod
    def _collect_tainted_module_aliases(
        tree: ast.AST,
        source_by_module: dict[str, dict[str, tuple[Path, int]]],
    ) -> dict[str, dict[str, tuple[Path, int]]]:
        aliases: dict[str, dict[str, tuple[Path, int]]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Import):
                continue
            for alias in node.names:
                module_sources = source_by_module.get(alias.name)
                if module_sources:
                    aliases[alias.asname or alias.name] = module_sources
        return aliases

    def _find_cross_file_sinks(
        self,
        fp: Path,
        source: str,
        tree: ast.AST,
        imported_sources: dict[str, tuple[Path, int, str]],
        module_aliases: dict[str, dict[str, tuple[Path, int]]],
        seen: set[tuple[str, int, str]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for scope in self._iter_scopes(tree):
            tainted_vars = self._collect_local_tainted_vars(scope, imported_sources, module_aliases)
            for node in ast.walk(scope):
                if not isinstance(node, ast.Call) or not self._is_unsafe_sink(node):
                    continue
                source_ref = self._tainted_arg_source(node, tainted_vars, imported_sources, module_aliases)
                if not source_ref:
                    continue

                src_path, src_line, src_name = source_ref
                line = getattr(node, "lineno", 1)
                key = (str(fp), line, self._call_name(node.func))
                if key in seen:
                    continue
                seen.add(key)
                snippet = ast.get_source_segment(source, node) or self._call_name(node.func)
                findings.append(Finding(
                    rule_id="SAST-CROSS-001",
                    module="sast",
                    title="Cross-file tainted input reaches unsafe sink",
                    description=(
                        f"Imported user-controlled value from {src_path.name}:{src_line} "
                        f"via {src_name}() flows into {self._call_name(node.func)}()."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.78,
                    target=str(fp),
                    location=Location(file=str(fp), line_start=line),
                    evidence=snippet[:200],
                    cwe_ids=["CWE-94", "CWE-502"],
                    remediation="Validate and parse user input with a safe parser before passing it to code execution or deserialization sinks.",
                    tags=["category:sast", "method:cross-file-taint", f"source:{src_path.name}:{src_line}"],
                ))
        return findings

    @staticmethod
    def _iter_scopes(tree: ast.AST) -> list[ast.AST]:
        scopes: list[ast.AST] = [tree]
        scopes.extend(
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        return scopes

    def _collect_local_tainted_vars(
        self,
        scope: ast.AST,
        imported_sources: dict[str, tuple[Path, int, str]],
        module_aliases: dict[str, dict[str, tuple[Path, int]]],
    ) -> dict[str, tuple[Path, int, str]]:
        tainted_vars: dict[str, tuple[Path, int, str]] = {}
        for node in ast.walk(scope):
            if not isinstance(node, ast.Assign):
                continue
            source_ref = self._expr_taint_source(node.value, tainted_vars, imported_sources, module_aliases)
            if not source_ref:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tainted_vars[target.id] = source_ref
        return tainted_vars

    def _tainted_arg_source(
        self,
        call: ast.Call,
        tainted_vars: dict[str, tuple[Path, int, str]],
        imported_sources: dict[str, tuple[Path, int, str]],
        module_aliases: dict[str, dict[str, tuple[Path, int]]],
    ) -> tuple[Path, int, str] | None:
        for arg in call.args:
            source_ref = self._expr_taint_source(arg, tainted_vars, imported_sources, module_aliases)
            if source_ref:
                return source_ref
        return None

    def _expr_taint_source(
        self,
        node: ast.AST,
        tainted_vars: dict[str, tuple[Path, int, str]],
        imported_sources: dict[str, tuple[Path, int, str]],
        module_aliases: dict[str, dict[str, tuple[Path, int]]],
    ) -> tuple[Path, int, str] | None:
        if isinstance(node, ast.Name):
            return tainted_vars.get(node.id)
        if isinstance(node, ast.Call):
            name = self._call_name(node.func)
            if name in imported_sources:
                return imported_sources[name]
            if "." in name:
                module_name, func_name = name.rsplit(".", 1)
                module_sources = module_aliases.get(module_name)
                if module_sources and func_name in module_sources:
                    src_path, src_line = module_sources[func_name]
                    return src_path, src_line, func_name
        for child in ast.iter_child_nodes(node):
            source_ref = self._expr_taint_source(child, tainted_vars, imported_sources, module_aliases)
            if source_ref:
                return source_ref
        return None

    def _is_unsafe_sink(self, call: ast.Call) -> bool:
        name = self._call_name(call.func)
        return name in self._SINK_NAMES or name in self._SINK_ATTRS

    @staticmethod
    def _call_name(func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parent = SASTAnalyzer._call_name(func.value)
            return f"{parent}.{func.attr}" if parent else func.attr
        if isinstance(func, ast.Subscript):
            return SASTAnalyzer._call_name(func.value)
        return ""
