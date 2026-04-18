"""
SAST Complexity Analyzer.

Measures code complexity metrics that correlate with security risk:
  - Cyclomatic complexity per function
  - Nesting depth (deeply nested code hides bugs)
  - Function length (long functions are harder to audit)
  - Import density (many imports = large attack surface)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity, Location

logger = logging.getLogger(__name__)


@dataclass
class FunctionMetrics:
    """Metrics for a single function."""
    name: str
    file: str
    line_start: int
    line_end: int
    line_count: int
    max_nesting: int
    branching_count: int  # if/elif/for/while/try/except
    import_count: int = 0

    @property
    def cyclomatic_complexity(self) -> int:
        """McCabe cyclomatic complexity estimate."""
        return self.branching_count + 1


@dataclass
class FileMetrics:
    """Metrics for a single file."""
    path: str
    total_lines: int = 0
    import_count: int = 0
    function_count: int = 0
    class_count: int = 0
    max_nesting: int = 0
    functions: list[FunctionMetrics] = field(default_factory=list)

    @property
    def avg_complexity(self) -> float:
        if not self.functions:
            return 0.0
        return sum(f.cyclomatic_complexity for f in self.functions) / len(self.functions)


# Patterns for detecting branching
_BRANCH_PATTERNS = re.compile(
    r"^\s*(?:if |elif |else:|for |while |try:|except |with |case )"
)
_FUNC_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
_CLASS_DEF = re.compile(r"^(\s*)class\s+(\w+)")
_IMPORT = re.compile(r"^\s*(?:import |from \S+ import )")

# Thresholds
COMPLEXITY_HIGH = 15
COMPLEXITY_CRITICAL = 25
NESTING_HIGH = 5
NESTING_CRITICAL = 8
LENGTH_HIGH = 100
LENGTH_CRITICAL = 300


class ComplexityAnalyzer:
    """
    Measure code complexity as a security risk indicator.

    High-complexity code is:
      - Harder to review for security issues
      - More likely to contain unintended logic paths
      - More difficult to test exhaustively

    Usage:
        analyzer = ComplexityAnalyzer()
        findings = analyzer.scan_file("app.py")
        metrics = analyzer.get_metrics("app.py")
    """

    SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv"}

    def __init__(
        self,
        complexity_threshold: int = COMPLEXITY_HIGH,
        nesting_threshold: int = NESTING_HIGH,
        length_threshold: int = LENGTH_HIGH,
    ):
        self._complexity_threshold = complexity_threshold
        self._nesting_threshold = nesting_threshold
        self._length_threshold = length_threshold

    def scan_file(self, path: str) -> list[Finding]:
        """Scan a file and return findings for high-complexity functions."""
        metrics = self.get_metrics(path)
        if not metrics:
            return []

        findings = []

        # File-level import density
        if metrics.import_count > 30:
            findings.append(Finding(
                rule_id="SAST-COMPLEX-001",
                module="sast.complexity",
                title="High import density",
                description=f"File has {metrics.import_count} imports — large attack surface",
                severity=Severity.MEDIUM,
                confidence=0.8,
                target=path,
                location=Location(file=path, line_start=1),
                evidence=f"import_count={metrics.import_count}",
                tags=["category:complexity"],
            ))

        # Function-level metrics
        for func in metrics.functions:
            cc = func.cyclomatic_complexity

            if cc >= COMPLEXITY_CRITICAL:
                findings.append(Finding(
                    rule_id="SAST-COMPLEX-010",
                    module="sast.complexity",
                    title=f"Critical complexity: {func.name}()",
                    description=f"Cyclomatic complexity {cc} (critical threshold: {COMPLEXITY_CRITICAL})",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    target=path,
                    location=Location(file=path, line_start=func.line_start),
                    evidence=f"complexity={cc}, lines={func.line_count}, nesting={func.max_nesting}",
                    tags=["category:complexity"],
                    remediation="Break into smaller, single-responsibility functions",
                ))
            elif cc >= self._complexity_threshold:
                findings.append(Finding(
                    rule_id="SAST-COMPLEX-011",
                    module="sast.complexity",
                    title=f"High complexity: {func.name}()",
                    description=f"Cyclomatic complexity {cc} (threshold: {self._complexity_threshold})",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    target=path,
                    location=Location(file=path, line_start=func.line_start),
                    evidence=f"complexity={cc}, lines={func.line_count}",
                    tags=["category:complexity"],
                ))

            if func.max_nesting >= NESTING_CRITICAL:
                findings.append(Finding(
                    rule_id="SAST-COMPLEX-020",
                    module="sast.complexity",
                    title=f"Critical nesting depth: {func.name}()",
                    description=f"Nesting depth {func.max_nesting} (critical: {NESTING_CRITICAL})",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    target=path,
                    location=Location(file=path, line_start=func.line_start),
                    evidence=f"max_nesting={func.max_nesting}",
                    tags=["category:complexity"],
                    remediation="Reduce nesting with early returns or extracted functions",
                ))
            elif func.max_nesting >= self._nesting_threshold:
                findings.append(Finding(
                    rule_id="SAST-COMPLEX-021",
                    module="sast.complexity",
                    title=f"Deep nesting: {func.name}()",
                    description=f"Nesting depth {func.max_nesting} (threshold: {self._nesting_threshold})",
                    severity=Severity.LOW,
                    confidence=0.7,
                    target=path,
                    location=Location(file=path, line_start=func.line_start),
                    evidence=f"max_nesting={func.max_nesting}",
                    tags=["category:complexity"],
                ))

            if func.line_count >= LENGTH_CRITICAL:
                findings.append(Finding(
                    rule_id="SAST-COMPLEX-030",
                    module="sast.complexity",
                    title=f"Extremely long function: {func.name}()",
                    description=f"Function is {func.line_count} lines (critical: {LENGTH_CRITICAL})",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    target=path,
                    location=Location(file=path, line_start=func.line_start),
                    evidence=f"line_count={func.line_count}",
                    tags=["category:complexity"],
                    remediation="Split into cohesive sub-functions for auditability",
                ))

        return findings

    def get_metrics(self, path: str) -> Optional[FileMetrics]:
        """Get complexity metrics for a file."""
        fp = Path(path)
        if not fp.exists() or fp.suffix not in {".py", ".pyi"}:
            return None

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return None

        metrics = FileMetrics(path=str(fp), total_lines=len(lines))
        current_func: Optional[dict] = None
        func_indent = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith("#"):
                continue

            # Count imports
            if _IMPORT.match(stripped):
                metrics.import_count += 1

            # Count classes
            cls_match = _CLASS_DEF.match(stripped)
            if cls_match:
                metrics.class_count += 1

            # Track functions
            func_match = _FUNC_DEF.match(stripped)
            if func_match:
                # Save previous function
                if current_func:
                    current_func["line_end"] = line_num - 1
                    metrics.functions.append(self._build_func_metrics(current_func, fp))

                indent = len(func_match.group(1))
                current_func = {
                    "name": func_match.group(2),
                    "line_start": line_num,
                    "line_end": line_num,
                    "indent": indent,
                    "branches": 0,
                    "max_nesting": 0,
                }
                func_indent = indent
                metrics.function_count += 1
                continue

            # Count branches within current function
            if current_func and _BRANCH_PATTERNS.match(stripped):
                current_func["branches"] += 1
                # Estimate nesting by indentation
                current_indent = len(line) - len(line.lstrip())
                relative_nesting = (current_indent - func_indent) // 4
                current_func["max_nesting"] = max(
                    current_func["max_nesting"], relative_nesting
                )
                metrics.max_nesting = max(metrics.max_nesting, relative_nesting)

        # Save last function
        if current_func:
            current_func["line_end"] = len(lines)
            metrics.functions.append(self._build_func_metrics(current_func, fp))

        return metrics

    @staticmethod
    def _build_func_metrics(func_dict: dict, fp: Path) -> FunctionMetrics:
        return FunctionMetrics(
            name=func_dict["name"],
            file=str(fp),
            line_start=func_dict["line_start"],
            line_end=func_dict["line_end"],
            line_count=func_dict["line_end"] - func_dict["line_start"] + 1,
            max_nesting=func_dict["max_nesting"],
            branching_count=func_dict["branches"],
        )

    def scan_directory(self, path: str) -> list[Finding]:
        """Scan a directory for complexity findings."""
        root = Path(path)
        findings = []

        for fp in sorted(root.rglob("*.py")):
            if not any(skip in fp.parts for skip in self.SKIP_DIRS):
                findings.extend(self.scan_file(str(fp)))

        return findings
