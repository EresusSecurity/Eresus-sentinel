"""
Codebase-level notebook scanner.

Recursively scans directories for Jupyter notebooks (.ipynb) and
runs all notebook scanner plugins against each one. Produces
an aggregated finding set with per-notebook and codebase-level
summary statistics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.result import NotebookScanResult
from sentinel.notebook_scanner.scanner import NotebookScanner

logger = logging.getLogger(__name__)


@dataclass
class CodebaseScanResult:
    """Aggregated scan results for a directory of notebooks."""
    root_dir: str
    notebooks_scanned: int = 0
    notebooks_failed: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    per_notebook: dict[str, NotebookScanResult] = field(default_factory=dict)
    all_findings: list[Finding] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)

    @property
    def severity_summary(self) -> dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
        }

    @property
    def risk_rating(self) -> str:
        if self.critical_count > 0:
            return "CRITICAL"
        if self.high_count > 3:
            return "HIGH"
        if self.high_count > 0 or self.medium_count > 5:
            return "MEDIUM"
        if self.medium_count > 0 or self.low_count > 0:
            return "LOW"
        return "CLEAN"


class CodebaseScanner:
    """
    Scan a directory tree for Jupyter notebooks and aggregate results.

    Usage:
        scanner = CodebaseScanner()
        result = scanner.scan("/path/to/project")
        print(f"Scanned {result.notebooks_scanned} notebooks")
        print(f"Risk: {result.risk_rating}")
    """

    def __init__(
        self,
        recursive: bool = True,
        max_notebooks: int = 500,
        skip_checkpoints: bool = True,
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ):
        self._recursive = recursive
        self._max_notebooks = max_notebooks
        self._skip_checkpoints = skip_checkpoints
        self._include = include_patterns or ["*.ipynb"]
        self._exclude = exclude_patterns or []
        self._scanner = NotebookScanner()

    def scan(self, root_dir: str) -> CodebaseScanResult:
        """Scan all notebooks in a directory."""
        root = Path(root_dir)
        if not root.is_dir():
            logger.error("Not a directory: %s", root_dir)
            return CodebaseScanResult(root_dir=root_dir)

        result = CodebaseScanResult(root_dir=root_dir)
        notebooks = self._discover_notebooks(root)

        if len(notebooks) > self._max_notebooks:
            logger.warning(
                "Found %d notebooks, limiting to %d",
                len(notebooks), self._max_notebooks,
            )
            notebooks = notebooks[:self._max_notebooks]

        for nb_path in notebooks:
            try:
                nb_result = self._scanner.scan_file(str(nb_path))
                result.per_notebook[str(nb_path)] = nb_result
                result.notebooks_scanned += 1

                for finding in nb_result.findings:
                    result.all_findings.append(finding)
                    result.total_findings += 1
                    self._count_severity(result, finding.severity)

            except Exception as exc:
                logger.warning("Failed to scan %s: %s", nb_path, exc)
                result.notebooks_failed += 1
                result.skipped_files.append(str(nb_path))

        logger.info(
            "CodebaseScanner: %d notebooks, %d findings (%s)",
            result.notebooks_scanned,
            result.total_findings,
            result.risk_rating,
        )
        return result

    def _discover_notebooks(self, root: Path) -> list[Path]:
        """Find all .ipynb files in directory tree."""
        notebooks = []
        pattern = "**/*.ipynb" if self._recursive else "*.ipynb"

        for path in sorted(root.glob(pattern)):
            if self._skip_checkpoints and ".ipynb_checkpoints" in str(path):
                continue
            if self._should_exclude(path):
                continue
            notebooks.append(path)

        return notebooks

    def _should_exclude(self, path: Path) -> bool:
        """Check if path matches any exclude pattern."""
        path_str = str(path)
        for pattern in self._exclude:
            if pattern in path_str:
                return True
        return False

    @staticmethod
    def _count_severity(result: CodebaseScanResult, severity: Severity) -> None:
        if severity == Severity.CRITICAL:
            result.critical_count += 1
        elif severity == Severity.HIGH:
            result.high_count += 1
        elif severity == Severity.MEDIUM:
            result.medium_count += 1
        elif severity == Severity.LOW:
            result.low_count += 1
