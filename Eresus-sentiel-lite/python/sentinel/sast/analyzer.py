"""
Eresus Sentinel — SAST Analyzer (YAML-driven)

All rules are loaded from rules/sast_rules.yaml.
No hardcoded patterns in this file.
"""

import json
import os
import re
from pathlib import Path
from typing import List, Optional

from ..finding import Finding, Severity, Location
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
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for f in files:
                fp = Path(root) / f
                if fp.suffix in SCANNABLE_EXTENSIONS:
                    findings.extend(self._scan_file(fp))
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
                matched_text = m.group(0)
                rule_id = rule["id"]
                if rule_id == "SAST-020" and self._is_safe_eval(stripped, m):
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
