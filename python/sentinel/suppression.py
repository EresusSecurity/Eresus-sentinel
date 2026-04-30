"""
Eresus Sentinel — Finding Suppression System.

Supports:
  - .sentinelignore (gitignore-style path exclusions)
  - Rule-based allowlist (suppress by rule ID)
  - Path-based ignore patterns (glob)
  - Finding-hash suppression with expiry and justification
  - Shadow mode (downgrade BLOCK → WARN for precision measurement)
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding

logger = logging.getLogger(__name__)

# Built-in ignores — always applied, not user-configurable
BUILTIN_IGNORES = [
    ".git/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "node_modules/**",
    "__pycache__/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".tox/**",
    ".eggs/**",
    "*.pyc",
    "*.pyo",
    ".ruff_cache/**",
    ".sentinel-cache/**",
    "dist/**",
    "build/**",
    "*.egg-info/**",
]


class SuppressionEngine:
    """Filter findings based on suppression rules."""

    def __init__(
        self,
        ignore_file: str = ".sentinelignore",
        allowed_rules: Optional[list[str]] = None,
        ignore_paths: Optional[list[str]] = None,
        hash_file: str = ".sentinel-suppressions.yaml",
        shadow_mode: bool = False,
        project_root: Optional[str] = None,
    ):
        self._root = Path(project_root) if project_root else Path.cwd()
        self._allowed_rules = set(allowed_rules or [])
        self._ignore_paths = list(BUILTIN_IGNORES) + (ignore_paths or [])
        self._shadow_mode = shadow_mode
        self._ignore_patterns = self._load_ignore_file(ignore_file)
        self._hash_suppressions = self._load_hash_file(hash_file)

    def _load_ignore_file(self, filename: str) -> list[str]:
        path = self._root / filename
        if not path.exists():
            return []
        patterns = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
        logger.info("Loaded %d ignore patterns from %s", len(patterns), filename)
        return patterns

    def _load_hash_file(self, filename: str) -> dict[str, dict]:
        path = self._root / filename
        if not path.exists():
            return {}
        try:
            import yaml
            data = yaml.safe_load(path.read_text()) or {}
            return data.get("suppressions", {})
        except Exception:
            return {}

    @staticmethod
    def finding_hash(finding: Finding) -> str:
        key = f"{finding.rule_id}:{finding.target}:{getattr(finding.location, 'line_start', 0)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def is_suppressed(self, finding: Finding) -> bool:
        if finding.rule_id in self._allowed_rules:
            return True

        target = finding.target or ""
        for pattern in self._ignore_patterns + self._ignore_paths:
            if fnmatch(target, pattern):
                return True

        fh = self.finding_hash(finding)
        if fh in self._hash_suppressions:
            entry = self._hash_suppressions[fh]
            expires = entry.get("expires")
            if expires:
                try:
                    exp_date = datetime.fromisoformat(expires)
                    if exp_date.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                        return False
                except (ValueError, TypeError):
                    pass
            return True

        return False

    def filter(self, findings: list[Finding]) -> list[Finding]:
        original = len(findings)
        result = [f for f in findings if not self.is_suppressed(f)]
        suppressed = original - len(result)
        if suppressed:
            logger.info("Suppressed %d/%d findings", suppressed, original)
        return result

    @property
    def shadow_mode(self) -> bool:
        return self._shadow_mode
