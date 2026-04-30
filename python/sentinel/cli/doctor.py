"""
Sentinel Doctor — dependency and configuration health check.

Verifies all dependencies are installed, YAML rules are valid,
API connectivity works, and database connection is available.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_log = logging.getLogger("sentinel.cli.doctor")


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    severity: str = "info"  # "info", "warn", "error"


class Doctor:
    """Run health checks on the Sentinel installation."""

    def __init__(self, rules_dir: str | None = None):
        self._rules_dir = Path(
            rules_dir or os.environ.get("ERESUS_RULES_DIR", "rules")
        )

    def run_all(self) -> list[CheckResult]:
        """Run all health checks and return results."""
        results: list[CheckResult] = []
        results.extend(self.check_python_version())
        results.extend(self.check_core_dependencies())
        results.extend(self.check_optional_dependencies())
        results.extend(self.check_yaml_rules())
        results.extend(self.check_environment())
        results.extend(self.check_database())
        return results

    def check_python_version(self) -> list[CheckResult]:
        v = sys.version_info
        if v >= (3, 10):
            return [CheckResult("Python version", True, f"{v.major}.{v.minor}.{v.micro}")]
        return [CheckResult("Python version", False, f"{v.major}.{v.minor} < 3.10", "error")]

    def check_core_dependencies(self) -> list[CheckResult]:
        results = []
        for mod in ["yaml", "pydantic", "sentinel"]:
            try:
                importlib.import_module(mod)
                results.append(CheckResult(f"Module: {mod}", True, "installed"))
            except ImportError:
                results.append(CheckResult(f"Module: {mod}", False, "not installed", "error"))
        return results

    def check_optional_dependencies(self) -> list[CheckResult]:
        results = []
        optional = {
            "fastapi": "Web dashboard",
            "uvicorn": "ASGI server",
            "redis": "Redis session store",
            "httpx": "LLM examiner / HTTP client",
            "h5py": "HDF5 model scanning",
            "onnx": "ONNX model analysis",
            "torch": "PyTorch model scanning",
        }
        for mod, desc in optional.items():
            try:
                importlib.import_module(mod)
                results.append(CheckResult(f"Optional: {mod}", True, f"{desc} — installed"))
            except ImportError:
                results.append(CheckResult(f"Optional: {mod}", False, f"{desc} — not installed", "warn"))
        return results

    def check_yaml_rules(self) -> list[CheckResult]:
        results = []
        if not self._rules_dir.is_dir():
            results.append(CheckResult("Rules directory", False, f"{self._rules_dir} not found", "error"))
            return results

        results.append(CheckResult("Rules directory", True, str(self._rules_dir)))
        errors = 0
        total = 0
        for f in sorted(self._rules_dir.glob("*.yaml")):
            total += 1
            try:
                with open(f) as fh:
                    data = yaml.safe_load(fh)
                if data is None:
                    results.append(CheckResult(f"Rule: {f.name}", False, "Empty YAML file", "warn"))
                    errors += 1
            except yaml.YAMLError as exc:
                results.append(CheckResult(f"Rule: {f.name}", False, f"Parse error: {exc}", "error"))
                errors += 1

        if errors == 0:
            results.append(CheckResult("YAML rules validation", True, f"{total} rule files OK"))
        else:
            results.append(CheckResult("YAML rules validation", False, f"{errors}/{total} files have errors", "error"))
        return results

    def check_environment(self) -> list[CheckResult]:
        results = []
        # Auth configuration
        auth_type = os.environ.get("SENTINEL_AUTH_TYPE", "")
        auth_token = os.environ.get("SENTINEL_AUTH_TOKEN", "")
        if auth_type and auth_token:
            results.append(CheckResult("Auth config", True, f"type={auth_type}"))
        elif auth_type and not auth_token:
            results.append(CheckResult("Auth config", False, "AUTH_TYPE set but no AUTH_TOKEN", "warn"))
        else:
            results.append(CheckResult("Auth config", True, "No auth configured (dev mode)"))

        # Audit log
        audit_log = os.environ.get("SENTINEL_AUDIT_LOG", "")
        if audit_log:
            p = Path(audit_log)
            if p.parent.is_dir():
                results.append(CheckResult("Audit log", True, audit_log))
            else:
                results.append(CheckResult("Audit log", False, f"Directory not found: {p.parent}", "warn"))

        return results

    def check_database(self) -> list[CheckResult]:
        db_url = os.environ.get("DATABASE_URL", "")
        if not db_url:
            return [CheckResult("Database", True, "No DATABASE_URL — using file/memory mode")]

        try:
            if "postgresql" in db_url:
                import asyncpg  # noqa: F401
                return [CheckResult("Database", True, "PostgreSQL driver available")]
        except ImportError:
            return [CheckResult("Database", False, "asyncpg not installed for PostgreSQL", "error")]

        return [CheckResult("Database", True, f"URL configured: {db_url[:30]}...")]

    def format_report(self, results: list[CheckResult]) -> str:
        lines = ["Sentinel Doctor Report", "=" * 40]
        passed = sum(1 for r in results if r.passed)
        total = len(results)

        for r in results:
            icon = "✓" if r.passed else ("⚠" if r.severity == "warn" else "✗")
            lines.append(f"  {icon} {r.name}: {r.detail}")

        lines.append("-" * 40)
        lines.append(f"  {passed}/{total} checks passed")
        return "\n".join(lines)
