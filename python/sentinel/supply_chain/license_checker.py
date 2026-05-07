"""Dependency license compliance checker.

Reads requirements.txt / pyproject.toml, resolves package licenses via the
PyPI JSON API, and flags packages whose licenses appear in the blocklist or
warn-list defined in rules/license_blocklist.yaml.

Design notes:
- Network calls are cached to a JSON file in the system temp directory to
  avoid repeated PyPI requests across scans (mirrors NB Defense LicenseCache).
- All network calls are wrapped with a configurable timeout and suppressed on
  failure so offline use still works (with reduced coverage).
- The PyPI API is read-only and does not require authentication.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import NamedTuple
from urllib.request import urlopen, Request
from urllib.error import URLError

import yaml

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules"
_BLOCKLIST_FILE = _RULES_DIR / "license_blocklist.yaml"
_CACHE_FILE = Path(tempfile.gettempdir()) / "sentinel_license_cache.json"
_PYPI_TIMEOUT = 5
_CACHE_TTL = 86_400 * 7  # 7 days


class LicenseResult(NamedTuple):
    package: str
    version: str
    licenses: list[str]
    source: str


def _load_blocklist() -> tuple[set[str], set[str]]:
    """Return (blocked_ids, warn_ids) from license_blocklist.yaml."""
    if not _BLOCKLIST_FILE.exists():
        logger.debug("license_blocklist.yaml not found at %s", _BLOCKLIST_FILE)
        return set(), set()
    try:
        with open(_BLOCKLIST_FILE, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        logger.warning("Failed to load license_blocklist.yaml: %s", exc)
        return set(), set()

    blocked = {entry["id"] for entry in (data.get("blocked_licenses") or [])}
    warn = {entry["id"] for entry in (data.get("warn_licenses") or [])}
    return blocked, warn


def _load_cache() -> dict[str, dict]:
    try:
        if _CACHE_FILE.exists():
            with open(_CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_cache(cache: dict[str, dict]) -> None:
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception as exc:
        logger.debug("Failed to save license cache: %s", exc)


def _fetch_pypi_licenses(package: str, cache: dict[str, dict]) -> list[str]:
    """Fetch license identifiers for *package* from PyPI JSON API."""
    key = package.lower().replace("-", "_")
    cached = cache.get(key)
    if cached and time.time() - cached.get("ts", 0) < _CACHE_TTL:
        return cached.get("licenses", [])

    url = f"https://pypi.org/pypi/{package}/json"
    try:
        req = Request(url, headers={"User-Agent": "sentinel-license-checker/1.0"})
        with urlopen(req, timeout=_PYPI_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, Exception) as exc:
        logger.debug("PyPI lookup failed for %s: %s", package, exc)
        return []

    info = data.get("info", {})
    raw_license = (info.get("license") or "").strip()
    classifiers = info.get("classifiers") or []

    licenses: list[str] = []

    for clf in classifiers:
        if clf.startswith("License ::"):
            parts = clf.split(" :: ")
            if len(parts) >= 3:
                spdx = _classifier_to_spdx(parts[-1].strip())
                if spdx:
                    licenses.append(spdx)

    if not licenses and raw_license:
        spdx = _normalize_license_id(raw_license)
        if spdx:
            licenses.append(spdx)

    cache[key] = {"licenses": licenses, "ts": time.time()}
    return licenses


_CLASSIFIER_MAP: dict[str, str] = {
    "GNU Affero General Public License v3 (AGPLv3)": "AGPL-3.0",
    "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Server Side Public License": "SSPL-1.0",
}


def _classifier_to_spdx(clf_text: str) -> str:
    return _CLASSIFIER_MAP.get(clf_text, "")


def _normalize_license_id(raw: str) -> str:
    """Best-effort normalisation of a free-form license string to SPDX ID."""
    mappings: list[tuple[str, str]] = [
        (r"(?i)\bAGPL.?3", "AGPL-3.0"),
        (r"(?i)\bGPL.?3", "GPL-3.0"),
        (r"(?i)\bGPL.?2", "GPL-2.0"),
        (r"(?i)\bLGPL.?3", "LGPL-3.0"),
        (r"(?i)\bLGPL.?2\.1", "LGPL-2.1"),
        (r"(?i)\bLGPL.?2", "LGPL-2.0"),
        (r"(?i)\bSSPL", "SSPL-1.0"),
        (r"(?i)\bBUSL", "BUSL-1.1"),
        (r"(?i)\bMPL.?2", "MPL-2.0"),
        (r"(?i)\bCC-BY-NC", "CC-BY-NC-4.0"),
        (r"(?i)\bMIT\b", "MIT"),
        (r"(?i)\bApache.?2", "Apache-2.0"),
        (r"(?i)\bBSD.?3", "BSD-3-Clause"),
        (r"(?i)\bBSD.?2", "BSD-2-Clause"),
    ]
    for pattern, spdx in mappings:
        if re.search(pattern, raw):
            return spdx
    return ""


def _parse_requirements(path: Path) -> list[str]:
    """Extract bare package names from a requirements.txt file."""
    packages: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http", "git+")):
            continue
        # Strip version specifiers
        pkg = re.split(r"[=<>!\[;@ \t]", line)[0].strip()
        if pkg:
            packages.append(pkg)
    return packages


def _parse_pyproject(path: Path) -> list[str]:
    """Extract dependency names from pyproject.toml [project.dependencies]."""
    packages: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return packages

    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in ("[project.dependencies]", "dependencies = [", "dependencies=["):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("[") or stripped == "]":
                in_deps = False
                continue
            pkg = re.split(r"[=<>!\[;@ \t\"',]", stripped.lstrip('"').lstrip("'"))[0].strip()
            if pkg and not pkg.startswith("#"):
                packages.append(pkg)
    return packages


class LicenseChecker:
    """Resolves package licenses from requirements files via PyPI JSON API.

    Usage::

        checker = LicenseChecker()
        findings = checker.check_file(Path("requirements.txt"))
    """

    def __init__(self, offline: bool = False) -> None:
        self._offline = offline
        self._blocked, self._warn = _load_blocklist()
        self._cache = _load_cache()

    def check_file(self, dep_file: Path) -> list[dict]:
        """Return a list of license issue dicts for a dependency file.

        Each dict has keys: package, version, license_id, severity, reason.
        """
        suffix = dep_file.suffix.lower()
        name = dep_file.name.lower()

        if name == "requirements.txt" or suffix == ".txt":
            packages = _parse_requirements(dep_file)
        elif name == "pyproject.toml":
            packages = _parse_pyproject(dep_file)
        else:
            return []

        issues: list[dict] = []
        for pkg in packages:
            if self._offline:
                licenses = []
            else:
                licenses = _fetch_pypi_licenses(pkg, self._cache)

            for lic in licenses:
                if lic in self._blocked:
                    issues.append({
                        "package": pkg,
                        "license_id": lic,
                        "severity": "HIGH",
                        "reason": "blocked",
                        "file": str(dep_file),
                    })
                elif lic in self._warn:
                    issues.append({
                        "package": pkg,
                        "license_id": lic,
                        "severity": "MEDIUM",
                        "reason": "warn",
                        "file": str(dep_file),
                    })

        _save_cache(self._cache)
        return issues


def scan_dependency_licenses(dep_file: Path, offline: bool = False) -> list[dict]:
    """Convenience function: check a single dependency file and return issues."""
    return LicenseChecker(offline=offline).check_file(dep_file)
