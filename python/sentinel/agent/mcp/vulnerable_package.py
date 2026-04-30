"""Vulnerable package scanner for MCP server dependencies.

Parses MCP server dependency files (requirements.txt, pyproject.toml,
package.json) and checks each package against a local CVE database or
the OSV.dev API (https://osv.dev/docs/).
"""
from __future__ import annotations

import json
import logging
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


@dataclass
class PackageVuln:
    package: str
    version: str
    vuln_id: str
    summary: str
    severity: str = "UNKNOWN"
    aliases: list[str] = field(default_factory=list)


@dataclass
class VulnScanResult:
    path: str
    packages: list[tuple[str, str]] = field(default_factory=list)
    vulnerabilities: list[PackageVuln] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_clean(self) -> bool:
        return len(self.vulnerabilities) == 0 and self.error is None


class VulnerablePackageAnalyzer:
    """Detect vulnerable dependencies in an MCP server project.

    Args:
        timeout: HTTP timeout for OSV API calls.
        use_osv: Query osv.dev API (requires internet). Default ``True``.
    """

    def __init__(self, timeout: int = 10, use_osv: bool = True) -> None:
        self._timeout = timeout
        self._use_osv = use_osv

    def scan_path(self, project_path: str) -> VulnScanResult:
        """Scan *project_path* for dependency files and check each package."""
        root = Path(project_path)
        packages = self._collect_packages(root)

        result = VulnScanResult(path=project_path, packages=packages)
        if not packages:
            return result

        if self._use_osv:
            try:
                result.vulnerabilities = self._query_osv(packages)
            except Exception as exc:
                logger.warning("OSV query failed: %s", exc)
                result.error = f"OSV lookup failed: {exc}"

        return result

    def _collect_packages(self, root: Path) -> list[tuple[str, str]]:
        packages: list[tuple[str, str]] = []

        req = root / "requirements.txt"
        if req.exists():
            packages.extend(self._parse_requirements(req))

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            packages.extend(self._parse_pyproject(pyproject))

        pkg_json = root / "package.json"
        if pkg_json.exists():
            packages.extend(self._parse_package_json(pkg_json))

        return packages

    @staticmethod
    def _parse_requirements(path: Path) -> list[tuple[str, str]]:
        pkgs: list[tuple[str, str]] = []
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)[=~<>!]+([^\s;#]+)", line)
            if m:
                pkgs.append((m.group(1).lower(), m.group(2)))
            else:
                name_only = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if name_only:
                    pkgs.append((name_only.group(1).lower(), ""))
        return pkgs

    @staticmethod
    def _parse_pyproject(path: Path) -> list[tuple[str, str]]:
        pkgs: list[tuple[str, str]] = []
        text = path.read_text(errors="ignore")
        for m in re.finditer(r'"([A-Za-z0-9_\-\.]+)[=~<>!]+([^"]+)"', text):
            pkgs.append((m.group(1).lower(), m.group(2)))
        return pkgs

    @staticmethod
    def _parse_package_json(path: Path) -> list[tuple[str, str]]:
        pkgs: list[tuple[str, str]] = []
        try:
            data = json.loads(path.read_text(errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in data.get(section, {}).items():
                    ver_clean = re.sub(r"[^0-9.]", "", ver).strip(".")
                    pkgs.append((name.lower(), ver_clean))
        except Exception:
            pass
        return pkgs

    def _query_osv(self, packages: list[tuple[str, str]]) -> list[PackageVuln]:
        queries = []
        for name, version in packages:
            q: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
            if version:
                q["version"] = version
            queries.append(q)

        payload = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            _OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read())

        vulns: list[PackageVuln] = []
        results = data.get("results", [])
        for (pkg_name, pkg_ver), result in zip(packages, results):
            for vuln in result.get("vulns", []):
                severity = "UNKNOWN"
                for sev in vuln.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        score = float(sev.get("score", 0))
                        if score >= 9.0:
                            severity = "CRITICAL"
                        elif score >= 7.0:
                            severity = "HIGH"
                        elif score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                        break
                vulns.append(PackageVuln(
                    package=pkg_name,
                    version=pkg_ver,
                    vuln_id=vuln.get("id", ""),
                    summary=vuln.get("summary", ""),
                    severity=severity,
                    aliases=vuln.get("aliases", []),
                ))
        return vulns
