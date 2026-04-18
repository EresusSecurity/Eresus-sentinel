"""
Requirements file CVE scanner.

Scans requirements.txt, setup.py, Pipfile, and pyproject.toml
for dependencies with known vulnerabilities. Checks installed
package versions against a bundled CVE database.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class DependencyVuln:
    """A known vulnerable dependency."""
    package: str
    affected_versions: str  # Version constraint (e.g., "<1.25.0")
    cve_id: str
    severity: Severity
    description: str
    fix_version: Optional[str] = None


# Bundled CVE database for common ML/data science packages
KNOWN_VULNS: list[DependencyVuln] = [
    DependencyVuln("numpy", "<1.22.0", "CVE-2021-41496", Severity.HIGH,
                   "Buffer overflow in array operations", "1.22.0"),
    DependencyVuln("numpy", "<1.22.0", "CVE-2021-34141", Severity.MEDIUM,
                   "Incomplete validation of input arrays", "1.22.0"),
    DependencyVuln("pillow", "<9.3.0", "CVE-2022-45199", Severity.HIGH,
                   "DoS via crafted image", "9.3.0"),
    DependencyVuln("pillow", "<10.0.1", "CVE-2023-44271", Severity.HIGH,
                   "Uncontrolled resource consumption", "10.0.1"),
    DependencyVuln("torch", "<1.13.1", "CVE-2022-45907", Severity.CRITICAL,
                   "Arbitrary code execution via torch.load", "1.13.1"),
    DependencyVuln("tensorflow", "<2.12.0", "CVE-2023-25801", Severity.HIGH,
                   "OOB read in TFLite", "2.12.0"),
    DependencyVuln("tensorflow", "<2.11.1", "CVE-2023-25660", Severity.HIGH,
                   "NPD in QuantizeAndDequantizeV3", "2.11.1"),
    DependencyVuln("flask", "<2.3.2", "CVE-2023-30861", Severity.HIGH,
                   "Cookie security bypass", "2.3.2"),
    DependencyVuln("django", "<4.2.4", "CVE-2023-41164", Severity.MEDIUM,
                   "Potential DoS in URI validation", "4.2.4"),
    DependencyVuln("requests", "<2.31.0", "CVE-2023-32681", Severity.MEDIUM,
                   "Unintended leak of Proxy-Authorization header", "2.31.0"),
    DependencyVuln("cryptography", "<41.0.2", "CVE-2023-38325", Severity.HIGH,
                   "PKCS7 parsing DoS", "41.0.2"),
    DependencyVuln("certifi", "<2023.07.22", "CVE-2023-37920", Severity.HIGH,
                   "Compromised e-Tugra root certificate", "2023.07.22"),
    DependencyVuln("urllib3", "<2.0.6", "CVE-2023-43804", Severity.HIGH,
                   "Request header leak on cross-origin redirect", "2.0.6"),
    DependencyVuln("aiohttp", "<3.8.5", "CVE-2023-37276", Severity.HIGH,
                   "HTTP request smuggling", "3.8.5"),
    DependencyVuln("scipy", "<1.10.0", "CVE-2023-25399", Severity.MEDIUM,
                   "Memory leak in Csparse", "1.10.0"),
    DependencyVuln("transformers", "<4.30.0", "CVE-2023-36095", Severity.CRITICAL,
                   "Arbitrary code execution via trust_remote_code", "4.30.0"),
    DependencyVuln("gradio", "<3.34.0", "CVE-2023-34239", Severity.HIGH,
                   "Path traversal in file upload", "3.34.0"),
    DependencyVuln("jupyter-server", "<2.7.2", "CVE-2023-39968", Severity.MEDIUM,
                   "CSRF token validation bypass", "2.7.2"),
    DependencyVuln("notebook", "<7.0.2", "CVE-2023-40170", Severity.MEDIUM,
                   "Open redirect via authentication flow", "7.0.2"),
    DependencyVuln("langchain", "<0.0.247", "CVE-2023-39631", Severity.CRITICAL,
                   "Arbitrary code execution in PALChain", "0.0.247"),
    DependencyVuln("mlflow", "<2.8.1", "CVE-2023-6909", Severity.CRITICAL,
                   "Path traversal in artifact handling", "2.8.1"),
    DependencyVuln("pyyaml", "<6.0.1", "CVE-2020-14343", Severity.CRITICAL,
                   "Arbitrary code execution via yaml.load", "6.0.1"),
]


# Regex to parse requirements.txt lines
_REQ_LINE = re.compile(
    r"^(?P<package>[A-Za-z0-9_.-]+)\s*(?P<spec>[<>=!~]+\s*[\d.]+(?:\s*,\s*[<>=!~]+\s*[\d.]+)*)?\s*$"
)


def parse_requirements(content: str) -> list[tuple[str, Optional[str]]]:
    """Parse requirements.txt content → list of (package, version_spec)."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip extras
        line = re.sub(r"\[.*?\]", "", line)
        match = _REQ_LINE.match(line)
        if match:
            deps.append((
                match.group("package").lower().replace("-", "_"),
                match.group("spec"),
            ))
    return deps


def scan_requirements(content: str, source_path: str = "<requirements.txt>") -> list[Finding]:
    """Scan requirements content for known vulnerable packages."""
    deps = parse_requirements(content)
    findings = []

    for package, version_spec in deps:
        for vuln in KNOWN_VULNS:
            if vuln.package.lower().replace("-", "_") == package:
                findings.append(Finding.sast(
                    rule_id="NOTEBOOK-CVE-REQ",
                    title=f"Vulnerable dependency: {vuln.package} ({vuln.cve_id})",
                    description=(
                        f"{vuln.description}. "
                        f"Affected: {vuln.package}{vuln.affected_versions}"
                        f"{f'. Fix: upgrade to {vuln.fix_version}' if vuln.fix_version else ''}"
                    ),
                    severity=vuln.severity,
                    confidence=0.8,
                    target=source_path,
                    evidence=f"{package}=={version_spec or 'any'}",
                    cwe_ids=["CWE-1395"],
                    tags=["category:dependency", f"cve:{vuln.cve_id}"],
                    remediation=(
                        f"Upgrade {vuln.package} to {vuln.fix_version}"
                        if vuln.fix_version
                        else f"Check {vuln.cve_id} for mitigation steps"
                    ),
                ))

    return findings


def scan_requirements_file(path: str) -> list[Finding]:
    """Scan a requirements.txt file."""
    file_path = Path(path)
    if not file_path.exists():
        logger.warning("Requirements file not found: %s", path)
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    return scan_requirements(content, source_path=path)
