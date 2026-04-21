"""Notebook CVE vulnerability plugin — checks dependencies for known vulnerabilities."""

from __future__ import annotations

import re
import logging
from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.parser import NotebookCell

logger = logging.getLogger(__name__)

KNOWN_VULNERABLE_PACKAGES = {
    "tensorflow": {
        "affected": ["<2.12.0"],
        "cve": "CVE-2023-25801",
        "severity": Severity.HIGH,
        "description": "TensorFlow < 2.12.0 has multiple deserialization vulnerabilities",
    },
    "torch": {
        "affected": ["<2.1.0"],
        "cve": "CVE-2024-31583",
        "severity": Severity.CRITICAL,
        "description": "PyTorch < 2.1.0 torch.load allows arbitrary code execution",
    },
    "numpy": {
        "affected": ["<1.22.0"],
        "cve": "CVE-2021-41496",
        "severity": Severity.MEDIUM,
        "description": "NumPy < 1.22.0 buffer overflow in array operations",
    },
    "pillow": {
        "affected": ["<10.0.1"],
        "cve": "CVE-2023-44271",
        "severity": Severity.HIGH,
        "description": "Pillow < 10.0.1 denial of service via crafted image",
    },
    "requests": {
        "affected": ["<2.31.0"],
        "cve": "CVE-2023-32681",
        "severity": Severity.MEDIUM,
        "description": "Requests < 2.31.0 leaks Proxy-Authorization headers",
    },
    "transformers": {
        "affected": ["<4.36.0"],
        "cve": "CVE-2023-7018",
        "severity": Severity.CRITICAL,
        "description": "Transformers < 4.36.0 arbitrary code execution via unsafe deserialization",
    },
    "scikit-learn": {
        "affected": ["<1.3.0"],
        "cve": "CVE-2020-28975",
        "severity": Severity.MEDIUM,
        "description": "scikit-learn < 1.3.0 pickle deserialization in joblib",
    },
    "flask": {
        "affected": ["<2.3.2"],
        "cve": "CVE-2023-30861",
        "severity": Severity.HIGH,
        "description": "Flask < 2.3.2 session cookie security",
    },
    "cryptography": {
        "affected": ["<41.0.0"],
        "cve": "CVE-2023-38325",
        "severity": Severity.HIGH,
        "description": "cryptography < 41.0.0 certificate validation bypass",
    },
    "gradio": {
        "affected": ["<4.0"],
        "cve": "CVE-2023-51449",
        "severity": Severity.CRITICAL,
        "description": "Gradio < 4.0 path traversal leading to arbitrary file read",
    },
    "langchain": {
        "affected": ["<0.0.325"],
        "cve": "CVE-2023-44467",
        "severity": Severity.CRITICAL,
        "description": "LangChain < 0.0.325 arbitrary code execution via JIRA toolkit",
    },
    "jupyter-server": {
        "affected": ["<2.7.2"],
        "cve": "CVE-2023-40170",
        "severity": Severity.HIGH,
        "description": "Jupyter Server < 2.7.2 XSRF token exposure",
    },
    "aiohttp": {
        "affected": ["<3.9.0"],
        "cve": "CVE-2024-23334",
        "severity": Severity.HIGH,
        "description": "aiohttp < 3.9.0 directory traversal",
    },
    "onnx": {
        "affected": ["<1.14.1"],
        "cve": "CVE-2023-44584",
        "severity": Severity.HIGH,
        "description": "ONNX < 1.14.1 arbitrary file access via external data",
    },
}

IMPORT_PATTERN = re.compile(r"^\s*(?:import|from)\s+([\w\-]+)", re.MULTILINE)
PIP_INSTALL_PATTERN = re.compile(r"!pip\s+install\s+([^\s=<>!]+)(?:[=<>!]+(\S+))?", re.MULTILINE)


def scan_cve(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan code cell for imports/installs of packages with known CVEs."""
    if not cell.is_code:
        return []

    findings = []
    imported_packages = set()

    for match in IMPORT_PATTERN.finditer(cell.source):
        pkg = match.group(1).replace("-", "_").lower()
        imported_packages.add(pkg)

    for match in PIP_INSTALL_PATTERN.finditer(cell.source):
        pkg = match.group(1).replace("-", "_").lower()
        version = match.group(2)
        imported_packages.add(pkg)

        if pkg in KNOWN_VULNERABLE_PACKAGES:
            vuln = KNOWN_VULNERABLE_PACKAGES[pkg]
            findings.append(Finding.sast(
                rule_id="NOTEBOOK-030",
                title=f"Vulnerable dependency install: {pkg} ({vuln['cve']})",
                description=f"Notebook {cell.ref} installs {pkg}"
                            + (f"=={version}" if version else "")
                            + f" — {vuln['description']}",
                severity=vuln["severity"],
                confidence=0.8 if version else 0.5,
                target=path,
                evidence=f"{cell.ref}: pip install {pkg}" + (f"=={version}" if version else ""),
                cwe_ids=["CWE-1395"],
                tags=["category:notebook", "category:cve", f"cve:{vuln['cve']}"],
                remediation=f"Upgrade {pkg} to a patched version (affected: {vuln['affected']}).",
            ))

    for pkg in imported_packages:
        normalized = pkg.replace("_", "-")
        for known_name, vuln in KNOWN_VULNERABLE_PACKAGES.items():
            if pkg == known_name.replace("-", "_") and not any(f.rule_id == "NOTEBOOK-030" and known_name in f.title for f in findings):
                findings.append(Finding.sast(
                    rule_id="NOTEBOOK-031",
                    title=f"Potentially vulnerable import: {pkg} ({vuln['cve']})",
                    description=f"Notebook {cell.ref} imports {pkg} which has known CVEs. Version not determinable from import.",
                    severity=Severity.MEDIUM,
                    confidence=0.4,
                    target=path,
                    evidence=f"{cell.ref}: import {pkg}",
                    cwe_ids=["CWE-1395"],
                    tags=["category:notebook", "category:cve-import"],
                    remediation=f"Verify {pkg} version is not in affected range: {vuln['affected']}.",
                ))

    return findings
