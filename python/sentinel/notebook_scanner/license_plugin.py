"""Notebook license compliance plugin — checks package licenses for compatibility."""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.parser import NotebookCell

logger = logging.getLogger(__name__)

COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-3.0",
    "MPL-2.0",
    "EUPL-1.2",
    "SSPL-1.0",
    "CPAL-1.0",
    "OSL-3.0",
}

NON_COMMERCIAL_LICENSES = {
    "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0",
    "COMMERCIAL", "PROPRIETARY",
}

KNOWN_PACKAGE_LICENSES = {
    "torch": "BSD-3-Clause",
    "tensorflow": "Apache-2.0",
    "numpy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "scikit-learn": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "matplotlib": "PSF-2.0",
    "pillow": "HPND",
    "requests": "Apache-2.0",
    "flask": "BSD-3-Clause",
    "django": "BSD-3-Clause",
    "fastapi": "MIT",
    "transformers": "Apache-2.0",
    "tokenizers": "Apache-2.0",
    "datasets": "Apache-2.0",
    "gradio": "Apache-2.0",
    "streamlit": "Apache-2.0",
    "opencv-python": "Apache-2.0",
    "catboost": "Apache-2.0",
    "lightgbm": "MIT",
    "xgboost": "Apache-2.0",
    "keras": "Apache-2.0",
    "jax": "Apache-2.0",
    "spacy": "MIT",
    "nltk": "Apache-2.0",
    "gensim": "LGPL-2.1",       # Copyleft!
    "pycryptodome": "BSD-2-Clause",
    "mysql-connector-python": "GPL-2.0",  # Copyleft!
    "pyqt5": "GPL-3.0",                   # Copyleft!
    "readline": "GPL-3.0",                # Copyleft!
    "ghostscript": "AGPL-3.0",            # Strong copyleft!
    "mongo-python-driver": "SSPL-1.0",    # SSPL!
}

PIP_INSTALL_PATTERN = re.compile(r"!pip\s+install\s+([^\s=<>!]+)", re.MULTILINE)
IMPORT_PATTERN = re.compile(r"^\s*(?:import|from)\s+([\w\-]+)", re.MULTILINE)


def scan_licenses(cell: NotebookCell, path: str, block_copyleft: bool = True) -> list[Finding]:
    """Scan code cell for packages with potentially restrictive licenses."""
    if not cell.is_code:
        return []

    findings = []
    packages = set()

    for match in PIP_INSTALL_PATTERN.finditer(cell.source):
        packages.add(match.group(1).replace("-", "_").lower())

    for match in IMPORT_PATTERN.finditer(cell.source):
        packages.add(match.group(1).replace("-", "_").lower())

    for pkg in packages:
        pkg.replace("_", "-")
        license_id = None

        for known, lic in KNOWN_PACKAGE_LICENSES.items():
            if pkg == known.replace("-", "_"):
                license_id = lic
                break

        if not license_id:
            continue

        if license_id in COPYLEFT_LICENSES and block_copyleft:
            severity = Severity.HIGH if "AGPL" in license_id or "SSPL" in license_id else Severity.MEDIUM
            findings.append(Finding.sast(
                rule_id="NOTEBOOK-040",
                title=f"Copyleft license: {pkg} ({license_id})",
                description=f"Notebook {cell.ref} uses {pkg} licensed under {license_id}. "
                            "This may require releasing derivative works under the same license.",
                severity=severity,
                confidence=0.9,
                target=path,
                evidence=f"{cell.ref}: {pkg} → {license_id}",
                cwe_ids=["CWE-1395"],
                tags=["category:notebook", "category:license", f"license:{license_id}"],
                remediation=f"Review {license_id} obligations or use an alternative package.",
            ))

        if license_id in NON_COMMERCIAL_LICENSES:
            findings.append(Finding.sast(
                rule_id="NOTEBOOK-041",
                title=f"Non-commercial license: {pkg} ({license_id})",
                description=f"Notebook {cell.ref} uses {pkg} under {license_id} which restricts commercial use.",
                severity=Severity.HIGH,
                confidence=0.9,
                target=path,
                evidence=f"{cell.ref}: {pkg} → {license_id}",
                cwe_ids=["CWE-1395"],
                tags=["category:notebook", "category:license-commercial"],
                remediation=f"Obtain commercial license for {pkg} or use an alternative.",
            ))

    return findings
