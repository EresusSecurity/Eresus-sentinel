"""
Eresus Sentinel — Notebook Scanner Package.

Scans Jupyter .ipynb files for security issues across 9 plugin categories.
Supports codebase-level scanning and JSON/Markdown report generation.

Plugins:
    dangerous_code   — Code pattern detection (120 patterns from YAML)
    cve             — CVE detection in code
    pii             — PII/credential detection
    secrets         — Secret/token detection
    license         — License compliance
    requirements    — Dependency CVE auditing
    metadata        — Notebook metadata security (kernel, trust, injection)
    output          — Cell output security (XSS, credential leakage, exfil)
"""

from sentinel.notebook_scanner.scanner import NotebookScanner
from sentinel.notebook_scanner.parser import NotebookParser, NotebookCell, ParsedNotebook
from sentinel.notebook_scanner.result import NotebookScanResult
from sentinel.notebook_scanner.codebase_scanner import CodebaseScanner, CodebaseScanResult
from sentinel.notebook_scanner.report_generator import ReportGenerator
from sentinel.notebook_scanner.requirements_plugin import scan_requirements, scan_requirements_file
from sentinel.notebook_scanner.metadata_plugin import MetadataPlugin
from sentinel.notebook_scanner.output_plugin import OutputPlugin

__all__ = [
    "NotebookScanner",
    "NotebookParser",
    "NotebookCell",
    "ParsedNotebook",
    "NotebookScanResult",
    "CodebaseScanner",
    "CodebaseScanResult",
    "ReportGenerator",
    "scan_requirements",
    "scan_requirements_file",
    "MetadataPlugin",
    "OutputPlugin",
]


