"""Notebook scanner orchestrator — runs all plugins against parsed notebooks."""

from __future__ import annotations

import logging
import os
from sentinel.notebook_scanner.parser import NotebookParser
from sentinel.notebook_scanner.result import NotebookScanResult
from sentinel.notebook_scanner import secrets_plugin, pii_plugin, dangerous_code_plugin, cve_plugin, license_plugin

logger = logging.getLogger(__name__)


class NotebookScanner:
    """
    Orchestrates notebook security scanning across all plugin categories.

    Plugins:
      - secrets_plugin: 27 credential patterns
      - pii_plugin: 15 PII patterns
      - dangerous_code_plugin: 40+ dangerous code patterns
      - cve_plugin: 14 known vulnerable packages
      - license_plugin: 30+ package license checks
    """

    def __init__(
        self,
        scan_secrets: bool = True,
        scan_pii: bool = True,
        scan_dangerous: bool = True,
        scan_outputs: bool = True,
        scan_cve: bool = True,
        scan_licenses: bool = True,
        block_copyleft: bool = True,
    ):
        self._scan_secrets = scan_secrets
        self._scan_pii = scan_pii
        self._scan_dangerous = scan_dangerous
        self._scan_outputs = scan_outputs
        self._scan_cve = scan_cve
        self._scan_licenses = scan_licenses
        self._block_copyleft = block_copyleft
        self._parser = NotebookParser()

    def scan_file(self, path: str) -> NotebookScanResult:
        """Scan a single notebook file through all active plugins."""
        notebook = self._parser.parse(path)
        result = NotebookScanResult(path=path)

        if notebook.error:
            result.error = notebook.error
            return result

        result.cell_count = notebook.cell_count

        for cell in notebook.cells:
            if cell.is_code:
                if self._scan_dangerous:
                    result.findings.extend(dangerous_code_plugin.scan_dangerous_code(cell, path))
                if self._scan_cve:
                    result.findings.extend(cve_plugin.scan_cve(cell, path))
                if self._scan_licenses:
                    result.findings.extend(license_plugin.scan_licenses(cell, path, self._block_copyleft))

            if cell.is_code or cell.is_markdown:
                if self._scan_secrets:
                    result.findings.extend(secrets_plugin.scan_secrets(cell, path))
                if self._scan_pii:
                    result.findings.extend(pii_plugin.scan_pii(cell, path))

            if self._scan_outputs and cell.is_code:
                if self._scan_secrets:
                    result.findings.extend(secrets_plugin.scan_output_secrets(cell, path))
                if self._scan_pii:
                    result.findings.extend(pii_plugin.scan_output_pii(cell, path))

        result.scanned = True
        return result

    def scan_directory(self, directory: str) -> list[NotebookScanResult]:
        """Scan all .ipynb files in a directory tree."""
        results = []
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                if fname.endswith(".ipynb") and ".ipynb_checkpoints" not in root:
                    fpath = os.path.join(root, fname)
                    results.append(self.scan_file(fpath))
        return results

    def scan_files(self, paths: list[str]) -> list[NotebookScanResult]:
        """Scan a list of notebook file paths."""
        return [self.scan_file(p) for p in paths]
