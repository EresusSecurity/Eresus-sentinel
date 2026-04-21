"""
Notebook Output Security Plugin.

Scans Jupyter notebook cell outputs for security-relevant content:
  - Embedded HTML/JavaScript in cell outputs
  - Base64-encoded payloads in display_data
  - Suspicious image/media data
  - Credential leakage in stdout/stderr
  - Exfiltrated data patterns in output
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class OutputFinding:
    """A security finding in notebook output."""
    rule_id: str
    severity: str
    title: str
    description: str
    evidence: str
    cell_index: int
    output_type: str


# Patterns to detect in cell outputs
_OUTPUT_PATTERNS = [
    # HTML/JS injection in outputs
    (re.compile(r"<script[^>]*>.*?</script>", re.I | re.S), "NOTEBOOK-OUT-001", "CRITICAL", "Script tag in cell output"),
    (re.compile(r"<iframe[^>]*>", re.I), "NOTEBOOK-OUT-002", "HIGH", "Iframe in cell output"),
    (re.compile(r"<object[^>]*>", re.I), "NOTEBOOK-OUT-003", "HIGH", "Object tag in cell output"),
    (re.compile(r"<embed[^>]*>", re.I), "NOTEBOOK-OUT-004", "HIGH", "Embed tag in cell output"),
    (re.compile(r"on(?:load|error|click|mouseover)\s*=", re.I), "NOTEBOOK-OUT-005", "HIGH", "Event handler in output"),
    (re.compile(r"javascript:", re.I), "NOTEBOOK-OUT-006", "HIGH", "JavaScript URI in output"),

    # Credential leakage in output
    (re.compile(r"(?:AKIA|A3T)[0-9A-Z]{16}"), "NOTEBOOK-OUT-010", "CRITICAL", "AWS key in cell output"),
    (re.compile(r"ghp_[A-Za-z0-9_]{36}"), "NOTEBOOK-OUT-011", "CRITICAL", "GitHub token in output"),
    (re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ"), "NOTEBOOK-OUT-012", "CRITICAL", "OpenAI key in output"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "NOTEBOOK-OUT-013", "CRITICAL", "Private key in output"),
    (re.compile(r"(?i)password\s*[=:]\s*.{8,}"), "NOTEBOOK-OUT-014", "HIGH", "Password in cell output"),

    # Data exfiltration indicators
    (re.compile(r"https?://[^/]*(?:ngrok|burp|webhook\.site|requestbin|pipedream)", re.I), "NOTEBOOK-OUT-020", "HIGH", "Exfiltration URL in output"),
    (re.compile(r"(?:curl|wget|fetch)\s+https?://", re.I), "NOTEBOOK-OUT-021", "MEDIUM", "HTTP request in output"),

    # Suspicious base64 payloads
    (re.compile(r"(?:[A-Za-z0-9+/]{100,}={0,2})"), "NOTEBOOK-OUT-030", "LOW", "Large base64 blob in output"),
]

# Dangerous MIME types in display_data
_DANGEROUS_MIMETYPES = {
    "text/html",
    "application/javascript",
    "application/x-javascript",
    "image/svg+xml",
}


class OutputPlugin:
    """
    Scan Jupyter notebook cell outputs for security issues.

    Checks:
      - HTML/JavaScript injection in rendered outputs
      - Credential/secret leakage in stdout/stderr
      - Data exfiltration indicators
      - Dangerous MIME types in display_data
      - Suspicious base64 payloads

    Usage:
        plugin = OutputPlugin()
        findings = plugin.scan(notebook_dict)
    """

    def scan(self, notebook: dict) -> list[OutputFinding]:
        """Scan all cell outputs in a notebook."""
        findings = []

        for idx, cell in enumerate(notebook.get("cells", [])):
            if cell.get("cell_type") != "code":
                continue

            outputs = cell.get("outputs", [])
            for output in outputs:
                output_type = output.get("output_type", "unknown")

                if output_type == "stream":
                    text = output.get("text", "")
                    if isinstance(text, list):
                        text = "".join(text)
                    findings.extend(self._scan_text(text, idx, "stream"))

                elif output_type in ("display_data", "execute_result"):
                    data = output.get("data", {})
                    findings.extend(self._scan_display_data(data, idx, output_type))

                elif output_type == "error":
                    traceback = output.get("traceback", [])
                    tb_text = "\n".join(traceback) if isinstance(traceback, list) else str(traceback)
                    findings.extend(self._scan_text(tb_text, idx, "error"))

        return findings

    def _scan_text(self, text: str, cell_idx: int, output_type: str) -> list[OutputFinding]:
        """Scan text output for patterns."""
        findings = []
        for pattern, rule_id, severity, title in _OUTPUT_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(OutputFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=f"Detected in cell[{cell_idx}] {output_type} output",
                    evidence=match.group(0)[:200],
                    cell_index=cell_idx,
                    output_type=output_type,
                ))
        return findings

    def _scan_display_data(self, data: dict, cell_idx: int, output_type: str) -> list[OutputFinding]:
        """Scan display_data MIME types and content."""
        findings = []

        for mime_type, content in data.items():
            # Check dangerous MIME types
            if mime_type in _DANGEROUS_MIMETYPES:
                text = content if isinstance(content, str) else "".join(content) if isinstance(content, list) else ""
                findings.append(OutputFinding(
                    rule_id="NOTEBOOK-OUT-040",
                    severity="MEDIUM",
                    title=f"Dangerous MIME type: {mime_type}",
                    description=f"Cell[{cell_idx}] contains {mime_type} output which can execute code",
                    evidence=text[:200],
                    cell_index=cell_idx,
                    output_type=output_type,
                ))

                # Also scan the content for specific patterns
                findings.extend(self._scan_text(text, cell_idx, f"{output_type}/{mime_type}"))

            # Check image/svg+xml specifically for XSS
            if mime_type == "image/svg+xml":
                svg_text = content if isinstance(content, str) else "".join(content) if isinstance(content, list) else ""
                if re.search(r"<script|onload|onerror|javascript:", svg_text, re.I):
                    findings.append(OutputFinding(
                        rule_id="NOTEBOOK-OUT-041",
                        severity="CRITICAL",
                        title="XSS payload in SVG output",
                        description=f"Cell[{cell_idx}] SVG output contains executable JavaScript",
                        evidence=svg_text[:200],
                        cell_index=cell_idx,
                        output_type=output_type,
                    ))

        return findings
