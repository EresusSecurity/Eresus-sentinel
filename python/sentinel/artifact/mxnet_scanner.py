"""MXNet .params + symbol JSON scanner."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

DANGEROUS_OP_TYPES = [
    "Custom", "_contrib_", "Plugin", "native_", "exec", "eval",
    "system", "popen", "subprocess", "shell",
]
PICKLE_MARKERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]


class MXNetScanner:
    """Scan MXNet .params and symbol JSON files for unsafe operations."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        suffix = path.suffix.lower()
        if suffix == ".params":
            self._scan_params(path, findings)
        elif suffix == ".json" and "symbol" in path.stem.lower():
            self._scan_symbol_json(path, findings)
        return findings

    def _scan_params(self, path: Path, findings: list[Finding]) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            return
        for marker in PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="MXNET-001", title="Pickle stream in MXNet params",
                    description=f"Pickle data at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=str(path),
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-502"],
                ))
                break
        dangerous = [b"__import__", b"os.system", b"subprocess", b"eval(", b"exec("]
        for pat in dangerous:
            if pat in data:
                findings.append(Finding.artifact(
                    rule_id="MXNET-002", title=f"Suspicious string in MXNet params: {pat.decode()}",
                    description="Dangerous pattern in parameter file",
                    severity=Severity.HIGH, target=str(path), evidence=pat.decode(),
                ))
        if len(data) > 50_000_000_000:
            findings.append(Finding.artifact(
                rule_id="MXNET-003", title="Abnormally large MXNet params file",
                description=f"Size: {len(data)/1e9:.1f} GB",
                severity=Severity.MEDIUM, target=str(path),
            ))

    def _scan_symbol_json(self, path: Path, findings: list[Finding]) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError) as e:
            findings.append(Finding.artifact(
                rule_id="MXNET-004", title="Invalid MXNet symbol JSON",
                description=str(e), severity=Severity.MEDIUM, target=str(path),
            ))
            return
        nodes = data.get("nodes", [])
        for node in nodes:
            op = node.get("op", "")
            for dangerous in DANGEROUS_OP_TYPES:
                if dangerous.lower() in op.lower():
                    findings.append(Finding.artifact(
                        rule_id="MXNET-005", title=f"Suspicious MXNet op: {op}",
                        description=f"Node '{node.get('name','')}' uses potentially dangerous op",
                        severity=Severity.HIGH, target=str(path), evidence=op,
                    ))
            attrs = node.get("attrs", {}) or node.get("param", {})
            for k, v in attrs.items():
                if isinstance(v, str) and any(d in v for d in ["eval(", "exec(", "__import__", "system("]):
                    findings.append(Finding.artifact(
                        rule_id="MXNET-006", title="Code injection in MXNet node attributes",
                        description=f"Attribute {k}={v[:100]}",
                        severity=Severity.CRITICAL, target=str(path), evidence=f"{k}={v[:200]}",
                    ))
