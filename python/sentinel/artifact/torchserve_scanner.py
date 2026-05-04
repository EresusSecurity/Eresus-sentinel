"""TorchServe .mar, Torch7 .t7/.th/.net, ExecuTorch .pte, TensorRT .engine scanners."""
from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)
PICKLE_MARKERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
DANGEROUS_STRINGS = [b"__import__", b"os.system", b"subprocess", b"eval(", b"exec(", b"/bin/sh", b"/bin/bash"]


class TorchServeScanner:
    """Scan TorchServe .mar archives for handler and dependency risks."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".mar":
            return findings
        if not zipfile.is_zipfile(str(path)):
            findings.append(Finding.artifact(rule_id="MAR-001", title="Invalid MAR archive", description="Not a ZIP", severity=Severity.HIGH, target=filepath))
            return findings
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith("/"):
                        findings.append(Finding.artifact(rule_id="MAR-002", title="Path traversal in MAR", description=f"Path: {info.filename}", severity=Severity.CRITICAL, target=filepath, cwe_ids=["CWE-22"]))
                if "MAR-INF/MANIFEST.json" in zf.namelist():
                    try:
                        manifest = json.loads(zf.read("MAR-INF/MANIFEST.json"))
                        handler = manifest.get("model", {}).get("handler", "")
                        if handler and any(d in handler for d in ["eval", "exec", "system", "subprocess"]):
                            findings.append(Finding.artifact(rule_id="MAR-003", title=f"Suspicious handler: {handler}", description="Handler references dangerous functions", severity=Severity.CRITICAL, target=filepath, evidence=handler))
                    except json.JSONDecodeError:
                        findings.append(Finding.artifact(rule_id="MAR-004", title="Invalid MAR manifest", description="Cannot parse MANIFEST.json", severity=Severity.MEDIUM, target=filepath))
                for name in zf.namelist():
                    if name.endswith((".py", ".sh")):
                        data = zf.read(name)[:20000]
                        for pat in DANGEROUS_STRINGS:
                            if pat in data:
                                findings.append(Finding.artifact(
                                    rule_id="MAR-008",
                                    title=f"Dangerous handler code in MAR: {name}",
                                    description=f"TorchServe handler contains dangerous pattern {pat.decode(errors='replace')}",
                                    severity=Severity.CRITICAL,
                                    target=filepath,
                                    evidence=f"{name}:{pat.decode(errors='replace')}",
                                    cwe_ids=["CWE-94"],
                                ))
                                break
                    if name.endswith((".pkl", ".pickle", ".pt", ".pth")):
                        data = zf.read(name)[:10000]
                        for m in PICKLE_MARKERS:
                            if m in data:
                                findings.append(Finding.artifact(rule_id="MAR-005", title=f"Pickle in MAR: {name}", description="Pickle data in model archive", severity=Severity.HIGH, target=filepath, evidence=name, cwe_ids=["CWE-502"]))
                                break
                    if name == "requirements.txt":
                        reqs = zf.read(name).decode(errors="replace")
                        if any(d in reqs for d in ["--index-url", "--extra-index-url", "git+", "http://"]):
                            findings.append(Finding.artifact(rule_id="MAR-006", title="Suspicious requirements in MAR", description="Requirements may pull from untrusted source", severity=Severity.HIGH, target=filepath, evidence=reqs[:200]))
        except zipfile.BadZipFile:
            findings.append(Finding.artifact(rule_id="MAR-007", title="Corrupted MAR", description="Bad ZIP", severity=Severity.HIGH, target=filepath))
        return findings


class Torch7Scanner:
    """Scan legacy Torch7 .t7/.th/.net files for Lua execution threats."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in (".t7", ".th", ".net"):
            return findings
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        lua_patterns = [b"loadstring(", b"dofile(", b"os.execute(", b"io.popen(", b"require(", b"loadfile("]
        for pat in lua_patterns:
            idx = data.find(pat)
            if idx != -1:
                findings.append(Finding.artifact(rule_id="T7-001", title=f"Lua code execution in Torch7: {pat.decode()}", description=f"Found at offset 0x{idx:x}", severity=Severity.CRITICAL, target=filepath, evidence=pat.decode()))
        for pat in DANGEROUS_STRINGS:
            if pat in data:
                findings.append(Finding.artifact(rule_id="T7-002", title=f"Suspicious string in Torch7: {pat.decode()}", description="Dangerous pattern", severity=Severity.HIGH, target=filepath))
        return findings


class ExecuTorchScanner:
    """Scan ExecuTorch .pte flatbuffer files for security issues."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in (".pte", ".ptl"):
            return findings
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        if len(data) < 8:
            findings.append(Finding.artifact(rule_id="EXECUTORCH-001", title="ExecuTorch file too small", description="File smaller than FlatBuffer header", severity=Severity.MEDIUM, target=filepath))
            return findings
        for pat in DANGEROUS_STRINGS:
            idx = data.find(pat)
            if idx != -1:
                findings.append(Finding.artifact(rule_id="EXECUTORCH-002", title=f"Suspicious string in ExecuTorch: {pat.decode()}", description=f"At offset 0x{idx:x}", severity=Severity.HIGH, target=filepath))
        custom_ops = [b"custom_op", b"aten::_custom", b"external_call"]
        for op in custom_ops:
            if op in data:
                findings.append(Finding.artifact(rule_id="EXECUTORCH-003", title=f"Custom op in ExecuTorch: {op.decode()}", description="Custom operators may execute arbitrary code", severity=Severity.MEDIUM, target=filepath, evidence=op.decode()))
        return findings


class TensorRTScanner:
    """Scan TensorRT .engine/.plan serialized files for integrity issues."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in (".engine", ".plan", ".trt"):
            return findings
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        plugin_refs = [b"nvinfer", b"IPluginV2", b"IPluginCreator", b"getPluginName"]
        for ref in plugin_refs:
            if ref in data:
                findings.append(Finding.artifact(rule_id="TRT-001", title=f"TensorRT plugin reference: {ref.decode()}", description="Plugin may load system libraries", severity=Severity.MEDIUM, target=filepath, evidence=ref.decode()))
        for pat in DANGEROUS_STRINGS:
            if pat in data:
                findings.append(Finding.artifact(rule_id="TRT-002", title=f"Suspicious string in TensorRT: {pat.decode()}", description="Dangerous pattern in engine", severity=Severity.HIGH, target=filepath))
        for label, magic in [("ELF", b"\x7fELF"), ("PE", b"MZ")]:
            idx = data.find(magic)
            if idx > 16:
                findings.append(Finding.artifact(rule_id="TRT-003", title=f"Embedded {label} in TensorRT engine", description=f"At offset 0x{idx:x}", severity=Severity.CRITICAL, target=filepath, cwe_ids=["CWE-506"]))
        return findings
