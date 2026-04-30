"""JIT script detector for PyTorch TorchScript payloads."""
from __future__ import annotations

from dataclasses import dataclass

from sentinel.finding import Finding, Severity

_TORCHSCRIPT_MAGIC = b"PK"  # ZIP format, TorchScript models are ZIP archives
_TORCHSCRIPT_MANIFEST = "archive/code/"
_DANGEROUS_OPS = frozenset({
    "aten::_unsafe", "prim::PythonOp", "prim::CallFunction",
    "aten::_native_multi_head_attention",
})


@dataclass
class JITAnalysis:
    is_torchscript: bool = False
    has_code: bool = False
    dangerous_ops: list[str] = None
    file_count: int = 0

    def __post_init__(self):
        if self.dangerous_ops is None:
            self.dangerous_ops = []


def analyze_torchscript(data: bytes, filepath: str = "") -> JITAnalysis:
    """Analyze a potential TorchScript archive for dangerous operations."""
    result = JITAnalysis()

    if not data or len(data) < 4:
        return result

    if data[:2] != _TORCHSCRIPT_MAGIC:
        return result

    result.is_torchscript = True

    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            result.file_count = len(zf.namelist())
            for name in zf.namelist():
                if _TORCHSCRIPT_MANIFEST in name:
                    result.has_code = True
                    try:
                        code_content = zf.read(name).decode("utf-8", errors="replace")
                        for op in _DANGEROUS_OPS:
                            if op in code_content:
                                result.dangerous_ops.append(op)
                    except Exception:
                        pass
    except (zipfile.BadZipFile, Exception):
        pass

    return result


def check_jit_safety(data: bytes, filepath: str = "") -> list[Finding]:
    """Check a file for TorchScript safety issues."""
    analysis = analyze_torchscript(data, filepath)
    findings: list[Finding] = []

    if not analysis.is_torchscript:
        return findings

    if analysis.dangerous_ops:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-JIT-001",
            title="TorchScript dangerous operations",
            description=f"TorchScript contains dangerous ops: {', '.join(analysis.dangerous_ops)}",
            severity=Severity.HIGH,
            confidence=0.9,
            target=filepath,
        ))
    elif analysis.has_code:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-JIT-002",
            title="TorchScript embedded code",
            description="TorchScript archive contains embedded code",
            severity=Severity.MEDIUM,
            confidence=0.6,
            target=filepath,
        ))

    return findings
