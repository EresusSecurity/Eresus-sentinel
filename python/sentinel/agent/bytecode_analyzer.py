"""Python bytecode analyzer for AI skill security scanning.

Disassembles .pyc files using the ``dis`` module and detects dangerous
opcode patterns such as dynamic code execution, subprocess invocation,
and network socket calls.
"""
from __future__ import annotations

import dis
import logging
import marshal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DANGEROUS_NAMES = frozenset({
    "exec", "eval", "compile", "__import__", "execfile",
    "subprocess", "Popen", "os.system", "os.popen", "os.execve",
    "socket", "urllib", "requests", "httpx", "ftplib", "smtplib",
    "shutil.rmtree", "os.remove", "os.unlink", "os.rename",
    "open", "pickle.loads", "marshal.loads", "yaml.load",
})

_DANGEROUS_OPCODES = frozenset({
    "IMPORT_NAME", "IMPORT_FROM",
    "LOAD_GLOBAL", "LOAD_ATTR",
    "CALL_FUNCTION", "CALL_FUNCTION_KW",
    "CALL_FUNCTION_EX", "CALL_METHOD",
    "CALL", "PUSH_NULL",
})


@dataclass
class BytecodeIssue:
    opcode: str
    name: str
    offset: int
    severity: str
    description: str


@dataclass
class BytecodeAnalysisResult:
    source: str
    parsed: bool = False
    issues: list[BytecodeIssue] = field(default_factory=list)
    dangerous_imports: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def risk_score(self) -> float:
        weights = {"CRITICAL": 0.4, "HIGH": 0.25, "MEDIUM": 0.1, "LOW": 0.05}
        total = sum(weights.get(i.severity, 0.05) for i in self.issues)
        return min(1.0, total)


class BytecodeAnalyzer:
    """Analyze Python bytecode (.pyc) or source (.py) files for dangerous patterns."""

    def analyze_file(self, path: str) -> BytecodeAnalysisResult:
        p = Path(path)
        if not p.exists():
            return BytecodeAnalysisResult(source=path, error=f"File not found: {path}")

        if p.suffix == ".pyc":
            return self._analyze_pyc(path)
        if p.suffix == ".py":
            return self._analyze_source(path)
        return BytecodeAnalysisResult(source=path, error=f"Unsupported extension: {p.suffix}")

    def analyze_source(self, source_code: str, name: str = "<string>") -> BytecodeAnalysisResult:
        try:
            code = compile(source_code, name, "exec")
            return self._inspect_code(code, name)
        except SyntaxError as exc:
            return BytecodeAnalysisResult(
                source=name,
                error=f"SyntaxError: {exc}",
            )

    def _analyze_source(self, path: str) -> BytecodeAnalysisResult:
        try:
            source = Path(path).read_text(errors="ignore")
            return self.analyze_source(source, path)
        except Exception as exc:
            return BytecodeAnalysisResult(source=path, error=str(exc))

    def _analyze_pyc(self, path: str) -> BytecodeAnalysisResult:
        try:
            data = Path(path).read_bytes()
            # pyc header: 4 magic + 4 flags + 4 mtime + 4 size = 16 bytes (3.8+)
            header_size = 16 if sys.version_info >= (3, 8) else 12
            code = marshal.loads(data[header_size:])
            return self._inspect_code(code, path)
        except Exception as exc:
            return BytecodeAnalysisResult(source=path, error=f"Failed to load .pyc: {exc}")

    def _inspect_code(self, code_obj, source: str) -> BytecodeAnalysisResult:
        result = BytecodeAnalysisResult(source=source, parsed=True)
        self._walk_code(code_obj, result)
        return result

    def _walk_code(self, code_obj, result: BytecodeAnalysisResult) -> None:
        instructions = list(dis.get_instructions(code_obj))

        for instr in instructions:
            if instr.opname == "IMPORT_NAME":
                module = instr.argval or ""
                top = module.split(".")[0]
                if top in {
                    "os", "subprocess", "socket", "urllib", "requests",
                    "httpx", "pickle", "marshal", "ctypes", "importlib",
                    "ast", "exec", "eval",
                }:
                    result.dangerous_imports.append(module)
                    result.issues.append(BytecodeIssue(
                        opcode=instr.opname,
                        name=module,
                        offset=instr.offset,
                        severity=_import_severity(top),
                        description=f"Dangerous module imported: {module!r}",
                    ))

            if instr.opname in ("LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR"):
                name = instr.argval or ""
                if name in _DANGEROUS_NAMES:
                    result.issues.append(BytecodeIssue(
                        opcode=instr.opname,
                        name=name,
                        offset=instr.offset,
                        severity="HIGH",
                        description=f"Reference to dangerous builtin/attribute: {name!r}",
                    ))

        for const in code_obj.co_consts:
            if hasattr(const, "co_code"):
                self._walk_code(const, result)

        for nested in getattr(code_obj, "co_consts", []):
            if hasattr(nested, "co_code"):
                self._walk_code(nested, result)


def _import_severity(module_name: str) -> str:
    critical = {"subprocess", "ctypes", "exec", "eval"}
    high = {"os", "socket", "pickle", "marshal", "importlib"}
    if module_name in critical:
        return "CRITICAL"
    if module_name in high:
        return "HIGH"
    return "MEDIUM"
