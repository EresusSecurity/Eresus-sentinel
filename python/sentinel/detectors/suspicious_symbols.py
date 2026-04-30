"""
Suspicious symbol detector for pickle globals and module imports.

Detects dangerous module.attribute combinations in pickle bytecode that
indicate potential RCE, data exfiltration, or other malicious behavior.
Works with both text-form GLOBAL opcodes and STACK_GLOBAL references.
"""

from __future__ import annotations

import re
from pathlib import Path

from sentinel.analysis.framework_patterns import is_safe_module
from sentinel.finding import Finding, Severity


class SuspiciousSymbolDetector:
    """Detect suspicious Python symbols in pickle bytecode."""

    # Modules that should NEVER appear in legitimate ML model pickles
    BLOCKED_MODULES: frozenset[str] = frozenset({
        "os", "os.path", "posixpath", "ntpath",
        "sys", "subprocess", "shutil", "signal",
        "socket", "http", "http.client", "urllib", "urllib.request",
        "ftplib", "smtplib", "telnetlib",
        "ctypes", "ctypes.util",
        "code", "codeop", "compile", "compileall",
        "webbrowser", "antigravity",
        "pickle", "shelve", "marshal",
        "importlib", "pkgutil", "runpy",
        "builtins", "__builtin__",
        "nt", "posix",
        "multiprocessing", "threading",
        "tempfile", "glob",
        "zipfile", "tarfile", "gzip", "bz2", "lzma",
    })

    # Specific module.attribute pairs that are high-confidence malicious
    BLOCKED_ATTRS: frozenset[str] = frozenset({
        "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
        "os.execv", "os.execve", "os.execvp", "os.execvpe",
        "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
        "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
        "os.remove", "os.unlink", "os.rmdir", "os.rename",
        "os.chmod", "os.chown", "os.mkdir", "os.makedirs",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_call", "subprocess.check_output",
        "subprocess.getoutput", "subprocess.getstatusoutput",
        "builtins.eval", "builtins.exec", "builtins.compile",
        "builtins.__import__", "builtins.open",
        "__builtin__.eval", "__builtin__.exec",
        "nt.system", "posix.system",
        "webbrowser.open", "webbrowser.open_new",
        "shutil.rmtree", "shutil.move", "shutil.copy",
        "socket.socket", "socket.create_connection",
        "ctypes.cdll", "ctypes.windll", "ctypes.CDLL",
        "marshal.loads", "pickle.loads",
        "importlib.import_module", "importlib.__import__",
        "runpy.run_module", "runpy.run_path",
        "code.interact", "code.compile_command",
    })

    # Regex to extract GLOBAL opcodes: "c<module>\n<name>\n"
    _GLOBAL_RE = re.compile(rb"c([^\n]{1,200})\n([^\n]{1,200})\n")

    # SHORT_BINUNICODE strings that look like module names
    _SHORT_BINUNICODE_RE = re.compile(rb"\x8c([\x01-\xff])([\x20-\x7e]+)")

    def scan_bytes(self, data: bytes, filepath: str = "") -> list[Finding]:
        """Scan pickle bytecode for suspicious symbols."""
        findings: list[Finding] = []

        # Extract text-form GLOBAL references
        for m in self._GLOBAL_RE.finditer(data):
            module = m.group(1).decode(errors="replace")
            attr = m.group(2).decode(errors="replace")
            fqn = f"{module}.{attr}"

            if fqn in self.BLOCKED_ATTRS:
                findings.append(Finding.artifact(
                    rule_id="SYMBOL-001",
                    title=f"Blocked symbol: {fqn}",
                    description=f"Dangerous function {fqn} at offset 0x{m.start():x}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    target=filepath,
                    evidence=fqn,
                ))
            elif module in self.BLOCKED_MODULES:
                findings.append(Finding.artifact(
                    rule_id="SYMBOL-002",
                    title=f"Blocked module: {module}",
                    description=f"Dangerous module {module} imported at offset 0x{m.start():x}",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    target=filepath,
                    evidence=module,
                ))
            elif not is_safe_module(module):
                findings.append(Finding.artifact(
                    rule_id="SYMBOL-003",
                    title=f"Unknown module: {module}",
                    description=(
                        f"Module {module} is not in any known ML framework safe list. "
                        f"Full reference: {fqn}"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    target=filepath,
                    evidence=fqn,
                ))

        return findings

    def scan_file(self, filepath: str) -> list[Finding]:
        """Scan a pickle file for suspicious symbols."""
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return []
        return self.scan_bytes(data, filepath)
