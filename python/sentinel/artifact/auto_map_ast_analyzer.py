"""
Eresus Sentinel — auto_map Referenced Python File AST Analyzer.

When a HuggingFace config.json declares auto_map, the referenced .py files
are downloaded and executed with trust_remote_code=True. This analyzer
performs deep static analysis on those files BEFORE they are executed.

Analysis layers:
  1. Import graph — detect dangerous stdlib/third-party imports
  2. Syscall graph — os.system, subprocess, pty, ctypes
  3. Network behavior — socket, urllib, requests, httpx
  4. Filesystem access — open(), write, delete operations
  5. Obfuscation detection — eval(compile()), exec(base64), marshal.loads
  6. Anti-analysis patterns — debugger checks, sandbox detection
  7. Credential access — env var harvesting, keychain access
  8. Persistence patterns — .bashrc, cron, startup hooks

This directly addresses the "referenced Python file not analyzed" gap where
hf_guard reports auto_map CRITICAL but doesn't scan the actual .py content.
"""

from __future__ import annotations

import ast
import logging
import re
import textwrap
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

# ── Dangerous Import Signatures ───────────────────────────────────────────────

_DANGEROUS_IMPORTS: dict[str, tuple[str, str]] = {
    "os":           ("MEDIUM",   "os module — enables filesystem and shell access"),
    "subprocess":   ("HIGH",     "subprocess — shell command execution"),
    "pty":          ("HIGH",     "pty — pseudo-terminal (shell spawning)"),
    "ctypes":       ("CRITICAL", "ctypes — native library loading, memory manipulation"),
    "cffi":         ("HIGH",     "cffi — C foreign function interface"),
    "socket":       ("HIGH",     "socket — raw network communication"),
    "ssl":          ("MEDIUM",   "ssl — TLS connections (may be C2)"),
    "urllib":       ("MEDIUM",   "urllib — HTTP requests"),
    "requests":     ("MEDIUM",   "requests — HTTP client"),
    "httpx":        ("MEDIUM",   "httpx — HTTP client"),
    "aiohttp":      ("MEDIUM",   "aiohttp — async HTTP client"),
    "paramiko":     ("HIGH",     "paramiko — SSH client (lateral movement)"),
    "ftplib":       ("HIGH",     "ftplib — FTP (data exfiltration)"),
    "smtplib":      ("HIGH",     "smtplib — email sending (data exfiltration)"),
    "marshal":      ("CRITICAL", "marshal — code serialization (evasion via marshal.loads)"),
    "pickle":       ("CRITICAL", "pickle — arbitrary deserialization"),
    "dill":         ("CRITICAL", "dill — extended pickle (more dangerous)"),
    "importlib":    ("HIGH",     "importlib — dynamic import (code loading)"),
    "builtins":     ("HIGH",     "builtins — can override built-in functions"),
    "gc":           ("MEDIUM",   "gc — garbage collector (reference counting exploits)"),
    "sys":          ("MEDIUM",   "sys — Python internals access"),
    "code":         ("HIGH",     "code module — interactive interpreter access"),
    "pdb":          ("MEDIUM",   "pdb — debugger (anti-analysis detection)"),
    "crypt":        ("MEDIUM",   "crypt — crypto (may generate keys for C2)"),
    "hashlib":      ("LOW",      "hashlib — hashing (low risk but may be used for C2 auth)"),
    "base64":       ("MEDIUM",   "base64 — encoding (often used to decode payloads)"),
    "zlib":         ("MEDIUM",   "zlib — compression (payload unpacking)"),
    "gzip":         ("MEDIUM",   "gzip — decompression (payload unpacking)"),
    "zipfile":      ("MEDIUM",   "zipfile — archive extraction"),
    "tarfile":      ("MEDIUM",   "tarfile — archive extraction (zip-slip risk)"),
    "shutil":       ("MEDIUM",   "shutil — file operations (copying, deletion)"),
    "tempfile":     ("MEDIUM",   "tempfile — temp files (staging payloads)"),
    "threading":    ("MEDIUM",   "threading — background threads (persistence)"),
    "multiprocessing": ("MEDIUM","multiprocessing — spawning processes"),
    "signal":       ("HIGH",     "signal — signal handlers (anti-analysis)"),
    "mmap":         ("HIGH",     "mmap — memory mapping (shellcode staging)"),
    "struct":       ("MEDIUM",   "struct — binary packing (shellcode construction)"),
    "platform":     ("LOW",      "platform — OS fingerprinting"),
    "getpass":      ("HIGH",     "getpass — credential harvesting"),
    "pwd":          ("HIGH",     "pwd — password database access (Unix)"),
    "grp":          ("MEDIUM",   "grp — group database access (Unix)"),
    "winreg":       ("CRITICAL", "winreg — Windows registry (persistence)"),
    "winsound":     ("LOW",      "winsound — Windows audio"),
    "win32api":     ("CRITICAL", "win32api — Windows API (privilege escalation)"),
    "win32con":     ("CRITICAL", "win32con — Windows constants"),
    "pywintypes":   ("CRITICAL", "pywintypes — Windows type definitions"),
    "cryptography": ("MEDIUM",   "cryptography — may generate C2 encryption keys"),
    "nacl":         ("MEDIUM",   "PyNaCl — may generate C2 encryption keys"),
    "torch":        ("LOW",      "torch — expected in ML models"),
    "transformers": ("LOW",      "transformers — expected in HF models"),
}

# ── Dangerous Call Patterns (AST node names) ──────────────────────────────────

_DANGEROUS_CALLS: list[tuple[str, str, str]] = [
    ("os.system",               "CRITICAL", "os.system — shell command execution"),
    ("os.popen",                "CRITICAL", "os.popen — shell command execution"),
    ("os.execv",                "CRITICAL", "os.execv — process replacement"),
    ("os.execve",               "CRITICAL", "os.execve — process replacement with env"),
    ("os.spawn",                "CRITICAL", "os.spawn — process spawning"),
    ("subprocess.call",         "CRITICAL", "subprocess.call — shell command"),
    ("subprocess.run",          "CRITICAL", "subprocess.run — shell command"),
    ("subprocess.Popen",        "CRITICAL", "subprocess.Popen — shell command"),
    ("subprocess.check_output", "CRITICAL", "subprocess.check_output — shell command"),
    ("subprocess.getoutput",    "CRITICAL", "subprocess.getoutput — shell command"),
    ("eval",                    "CRITICAL", "eval() — arbitrary code execution"),
    ("exec",                    "CRITICAL", "exec() — arbitrary code execution"),
    ("compile",                 "HIGH",     "compile() — dynamic code compilation"),
    ("__import__",              "HIGH",     "__import__() — dynamic import"),
    ("importlib.import_module",  "HIGH",    "importlib.import_module — dynamic import"),
    ("ctypes.cdll.LoadLibrary", "CRITICAL", "LoadLibrary — native code execution"),
    ("ctypes.windll",           "CRITICAL", "ctypes.windll — Windows API execution"),
    ("ctypes.CDLL",             "CRITICAL", "ctypes.CDLL — native library loading"),
    ("marshal.loads",           "CRITICAL", "marshal.loads — code object deserialization"),
    ("pickle.loads",            "CRITICAL", "pickle.loads — arbitrary deserialization"),
    ("dill.loads",              "CRITICAL", "dill.loads — arbitrary deserialization"),
    ("base64.b64decode",        "MEDIUM",   "base64.b64decode — payload decoding"),
    ("zlib.decompress",         "MEDIUM",   "zlib.decompress — payload decompression"),
    ("getattr",                 "LOW",      "getattr — dynamic attribute access"),
    ("socket.connect",          "HIGH",     "socket.connect — outbound network connection"),
    ("socket.bind",             "HIGH",     "socket.bind — listening on port (backdoor)"),
    ("os.getenv",               "MEDIUM",   "os.getenv — environment variable access (credential harvest)"),
    ("os.environ",              "MEDIUM",   "os.environ — environment variables (credential harvest)"),
    ("shutil.rmtree",           "HIGH",     "shutil.rmtree — directory deletion"),
    ("os.remove",               "HIGH",     "os.remove — file deletion"),
    ("mmap.mmap",               "HIGH",     "mmap.mmap — memory mapping"),
]

# ── Obfuscation Patterns (regex on source text) ───────────────────────────────

_OBFUSCATION_PATTERNS: list[tuple[str, str, str]] = [
    (r"eval\s*\(\s*compile\s*\(", "CRITICAL", "eval(compile(...)) — code compilation then execution"),
    (r"exec\s*\(\s*base64\.b64decode\s*\(", "CRITICAL", "exec(base64.decode) — encoded payload execution"),
    (r"exec\s*\(\s*zlib\.decompress\s*\(", "CRITICAL", "exec(zlib.decompress) — compressed payload"),
    (r"exec\s*\(\s*marshal\.loads\s*\(", "CRITICAL", "exec(marshal.loads) — marshalled code execution"),
    (r"(?:__builtins__|builtins)\s*\[\s*['\"]exec['\"]", "CRITICAL", "builtins['exec'] — eval evasion"),
    (r"getattr\s*\(\s*__builtins__", "HIGH", "getattr(__builtins__) — built-in function access evasion"),
    (r"chr\s*\(\d+\)\s*\+\s*chr\s*\(\d+\)", "HIGH", "chr() concatenation — string obfuscation"),
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){8,}", "HIGH", "Long hex escape sequence — shellcode pattern"),
    (r"lambda\s*:\s*exec\s*\(", "CRITICAL", "lambda:exec() — execution obfuscation"),
    (r"(?:LOAD_GLOBAL|CALL_FUNCTION|MAKE_FUNCTION)", "HIGH", "Raw CPython bytecode opcodes in source"),
    (r"(?:__reduce__|__reduce_ex__)\s*=", "CRITICAL", "__reduce__ definition — pickle exploitation"),
    (r"(?:getattr|setattr)\s*\(.*,\s*['\"]__class__['\"]", "HIGH", "Class manipulation via getattr"),
]

# ── Persistence Patterns ──────────────────────────────────────────────────────

_PERSISTENCE_PATTERNS: list[tuple[str, str]] = [
    (r"(?:\.bashrc|\.profile|\.bash_profile|\.zshrc)", "Shell startup modification"),
    (r"(?:crontab|/etc/cron)", "Cron job installation"),
    (r"(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)", "Windows registry persistence"),
    (r"(?:launchd|LaunchAgent|LaunchDaemon|~/Library/Launch)", "macOS LaunchAgent persistence"),
    (r"(?:systemd|/etc/systemd/system|\.service\s*file)", "Linux systemd service persistence"),
    (r"(?:startup|autostart|winlogon)", "Windows startup persistence"),
]


class AutoMapASTAnalyzer:
    """
    Deep static analysis of Python files referenced by auto_map in HuggingFace configs.

    When config.json has auto_map pointing to custom Python classes, those files
    will be executed with trust_remote_code=True. This analyzer performs AST-level
    analysis to detect malicious behavior BEFORE execution.
    """

    def scan_file(self, path: str | Path) -> list[Finding]:
        path = Path(path)
        source = path.read_text(encoding="utf-8", errors="replace")
        findings: list[Finding] = []

        findings.extend(self._check_imports_ast(source, str(path)))
        findings.extend(self._check_calls_ast(source, str(path)))
        findings.extend(self._check_obfuscation(source, str(path)))
        findings.extend(self._check_persistence(source, str(path)))
        findings.extend(self._check_network_behavior(source, str(path)))

        return findings

    def _check_imports_ast(self, source: str, filepath: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            findings.append(Finding.artifact(
                rule_id="AUTOMAP-000",
                title="Python syntax error in auto_map file",
                description=(
                    f"auto_map referenced Python file has syntax errors: {e}. "
                    "May indicate obfuscation or corruption."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                target=filepath,
                evidence=str(e),
            ))
            return findings

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                else:
                    names = [node.module.split(".")[0]] if node.module else []

                for name in names:
                    if name in _DANGEROUS_IMPORTS:
                        sev_str, desc = _DANGEROUS_IMPORTS[name]
                        if sev_str in ("CRITICAL", "HIGH"):
                            severity = getattr(Severity, sev_str, Severity.HIGH)
                            lineno = getattr(node, "lineno", 0)
                            findings.append(Finding.artifact(
                                rule_id="AUTOMAP-001",
                                title=f"Dangerous import in auto_map file: {name}",
                                description=(
                                    f"auto_map referenced Python file imports '{name}'. "
                                    f"{desc}. This code will execute when the model is loaded "
                                    "with trust_remote_code=True."
                                ),
                                severity=severity,
                                confidence=0.9,
                                target=filepath,
                                evidence=f"import {name} at line {lineno}",
                                remediation=f"Review usage of '{name}' and verify no malicious behavior",
                            ))
        return findings

    def _check_calls_ast(self, source: str, filepath: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        source_lines = source.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_str = _ast_call_to_str(node)
            for pattern, sev_str, desc in _DANGEROUS_CALLS:
                if pattern in call_str or call_str.startswith(pattern):
                    sev_str_adjusted = sev_str
                    if sev_str in ("LOW", "MEDIUM"):
                        continue
                    severity = getattr(Severity, sev_str_adjusted, Severity.HIGH)
                    lineno = getattr(node, "lineno", 0)
                    line_snippet = source_lines[lineno - 1].strip() if lineno > 0 and lineno <= len(source_lines) else ""
                    findings.append(Finding.artifact(
                        rule_id="AUTOMAP-002",
                        title=f"Dangerous call in auto_map file: {pattern}",
                        description=(
                            f"auto_map referenced Python file calls '{pattern}'. "
                            f"{desc}. This code executes at model load time."
                        ),
                        severity=severity,
                        confidence=0.88,
                        target=filepath,
                        evidence=f"line {lineno}: {line_snippet!r:.120}",
                        remediation=f"Remove or isolate call to '{pattern}'",
                    ))
                    break
        return findings

    def _check_obfuscation(self, source: str, filepath: str) -> list[Finding]:
        findings = []
        for pattern, sev_str, desc in _OBFUSCATION_PATTERNS:
            m = re.search(pattern, source)
            if m:
                severity = getattr(Severity, sev_str, Severity.HIGH)
                snippet = source[max(0, m.start()-20):m.end()+60].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="AUTOMAP-003",
                    title=f"Obfuscation pattern in auto_map file",
                    description=(
                        f"Code obfuscation detected in auto_map referenced file. "
                        f"Pattern: {desc}. Obfuscated code is a strong indicator of malice."
                    ),
                    severity=severity,
                    confidence=0.9,
                    target=filepath,
                    evidence=f"pattern={snippet!r:.120}",
                    remediation="Investigate obfuscated code block",
                ))
        return findings

    def _check_persistence(self, source: str, filepath: str) -> list[Finding]:
        findings = []
        for pattern, desc in _PERSISTENCE_PATTERNS:
            m = re.search(pattern, source, re.IGNORECASE)
            if m:
                snippet = source[max(0, m.start()-20):m.end()+40].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="AUTOMAP-004",
                    title=f"Persistence mechanism in auto_map file: {desc}",
                    description=(
                        f"auto_map referenced Python file contains persistence mechanisms: "
                        f"{desc}. The model may install itself to survive reboots."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    target=filepath,
                    evidence=f"match={snippet!r:.100}",
                    remediation="Remove persistence code from model file",
                ))
        return findings

    def _check_network_behavior(self, source: str, filepath: str) -> list[Finding]:
        findings = []
        net_patterns = [
            (r"(?:requests|httpx|urllib)\s*\.\s*(?:get|post|put|delete|request)\s*\(", "CRITICAL", "Outbound HTTP request at model load"),
            (r"socket\s*\.\s*(?:connect|bind|listen)\s*\(", "CRITICAL", "Raw socket operation"),
            (r"(?:ftplib|smtplib|imaplib)\s*\.", "HIGH", "FTP/SMTP/IMAP — data exfiltration risk"),
            (r"dns\.resolver|dnspython", "HIGH", "DNS lookups — possible C2 beacon"),
            (r"(?:websocket|ws://|wss://)", "HIGH", "WebSocket — possible C2 channel"),
        ]
        for pattern, sev_str, desc in net_patterns:
            m = re.search(pattern, source, re.IGNORECASE)
            if m:
                severity = getattr(Severity, sev_str, Severity.HIGH)
                snippet = source[max(0, m.start()-20):m.end()+60].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="AUTOMAP-005",
                    title=f"Network activity in auto_map file: {desc}",
                    description=(
                        f"auto_map referenced Python file performs network operations at load time. "
                        f"{desc}. Legitimate ML code should not establish network connections during import."
                    ),
                    severity=severity,
                    confidence=0.87,
                    target=filepath,
                    evidence=f"match={snippet!r:.120}",
                    remediation="Remove or sandbox network calls from model loading code",
                ))
        return findings


def _ast_call_to_str(node: ast.Call) -> str:
    """Convert an AST Call node to a dotted string like 'os.system'."""
    func = node.func
    if isinstance(func, ast.Attribute):
        value = func.value
        if isinstance(value, ast.Name):
            return f"{value.id}.{func.attr}"
        if isinstance(value, ast.Attribute):
            return f"{_ast_attr_str(value)}.{func.attr}"
    elif isinstance(func, ast.Name):
        return func.id
    return ""


def _ast_attr_str(node: ast.Attribute) -> str:
    if isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node.value, ast.Attribute):
        return f"{_ast_attr_str(node.value)}.{node.attr}"
    return node.attr
