"""Skill scanner — analyze agent skills/plugins for dangerous patterns.

YAML-driven detection engine. All detection patterns are loaded from
sentinel/config/skill_patterns.yaml at module load time.

Features:
- 5-tier command safety analysis with 150+ shell command patterns
- Dangerous argument pattern detection
- Trigger analysis (event-driven skill activation risks)
- Cross-skill interaction scanning
- Privilege escalation detection
- Exfiltration pattern detection
- Bytecode analysis for obfuscated payloads
- File magic detection for polyglot/masqueraded files
- Dependency chain risk analysis
- Sandbox escape detection
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CommandRisk(Enum):
    SAFE = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class TriggerType(Enum):
    ON_MESSAGE = auto()
    ON_FILE_CHANGE = auto()
    ON_SCHEDULE = auto()
    ON_WEBHOOK = auto()
    ON_MCP_CALL = auto()
    ON_USER_ACTION = auto()
    ON_ERROR = auto()
    ALWAYS = auto()
    ON_STARTUP = auto()
    ON_SHUTDOWN = auto()
    ON_TIMER = auto()
    ON_SIGNAL = auto()
    ON_DATABASE_CHANGE = auto()
    ON_NETWORK_EVENT = auto()


@dataclass
class SkillFinding:
    skill_name: str
    finding_type: str
    severity: str
    description: str
    location: str = ""
    evidence: str = ""
    cwe: str = ""
    recommendation: str = ""


@dataclass
class SkillMetadata:
    name: str
    description: str = ""
    permissions: list[str] = field(default_factory=list)
    triggers: list[TriggerType] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    file_access: list[str] = field(default_factory=list)
    network_access: list[str] = field(default_factory=list)
    env_access: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    subprocess_calls: list[str] = field(default_factory=list)
    crypto_usage: list[str] = field(default_factory=list)
    risk_score: float = 0.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# YAML-DRIVEN PATTERN LOADING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_DEFAULT_YAML = Path(__file__).resolve().parent.parent / "config" / "skill_patterns.yaml"
_CUSTOM_YAML_ENV = "SENTINEL_SKILL_PATTERNS_PATH"


def _load_patterns(yaml_path: Path | None = None) -> dict[str, Any]:
    """Load pattern registry from YAML."""
    import yaml  # type: ignore[import-untyped]

    path = yaml_path or Path(os.getenv(_CUSTOM_YAML_ENV, str(_DEFAULT_YAML)))
    if not path.is_file():
        logger.warning("Skill patterns YAML not found: %s — using empty registry", path)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    logger.info("Loaded skill patterns from %s", path)
    return data


def _build_command_registry(data: dict) -> dict[CommandRisk, list[tuple[str, str]]]:
    registry: dict[CommandRisk, list[tuple[str, str]]] = {}
    raw = data.get("dangerous_commands", {})
    for level_name, entries in raw.items():
        try:
            level = CommandRisk[level_name]
        except KeyError:
            continue
        registry[level] = [(e["pattern"], e["description"]) for e in entries]
    return registry


def _build_4col_patterns(data: dict, key: str) -> list[tuple[str, str, str, str]]:
    return [
        (e["pattern"], e["description"], e.get("severity", "HIGH"), e.get("cwe", ""))
        for e in data.get(key, [])
    ]


def _build_trigger_registry(data: dict) -> dict[TriggerType, list[str]]:
    registry: dict[TriggerType, list[str]] = {}
    raw = data.get("trigger_patterns", {})
    for ttype_name, patterns in raw.items():
        try:
            ttype = TriggerType[ttype_name]
        except KeyError:
            continue
        registry[ttype] = list(patterns)
    return registry


# Load everything at module import time
_RAW = _load_patterns()
DANGEROUS_COMMANDS: dict[CommandRisk, list[tuple[str, str]]] = _build_command_registry(_RAW)
DANGEROUS_ARG_PATTERNS: list[tuple[str, str, str, str]] = _build_4col_patterns(_RAW, "dangerous_arg_patterns")
PRIVILEGE_ESCALATION_PATTERNS: list[tuple[str, str, str, str]] = _build_4col_patterns(_RAW, "privilege_escalation_patterns")
EXFILTRATION_PATTERNS: list[tuple[str, str, str, str]] = _build_4col_patterns(_RAW, "exfiltration_patterns")
OBFUSCATION_PATTERNS: list[tuple[str, str, str, str]] = _build_4col_patterns(_RAW, "obfuscation_patterns")
SANDBOX_ESCAPE_PATTERNS: list[tuple[str, str, str, str]] = _build_4col_patterns(_RAW, "sandbox_escape_patterns")
DANGEROUS_EXTENSIONS: set[str] = set(_RAW.get("dangerous_extensions", []))
_TRIGGER_REGISTRY: dict[TriggerType, list[str]] = _build_trigger_registry(_RAW)
_CROSS_SKILL_RISKS: list[tuple[str, str, str, str]] = _build_4col_patterns(_RAW, "cross_skill_risks")

# File magic signatures remain inline (binary data cannot be YAML-serialized cleanly)
FILE_MAGIC_SIGNATURES: dict[bytes, tuple[str, str]] = {
    b"\x89PNG\r\n\x1a\n": ("PNG image", "image/png"),
    b"\xff\xd8\xff": ("JPEG image", "image/jpeg"),
    b"GIF87a": ("GIF image (87a)", "image/gif"),
    b"GIF89a": ("GIF image (89a)", "image/gif"),
    b"%PDF": ("PDF document", "application/pdf"),
    b"PK\x03\x04": ("ZIP archive", "application/zip"),
    b"\x1f\x8b": ("Gzip compressed", "application/gzip"),
    b"BZ": ("Bzip2 compressed", "application/x-bzip2"),
    b"\xfd7zXZ\x00": ("XZ compressed", "application/x-xz"),
    b"\x7fELF": ("ELF executable", "application/x-executable"),
    b"MZ": ("PE executable", "application/x-dosexec"),
    b"\xca\xfe\xba\xbe": ("Mach-O fat binary", "application/x-mach-binary"),
    b"\xfe\xed\xfa\xce": ("Mach-O 32-bit", "application/x-mach-binary"),
    b"\xfe\xed\xfa\xcf": ("Mach-O 64-bit", "application/x-mach-binary"),
    b"\x80\x02": ("Python pickle v2", "application/x-python-pickle"),
    b"\x80\x03": ("Python pickle v3", "application/x-python-pickle"),
    b"\x80\x04": ("Python pickle v4", "application/x-python-pickle"),
    b"\x80\x05": ("Python pickle v5", "application/x-python-pickle"),
    b"{\n": ("JSON data", "application/json"),
    b"[": ("JSON array", "application/json"),
    b"---": ("YAML document", "text/yaml"),
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ANALYZER CLASSES (use YAML-loaded data from module-level variables)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CommandSafetyAnalyzer:

    def analyze(self, command: str) -> tuple[CommandRisk, list[SkillFinding]]:
        findings: list[SkillFinding] = []
        max_risk = CommandRisk.SAFE

        for risk_level in (CommandRisk.CRITICAL, CommandRisk.HIGH, CommandRisk.MEDIUM, CommandRisk.LOW):
            for pattern, desc in DANGEROUS_COMMANDS.get(risk_level, []):
                if re.search(pattern, command, re.IGNORECASE):
                    findings.append(SkillFinding(
                        skill_name="command",
                        finding_type="dangerous_command",
                        severity=risk_level.name,
                        description=desc,
                        evidence=command[:200],
                    ))
                    if risk_level.value > max_risk.value:
                        max_risk = risk_level

        for pattern, desc, severity, cwe in DANGEROUS_ARG_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                findings.append(SkillFinding(
                    skill_name="command",
                    finding_type="dangerous_argument",
                    severity=severity,
                    description=desc,
                    evidence=command[:200],
                    cwe=cwe,
                ))

        return max_risk, findings

    def analyze_script(self, script: str, name: str = "script") -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        for lineno, line in enumerate(script.strip().split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            _, line_findings = self.analyze(line)
            for f in line_findings:
                f.skill_name = name
                f.location = f"{name}:{lineno}"
            findings.extend(line_findings)
        return findings


class TriggerAnalyzer:
    """Uses YAML-loaded _TRIGGER_REGISTRY instead of hardcoded patterns."""

    def analyze(self, code: str) -> list[tuple[TriggerType, str, int]]:
        found = []
        for lineno, line in enumerate(code.split("\n"), 1):
            for trigger_type, patterns in _TRIGGER_REGISTRY.items():
                for pat in patterns:
                    if re.search(pat, line):
                        found.append((trigger_type, line.strip(), lineno))
        return found


class CrossSkillScanner:
    """Uses YAML-loaded _CROSS_SKILL_RISKS instead of hardcoded patterns."""

    def scan(self, skill_code: str, skill_name: str) -> list[SkillFinding]:
        findings = []
        for lineno, line in enumerate(skill_code.split("\n"), 1):
            for pat, desc, sev, cwe in _CROSS_SKILL_RISKS:
                if re.search(pat, line):
                    findings.append(SkillFinding(
                        skill_name=skill_name,
                        finding_type="cross_skill_risk",
                        severity=sev,
                        description=desc,
                        location=f"{skill_name}:{lineno}",
                        evidence=line.strip(),
                        cwe=cwe,
                    ))
        return findings


class FileMagicDetector:

    def detect_type(self, data: bytes) -> tuple[str, str]:
        for magic, (desc, mime) in FILE_MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                return desc, mime
        return "Unknown", "application/octet-stream"

    def check_extension_mismatch(self, filename: str, data: bytes) -> Optional[SkillFinding]:
        detected_desc, detected_mime = self.detect_type(data)
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        mime_ext_map = {
            "image/png": {".png"},
            "image/jpeg": {".jpg", ".jpeg"},
            "image/gif": {".gif"},
            "application/pdf": {".pdf"},
            "application/zip": {".zip", ".jar", ".war", ".apk", ".xlsx", ".docx", ".pptx"},
            "application/x-executable": {".so", ".o", ""},
            "application/x-dosexec": {".exe", ".dll", ".sys"},
            "application/x-python-pickle": {".pkl", ".pickle"},
        }

        expected_exts = mime_ext_map.get(detected_mime)
        if expected_exts and ext and ext not in expected_exts:
            return SkillFinding(
                skill_name=filename,
                finding_type="file_type_mismatch",
                severity="HIGH",
                description=f"File extension '{ext}' does not match detected type '{detected_desc}'",
                evidence=f"Detected: {detected_mime}, Extension: {ext}",
                cwe="CWE-434",
            )
        return None

    def is_dangerous_extension(self, filename: str) -> bool:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return ext in DANGEROUS_EXTENSIONS

    def check_polyglot(self, data: bytes) -> list[SkillFinding]:
        findings = []
        detected_types = []
        for magic, (desc, mime) in FILE_MAGIC_SIGNATURES.items():
            if magic in data[:4096]:
                detected_types.append((desc, mime))
        if len(detected_types) > 1:
            type_names = [d[0] for d in detected_types]
            findings.append(SkillFinding(
                skill_name="polyglot_check",
                finding_type="polyglot_file",
                severity="CRITICAL",
                description=f"Potential polyglot file: matches {len(detected_types)} types: {', '.join(type_names)}",
                cwe="CWE-434",
            ))
        return findings


class SkillScanner:

    def __init__(self):
        self._cmd_analyzer = CommandSafetyAnalyzer()
        self._trigger_analyzer = TriggerAnalyzer()
        self._cross_scanner = CrossSkillScanner()
        self._magic_detector = FileMagicDetector()

    def scan_skill(self, code: str, name: str = "unknown") -> list[SkillFinding]:
        findings = []

        for pat, desc, sev, cwe in PRIVILEGE_ESCALATION_PATTERNS:
            for lineno, line in enumerate(code.split("\n"), 1):
                if re.search(pat, line):
                    findings.append(SkillFinding(
                        skill_name=name, finding_type="privilege_escalation",
                        severity=sev, description=desc,
                        location=f"{name}:{lineno}", evidence=line.strip(),
                        cwe=cwe,
                    ))

        for pat, desc, sev, cwe in EXFILTRATION_PATTERNS:
            for lineno, line in enumerate(code.split("\n"), 1):
                if re.search(pat, line):
                    findings.append(SkillFinding(
                        skill_name=name, finding_type="data_exfiltration",
                        severity=sev, description=desc,
                        location=f"{name}:{lineno}", evidence=line.strip(),
                        cwe=cwe,
                    ))

        for pat, desc, sev, cwe in OBFUSCATION_PATTERNS:
            for lineno, line in enumerate(code.split("\n"), 1):
                if re.search(pat, line):
                    findings.append(SkillFinding(
                        skill_name=name, finding_type="code_obfuscation",
                        severity=sev, description=desc,
                        location=f"{name}:{lineno}", evidence=line.strip(),
                        cwe=cwe,
                    ))

        for pat, desc, sev, cwe in SANDBOX_ESCAPE_PATTERNS:
            for lineno, line in enumerate(code.split("\n"), 1):
                if re.search(pat, line):
                    findings.append(SkillFinding(
                        skill_name=name, finding_type="sandbox_escape",
                        severity=sev, description=desc,
                        location=f"{name}:{lineno}", evidence=line.strip(),
                        cwe=cwe,
                    ))

        triggers = self._trigger_analyzer.analyze(code)
        for trigger_type, line, lineno in triggers:
            if trigger_type in (TriggerType.ALWAYS, TriggerType.ON_SCHEDULE, TriggerType.ON_STARTUP):
                findings.append(SkillFinding(
                    skill_name=name, finding_type="dangerous_trigger",
                    severity="MEDIUM",
                    description=f"Skill has {trigger_type.name} trigger",
                    location=f"{name}:{lineno}", evidence=line,
                ))

        findings.extend(self._cross_scanner.scan(code, name))
        return findings

    def scan_command(self, command: str) -> tuple[CommandRisk, list[SkillFinding]]:
        return self._cmd_analyzer.analyze(command)

    def scan_file_bytes(self, filename: str, data: bytes) -> list[SkillFinding]:
        findings = []
        mismatch = self._magic_detector.check_extension_mismatch(filename, data)
        if mismatch:
            findings.append(mismatch)
        findings.extend(self._magic_detector.check_polyglot(data))
        if self._magic_detector.is_dangerous_extension(filename):
            findings.append(SkillFinding(
                skill_name=filename,
                finding_type="dangerous_file_type",
                severity="MEDIUM",
                description="File has potentially dangerous extension",
                evidence=filename,
                cwe="CWE-434",
            ))
        return findings

    def extract_metadata(self, code: str, name: str = "unknown") -> SkillMetadata:
        meta = SkillMetadata(name=name)

        file_pats = [r"open\s*\(['\"]([\\w./\\\\-]+)", r"Path\s*\(['\"]([\\w./\\\\-]+)"]
        for pat in file_pats:
            meta.file_access.extend(m.group(1) for m in re.finditer(pat, code))

        net_pats = [
            r"(?:https?://[^\s'\"]+)",
            r"requests\.\w+\s*\(['\"]([\\w./:?&#=-]+)",
        ]
        for pat in net_pats:
            meta.network_access.extend(m.group(0) for m in re.finditer(pat, code))

        env_pats = [r"os\.getenv\s*\(['\"](\w+)", r"os\.environ\[['\"](\w+)"]
        for pat in env_pats:
            meta.env_access.extend(m.group(1) for m in re.finditer(pat, code))

        import_pat = re.compile(r"(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import)")
        for m in import_pat.finditer(code):
            mod = m.group(1) or m.group(2)
            if mod:
                meta.imports.append(mod)

        subprocess_pat = re.compile(r"(?:subprocess\.\w+|os\.system|os\.popen)\s*\(\s*['\"]([^'\"]+)")
        for m in subprocess_pat.finditer(code):
            meta.subprocess_calls.append(m.group(1))

        crypto_pats = [r"hashlib\.\w+", r"hmac\.\w+", r"Cipher\.\w+", r"Fernet\s*\("]
        for pat in crypto_pats:
            for m in re.finditer(pat, code):
                meta.crypto_usage.append(m.group(0))

        triggers = self._trigger_analyzer.analyze(code)
        meta.triggers = list({t[0] for t in triggers})

        risk_score = 0.0
        findings = self.scan_skill(code, name)
        severity_weights = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5}
        for f in findings:
            risk_score += severity_weights.get(f.severity, 0.0)
        meta.risk_score = min(risk_score, 100.0)

        return meta
