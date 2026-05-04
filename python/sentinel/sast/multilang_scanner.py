"""Multi-language SAST scanner for AI/LLM security patterns.

Covers JS/TS/Java/Go/Ruby/C#/Rust/Kotlin/PHP using per-language YAML rule files.
Rules are loaded from rules/sast/<lang>.yaml + rules/sast/common.yaml.

FP strategy (target ≤ 3%):
- All injection rules guarded by file_context_pattern (LLM library import required)
- All patterns restricted to single-line matching via [^\n]{0,N} bounds
- Comment lines, test files, and placeholder strings suppressed
- API key rules use format-specific anchors (not broad variable name matching)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from sentinel.finding import Finding, Location, Module, Severity

logger = logging.getLogger(__name__)

# ── Language → extension mapping ──────────────────────────────────

LANG_EXTENSIONS: dict[str, list[str]] = {
    "javascript": [".js", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "java":       [".java"],
    "go":         [".go"],
    "ruby":       [".rb"],
    "csharp":     [".cs"],
    "rust":       [".rs"],
    "kotlin":     [".kt", ".kts"],
    "swift":      [".swift"],
    "php":        [".php"],
}

_EXT_TO_LANG: dict[str, str] = {
    ext: lang
    for lang, exts in LANG_EXTENSIONS.items()
    for ext in exts
}

# YAML rule files per language (relative to sentinel/rules/sast/)
_LANG_YAML: dict[str, list[str]] = {
    "javascript": ["javascript.yaml", "common.yaml"],
    "typescript": ["typescript.yaml", "javascript.yaml", "common.yaml"],
    "java":       ["java.yaml", "common.yaml"],
    "go":         ["go.yaml", "common.yaml"],
    "ruby":       ["ruby.yaml", "common.yaml"],
    "csharp":     ["csharp.yaml", "common.yaml"],
    "rust":       ["rust.yaml", "common.yaml"],
    "kotlin":     ["kotlin.yaml", "common.yaml"],
    "swift":      ["common.yaml"],
    "php":        ["php.yaml", "common.yaml"],
}

# Comment-line prefixes per language — lines starting with these are suppressed
_COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "javascript": ("//", "/*", " *", "#"),
    "typescript": ("//", "/*", " *", "#"),
    "java":       ("//", "/*", " *"),
    "go":         ("//", "/*"),
    "ruby":       ("#",),
    "csharp":     ("//", "/*", " *"),
    "rust":       ("//", "/*"),
    "kotlin":     ("//", "/*", " *"),
    "swift":      ("//", "/*"),
    "php":        ("//", "#", "/*", " *"),
}

# Test/example path patterns — files matching are suppressed for injection rules
_TEST_PATH_RE = re.compile(
    r'(?:/|\\)(?:test|tests|spec|specs|__tests__|__mocks__|fixtures|examples?|samples?|'
    r'mock|mocks|stubs?|fakes?|dummies?)(?:/|\\)',
    re.IGNORECASE,
)

# Placeholder strings that indicate a fake key assignment
_PLACEHOLDER_RE = re.compile(
    r'(?:example|placeholder|dummy|fake|test|sample|your[_\-]?(?:api[_\-]?)?key|'
    r'xxx|yyy|zzz|insert|replace|<key>|<token>|<secret>|todo|changeme)',
    re.IGNORECASE,
)


@dataclass
class _CompiledRule:
    rule_id: str
    title: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    owasp_llm: str
    tags: list[str]
    remediation: str
    require_file_context: bool
    context_pattern: Optional[re.Pattern[str]]
    fp_suppress_comment: bool
    fp_suppress_test_path: bool
    fp_suppress_placeholder: bool
    require_insecure_scheme: bool  # only flag http://, not https://


def _severity_from_str(s: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH":     Severity.HIGH,
        "MEDIUM":   Severity.MEDIUM,
        "LOW":      Severity.LOW,
        "INFO":     Severity.INFO,
    }.get(s.upper(), Severity.MEDIUM)


# ── YAML rule loader ───────────────────────────────────────────────

_RULES_DIR = Path(__file__).parent.parent / "rules" / "sast"
_rule_cache: dict[str, list[_CompiledRule]] = {}


def _load_yaml_rules(yaml_file: str) -> list[_CompiledRule]:
    """Load and compile rules from a YAML file (cached)."""
    if yaml_file in _rule_cache:
        return _rule_cache[yaml_file]

    path = _RULES_DIR / yaml_file
    if not path.exists():
        logger.debug("SAST rule file not found: %s", path)
        _rule_cache[yaml_file] = []
        return []

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        logger.warning("Failed to load SAST rule file %s: %s", path, exc)
        _rule_cache[yaml_file] = []
        return []

    file_context_pattern = data.get("file_context_pattern")
    file_ctx_re = re.compile(file_context_pattern, re.IGNORECASE) if file_context_pattern else None

    compiled: list[_CompiledRule] = []
    for rule in data.get("rules", []):
        try:
            pattern_str = rule.get("pattern", "")
            if not pattern_str:
                continue
            pat = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)

            fp = rule.get("fp_suppress", []) or []
            fp_comment = any(isinstance(x, dict) and x.get("comment_line") for x in fp)
            fp_test = any(isinstance(x, dict) and x.get("test_path") for x in fp)
            fp_placeholder = any(isinstance(x, dict) and x.get("in_string_assign_to") for x in fp)

            compiled.append(_CompiledRule(
                rule_id=rule["id"],
                title=rule.get("title", ""),
                description=rule.get("description", ""),
                pattern=pat,
                severity=_severity_from_str(rule.get("severity", "MEDIUM")),
                confidence=float(rule.get("confidence", 0.5)),
                owasp_llm=rule.get("owasp_llm", ""),
                tags=list(rule.get("tags", [])),
                remediation=rule.get("remediation", ""),
                require_file_context=bool(rule.get("require_file_context", False)),
                context_pattern=file_ctx_re,
                fp_suppress_comment=fp_comment,
                fp_suppress_test_path=fp_test,
                fp_suppress_placeholder=fp_placeholder,
                require_insecure_scheme=bool(rule.get("require_insecure_scheme", False)),
            ))
        except Exception as exc:
            logger.warning("Skipping malformed rule %s in %s: %s", rule.get("id", "?"), yaml_file, exc)

    _rule_cache[yaml_file] = compiled
    logger.debug("Loaded %d rules from %s", len(compiled), yaml_file)
    return compiled


def _rules_for_lang(lang: str) -> list[_CompiledRule]:
    """Return deduplicated compiled rules for a language."""
    yaml_files = _LANG_YAML.get(lang, ["common.yaml"])
    seen_ids: set[str] = set()
    rules: list[_CompiledRule] = []
    for yf in yaml_files:
        for r in _load_yaml_rules(yf):
            if r.rule_id not in seen_ids:
                seen_ids.add(r.rule_id)
                rules.append(r)
    return rules


# Legacy: keep MULTILANG_RULES name for backward compat (empty — rules now in YAML)
MULTILANG_RULES: list[_CompiledRule] = []


# ── FP suppression helpers ─────────────────────────────────────────

def _is_comment_line(line: str, lang: str) -> bool:
    stripped = line.lstrip()
    for prefix in _COMMENT_PREFIXES.get(lang, ("//", "#")):
        if stripped.startswith(prefix):
            return True
    return False


def _is_test_path(path: Path) -> bool:
    return bool(_TEST_PATH_RE.search(str(path)))


def _has_placeholder(line: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(line))


def _is_https_line(line: str) -> bool:
    """Return True if line only contains https:// and no bare http://."""
    has_http = bool(re.search(r'http://', line, re.IGNORECASE))
    has_https = bool(re.search(r'https://', line, re.IGNORECASE))
    return has_https and not has_http


# ── Scanner ────────────────────────────────────────────────────────

@dataclass
class MultiLangSASTResult:
    scanned_files: int
    findings: list[Finding]
    skipped_files: int = 0
    errors: list[str] = field(default_factory=list)


class MultiLangSASTScanner:
    """Security-focused SAST scanner for non-Python AI/LLM code.

    Loads rules from per-language YAML files in rules/sast/.
    FP-hardened: file context guards, comment suppression, test path exclusion,
    placeholder suppression, and single-line pattern bounds.

    Args:
        languages: Restrict to specific languages (None = all supported).
        min_confidence: Drop findings below this threshold (default 0.55).
        max_file_size: Skip files larger than this (bytes, default 512 KB).
    """

    def __init__(
        self,
        languages: Optional[list[str]] = None,
        min_confidence: float = 0.55,
        max_file_size: int = 512_000,
    ) -> None:
        self._languages = {lang.lower() for lang in languages} if languages else set()
        self._min_conf = min_confidence
        self._max_size = max_file_size

    def scan_path(self, path: str | Path) -> MultiLangSASTResult:
        """Scan a file or directory for multi-language LLM security issues."""
        p = Path(path)
        files = [p] if p.is_file() else [
            f for f in p.rglob("*")
            if f.is_file() and f.suffix.lower() in _EXT_TO_LANG
        ]

        all_findings: list[Finding] = []
        skipped = 0
        errors: list[str] = []

        for f in files:
            lang = _EXT_TO_LANG.get(f.suffix.lower())
            if not lang:
                continue
            if self._languages and lang not in self._languages:
                continue
            try:
                sz = f.stat().st_size
            except OSError:
                continue
            if sz > self._max_size:
                skipped += 1
                continue
            try:
                findings = self._scan_file(f, lang)
                all_findings.extend(findings)
            except Exception as exc:
                errors.append(f"{f}: {exc}")
                logger.debug("MultiLangSAST error on %s: %s", f, exc, exc_info=True)

        return MultiLangSASTResult(
            scanned_files=len(files) - skipped,
            findings=all_findings,
            skipped_files=skipped,
            errors=errors,
        )

    def _scan_file(self, path: Path, lang: str) -> list[Finding]:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        is_test = _is_test_path(path)

        findings: list[Finding] = []
        for rule in _rules_for_lang(lang):
            if rule.confidence < self._min_conf:
                continue

            # File-level context guard: skip injection rules in non-LLM files
            if rule.require_file_context and rule.context_pattern:
                if not rule.context_pattern.search(text):
                    continue

            for match in rule.pattern.finditer(text):
                line_no = text[:match.start()].count("\n") + 1
                line_text = lines[line_no - 1] if line_no <= len(lines) else ""

                # FP: skip comment lines
                if rule.fp_suppress_comment and _is_comment_line(line_text, lang):
                    continue

                # FP: skip test/spec/fixture files
                if rule.fp_suppress_test_path and is_test:
                    continue

                # FP: skip placeholder/example values
                if rule.fp_suppress_placeholder and _has_placeholder(line_text):
                    continue

                # FP: for model URL rules, skip https:// lines (only flag http://)
                if rule.require_insecure_scheme and not re.search(r'\bhttp://', line_text, re.IGNORECASE):
                    continue

                findings.append(Finding(
                    rule_id=rule.rule_id,
                    module=Module.SAST.value,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    category="Multi-Language SAST",
                    target=str(path),
                    location=Location(
                        file=str(path),
                        line_start=line_no,
                        line_end=line_no,
                    ),
                    evidence=f"line {line_no}: {line_text.strip()[:200]}",
                    remediation=rule.remediation,
                    owasp_llm=rule.owasp_llm,
                    tags=list(rule.tags) + [f"lang:{lang}"],
                ))

        return self._deduplicate(findings)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[str] = set()
        out: list[Finding] = []
        for f in findings:
            key = f"{f.rule_id}:{f.target}:{getattr(f.location, 'line_start', 0)}"
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    def supported_extensions(self) -> list[str]:
        if not self._languages:
            return list(_EXT_TO_LANG.keys())
        return [ext for ext, lang in _EXT_TO_LANG.items() if lang in self._languages]
