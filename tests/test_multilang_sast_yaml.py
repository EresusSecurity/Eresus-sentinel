"""Tests: YAML rule loading, per-language rules, FP suppression for multilang SAST."""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.sast.multilang_scanner import (
    MultiLangSASTScanner,
    _EXT_TO_LANG,
    _LANG_YAML,
    _RULES_DIR,
    _has_placeholder,
    _is_comment_line,
    _is_test_path,
    _load_yaml_rules,
    _rules_for_lang,
)


# ── Rule file loading ──────────────────────────────────────────────

def test_rules_dir_exists():
    assert _RULES_DIR.exists(), f"rules/sast/ directory not found at {_RULES_DIR}"


def test_common_yaml_loads():
    rules = _load_yaml_rules("common.yaml")
    assert len(rules) >= 5, "common.yaml should have at least 5 rules (API key patterns)"


@pytest.mark.parametrize("lang", ["javascript", "typescript", "java", "go", "ruby", "csharp", "rust", "kotlin", "php"])
def test_lang_yaml_loads(lang):
    yaml_files = _LANG_YAML[lang]
    total = 0
    for yf in yaml_files:
        rules = _load_yaml_rules(yf)
        total += len(rules)
    assert total >= 5, f"{lang} should produce at least 5 rules total"


def test_all_lang_rules_have_required_fields():
    for lang in ["javascript", "typescript", "java", "go", "ruby", "csharp", "rust", "kotlin", "php"]:
        for rule in _rules_for_lang(lang):
            assert rule.rule_id, f"{lang}: rule missing id"
            assert rule.title, f"{lang}/{rule.rule_id}: rule missing title"
            assert rule.pattern is not None, f"{lang}/{rule.rule_id}: rule missing pattern"
            assert rule.severity is not None, f"{lang}/{rule.rule_id}: rule missing severity"
            assert 0.0 <= rule.confidence <= 1.0, f"{lang}/{rule.rule_id}: confidence out of range"


def test_rules_deduplicated():
    """typescript inherits javascript.yaml — common rules should not be duplicated."""
    ts_ids = [r.rule_id for r in _rules_for_lang("typescript")]
    assert len(ts_ids) == len(set(ts_ids)), "duplicate rule IDs in typescript"


def test_common_rules_included_in_all_langs():
    """MLSAST-010 (OpenAI key) should appear in every language."""
    for lang in ["javascript", "java", "go", "ruby", "csharp", "rust", "kotlin", "php"]:
        ids = {r.rule_id for r in _rules_for_lang(lang)}
        assert "MLSAST-010" in ids, f"{lang} missing MLSAST-010 (OpenAI key rule)"


def test_patterns_compile_as_regex():
    """All loaded patterns must be valid compiled regex objects."""
    for lang in _LANG_YAML:
        for rule in _rules_for_lang(lang):
            assert isinstance(rule.pattern, re.Pattern), f"{lang}/{rule.rule_id}: pattern not compiled"


def test_injection_rules_require_file_context():
    """Injection rules (prompt-injection tag) must have require_file_context=True."""
    for lang in ["javascript", "java", "go", "ruby", "csharp", "php"]:
        for rule in _rules_for_lang(lang):
            if "prompt-injection" in rule.tags:
                assert rule.require_file_context, (
                    f"{lang}/{rule.rule_id}: prompt-injection rule missing require_file_context"
                )


def test_api_key_rules_have_high_confidence():
    """Hardcoded credential rules should have confidence >= 0.85."""
    for rule in _rules_for_lang("javascript"):
        if "hardcoded-credential" in rule.tags:
            assert rule.confidence >= 0.85, (
                f"MLSAST-010..015: {rule.rule_id} confidence {rule.confidence} < 0.85"
            )


# ── FP suppression helpers ─────────────────────────────────────────

@pytest.mark.parametrize("lang,line", [
    ("javascript", "// this is a comment"),
    ("javascript", "/* block comment */"),
    ("java", "// Java comment"),
    ("go", "// Go comment"),
    ("ruby", "# Ruby comment"),
    ("php", "# PHP comment"),
    ("php", "// PHP comment"),
])
def test_comment_line_detection(lang, line):
    assert _is_comment_line(line, lang), f"Expected comment line for {lang}: {line!r}"


@pytest.mark.parametrize("lang,line", [
    ("javascript", "const apiKey = 'sk-realkey123456789012345678901234';"),
    ("java", "String key = client.getApiKey();"),
])
def test_non_comment_line_not_suppressed(lang, line):
    assert not _is_comment_line(line, lang)


@pytest.mark.parametrize("path_str", [
    "/project/tests/auth.test.js",
    "/project/__tests__/llm_test.ts",
    "/project/spec/services/chat_spec.rb",
    "/project/src/test/java/ChatServiceTest.java",
    "/project/mocks/openai_mock.go",
])
def test_test_path_detection(path_str):
    assert _is_test_path(Path(path_str)), f"Should be detected as test path: {path_str}"


@pytest.mark.parametrize("path_str", [
    "/project/src/services/chat.ts",
    "/project/lib/openai_client.py",
    "/project/app/controllers/llm_controller.rb",
])
def test_non_test_path_not_suppressed(path_str):
    assert not _is_test_path(Path(path_str))


@pytest.mark.parametrize("line", [
    "sk-example123",
    "api_key = 'YOUR_KEY_HERE'",
    "const token = 'placeholder-token'",
    "# dummy key for testing",
])
def test_placeholder_detection(line):
    assert _has_placeholder(line), f"Should detect placeholder: {line!r}"


# ── Extension to language mapping ──────────────────────────────────

def test_ext_to_lang_coverage():
    expected = {".js", ".ts", ".java", ".go", ".rb", ".cs", ".rs", ".kt", ".php"}
    mapped = set(_EXT_TO_LANG.keys())
    assert expected <= mapped, f"Missing extensions: {expected - mapped}"


# ── Scanner integration — match on synthetic code ──────────────────

def test_scanner_detects_hardcoded_openai_key():
    scanner = MultiLangSASTScanner(min_confidence=0.5)
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write('const client = new OpenAI({ apiKey: "sk-proj-abcdefghij1234567890abcdefghij1234567890" });\n')
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        ids = {finding.rule_id for finding in result.findings}
        assert "MLSAST-010" in ids, f"Expected MLSAST-010 in {ids}"
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_scanner_detects_eval_llm_output():
    scanner = MultiLangSASTScanner(min_confidence=0.5)
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write("import OpenAI from 'openai';\n")
        f.write("const completion = await openai.chat.completions.create({messages});\n")
        f.write("eval(completion);\n")
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        ids = {finding.rule_id for finding in result.findings}
        assert "MLSAST-020" in ids, f"Expected MLSAST-020 in {ids}"
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_scanner_no_findings_on_clean_js():
    scanner = MultiLangSASTScanner(min_confidence=0.5)
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write("function add(a, b) { return a + b; }\n")
        f.write("console.log(add(1, 2));\n")
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        assert result.findings == [], f"Expected no findings on clean code, got {result.findings}"
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_scanner_suppresses_comment_line():
    scanner = MultiLangSASTScanner(min_confidence=0.5)
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write("import OpenAI from 'openai';\n")
        f.write("// eval(completion)  <- example of what NOT to do\n")
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        eval_findings = [fi for fi in result.findings if fi.rule_id == "MLSAST-020"]
        assert eval_findings == [], "Should suppress eval finding on comment line"
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_scanner_skips_oversized_file():
    scanner = MultiLangSASTScanner(max_file_size=10)
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write("X" * 100)
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        assert result.skipped_files >= 1
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_scanner_language_filter():
    scanner = MultiLangSASTScanner(languages=["java"])
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write('const x = "sk-proj-abc12345678901234567890123456789012345678901";\n')
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        assert result.findings == [], "JS file should be skipped when only java language selected"
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_scanner_supported_extensions():
    scanner = MultiLangSASTScanner()
    exts = scanner.supported_extensions()
    assert ".js" in exts
    assert ".java" in exts
    assert ".go" in exts
    assert ".rb" in exts


def test_scanner_result_fields():
    scanner = MultiLangSASTScanner(min_confidence=0.5)
    with tempfile.TemporaryDirectory() as tmpdir:
        result = scanner.scan_path(tmpdir)
        assert result.scanned_files == 0
        assert result.findings == []
        assert result.skipped_files == 0
        assert result.errors == []
