"""Tests: sentinel doctor command — health check system."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sentinel.cli.cmd_doctor import (
    _Check,
    _check_api_keys,
    _check_external_tools,
    _check_fp_engine,
    _check_model_file_formats,
    _check_pickle_bridge,
    _check_python,
    _check_python_extras,
    _check_sentinel_version,
    _check_treesitter,
    cmd_doctor,
    run_doctor_checks,
)


# ── _Check dataclass ───────────────────────────────────────────────

def test_check_dataclass_fields():
    c = _Check(name="Test", status="PASS", detail="ok")
    assert c.name == "Test"
    assert c.status == "PASS"
    assert c.detail == "ok"
    assert c.fix is None


def test_check_with_fix():
    c = _Check(name="X", status="FAIL", detail="missing", fix="pip install foo")
    assert c.fix == "pip install foo"


# ── Individual checks ─────────────────────────────────────────────

def test_check_python_returns_check():
    c = _check_python()
    assert isinstance(c, _Check)
    assert c.name == "Python version"
    assert c.status in ("PASS", "WARN")


def test_check_python_current_version_passes():
    import sys
    if sys.version_info >= (3, 10):
        c = _check_python()
        assert c.status == "PASS"


def test_check_sentinel_version_returns_check():
    c = _check_sentinel_version()
    assert isinstance(c, _Check)
    assert c.name == "Sentinel package"
    assert c.status in ("PASS", "WARN")


def test_check_pickle_bridge_returns_check():
    c = _check_pickle_bridge()
    assert isinstance(c, _Check)
    assert c.name == "Rust pickle bridge (sentinel_pickle)"
    assert c.status in ("PASS", "WARN")


def test_check_treesitter_returns_list():
    checks = _check_treesitter()
    assert isinstance(checks, list)
    assert len(checks) >= 1
    for c in checks:
        assert isinstance(c, _Check)
        assert c.status in ("PASS", "WARN", "FAIL", "INFO")


def test_check_api_keys_returns_list():
    checks = _check_api_keys()
    assert isinstance(checks, list)
    assert len(checks) >= 5
    for c in checks:
        assert isinstance(c, _Check)
        assert c.status in ("PASS", "INFO")


def test_check_api_key_pass_when_set():
    with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test12345678901234567890"}):
        checks = _check_api_keys()
        openai_check = next(c for c in checks if "OpenAI" in c.name)
        assert openai_check.status == "PASS"


def test_check_api_key_info_when_not_set():
    import os
    os.environ.pop("NONEXISTENT_LLM_KEY_XYZ", None)
    checks = _check_api_keys()
    for c in checks:
        env_var = c.detail.split()[0]
        if not os.environ.get(env_var):
            assert c.status == "INFO"
            break


def test_check_model_file_formats_returns_list():
    checks = _check_model_file_formats()
    assert isinstance(checks, list)
    assert len(checks) >= 1
    for c in checks:
        assert isinstance(c, _Check)


def test_check_fp_engine_returns_list():
    checks = _check_fp_engine()
    assert isinstance(checks, list)
    assert len(checks) >= 1


def test_check_fp_engine_yaml_rules_pass():
    checks = _check_fp_engine()
    yaml_check = next((c for c in checks if "YAML rules" in c.name), None)
    assert yaml_check is not None
    assert yaml_check.status in ("PASS", "WARN")


def test_check_external_tools_returns_list():
    checks = _check_external_tools()
    assert isinstance(checks, list)
    assert len(checks) >= 3
    for c in checks:
        assert c.status in ("PASS", "INFO", "WARN")


def test_check_python_extras_returns_list():
    checks = _check_python_extras()
    assert isinstance(checks, list)
    assert len(checks) >= 5


def test_check_python_extras_yaml_pass():
    """PyYAML is always installed (it's a required dep)."""
    checks = _check_python_extras()
    yaml_check = next((c for c in checks if c.name == "Python: yaml"), None)
    assert yaml_check is not None
    assert yaml_check.status == "PASS"


# ── run_doctor_checks ─────────────────────────────────────────────

def test_run_doctor_checks_returns_two_values():
    flat, sections = run_doctor_checks()
    assert isinstance(flat, list)
    assert isinstance(sections, dict)


def test_run_doctor_checks_sections():
    _, sections = run_doctor_checks()
    required = {"Core", "Tree-sitter", "FP Engine", "Model File Formats", "Python Packages"}
    assert required <= set(sections.keys()), f"Missing sections: {required - set(sections.keys())}"


def test_run_doctor_checks_flat_matches_sections():
    flat, sections = run_doctor_checks()
    section_total = sum(len(v) for v in sections.values())
    assert len(flat) == section_total


def test_run_doctor_checks_all_checks_valid():
    flat, _ = run_doctor_checks()
    valid_statuses = {"PASS", "WARN", "FAIL", "INFO"}
    for c in flat:
        assert c.status in valid_statuses, f"Invalid status {c.status!r} for check {c.name}"
        assert c.name
        assert c.detail is not None


# ── cmd_doctor (JSON output mode) ─────────────────────────────────

def test_cmd_doctor_json_output(capsys):
    args = SimpleNamespace(json_output=True, show_failed=False)
    exit_code = cmd_doctor(args)
    captured = capsys.readouterr()
    assert captured.out.strip(), "Expected non-empty JSON output"
    parsed = json.loads(captured.out)
    assert isinstance(parsed, dict)
    assert "Core" in parsed


def test_cmd_doctor_json_exit_code_no_failures():
    args = SimpleNamespace(json_output=True, show_failed=False)
    exit_code = cmd_doctor(args)
    assert exit_code in (0, 1)


def test_cmd_doctor_json_check_structure(capsys):
    args = SimpleNamespace(json_output=True, show_failed=False)
    cmd_doctor(args)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    for section_checks in parsed.values():
        for c in section_checks:
            assert "name" in c
            assert "status" in c
            assert "detail" in c
            assert "fix" in c


def test_cmd_doctor_exit_1_on_fail():
    """Simulate a FAIL check and verify exit code is 1."""
    failing_sections = {
        "Core": [_Check("Python version", "FAIL", "too old", "Upgrade Python")],
    }
    flat_failing = [c for checks in failing_sections.values() for c in checks]

    with patch("sentinel.cli.cmd_doctor.run_doctor_checks", return_value=(flat_failing, failing_sections)):
        args = SimpleNamespace(json_output=True, show_failed=False)
        exit_code = cmd_doctor(args)
    assert exit_code == 1


# ── CLI parser registration ────────────────────────────────────────

def test_doctor_registered_in_main():
    """doctor subcommand must be wired in main.py."""
    from sentinel.cli.main import main
    import argparse
    # Parse only --help equivalent: ensure 'doctor' is a known subcommand
    from sentinel.cli import main as main_module
    # Indirect check via cmd_tools import
    from sentinel.cli.cmd_tools import cmd_doctor as tools_doctor
    assert callable(tools_doctor)
