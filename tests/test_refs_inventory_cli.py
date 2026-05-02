import json
import os
import subprocess
import sys

import pytest

from sentinel.refs import (
    EXPECTED_REFERENCE_REPOS,
    REFERENCE_PHASES,
    available_refs_dirs,
    default_refs_dir,
    refs_inventory_json,
    refs_plan_json,
)

_HAS_REFS = bool(available_refs_dirs(os.getcwd()))
_skip_no_refs = pytest.mark.skipif(
    not _HAS_REFS,
    reason="no reference clone directory present",
)


@_skip_no_refs
def test_refs_inventory_covers_requested_repositories():
    refs_dir = default_refs_dir(os.getcwd())
    payload = json.loads(refs_inventory_json(refs_dir))
    names = {item["name"] for item in payload["inventory"]}

    assert len(REFERENCE_PHASES) >= 15
    assert len(EXPECTED_REFERENCE_REPOS) == 11
    assert {
        "promptfoo",
        "modelaudit",
        "pickle-fuzzer",
        "defenseclaw",
        "aibom",
        "mcp-scanner",
        "skill-scanner",
        "model-provenance-kit",
        "adversarial-hubness-detector",
        "securebert2",
        "ai-defense-hybrid",
    } == names


@_skip_no_refs
def test_refs_cli_inventory_json_smoke():
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli.main",
            "refs",
            "inventory",
            "--format",
            "json",
        ],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(result.stdout)
    assert payload["summary"]["expected"] == 11
    assert payload["summary"]["present"] == 11
    assert any(root.endswith("ai-security-tools/refs") for root in payload["summary"]["roots"])


@_skip_no_refs
def test_refs_plan_json_is_phase_focused():
    refs_dir = default_refs_dir(os.getcwd())
    payload = json.loads(refs_plan_json(refs_dir))

    assert "inventory" not in payload
    assert payload["summary"]["present"] == 11
    assert len(payload["phases"]) >= 15


@_skip_no_refs
def test_refs_gap_cli_emits_fix_queue_json():
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli.main",
            "refs",
            "gap",
            "--format",
            "json",
        ],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "refs.gap-ledger.v1"
    assert payload["summary"]["refs"]["present"] == 11
    assert payload["summary"]["gap_count"] == len(payload["fix_queue"])
    assert payload["fix_queue"]
