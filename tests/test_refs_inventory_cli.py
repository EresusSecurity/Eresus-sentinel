import json
import os
import subprocess
import sys

import pytest

from sentinel.refs import (
    EXPECTED_REFERENCE_REPOS,
    REFERENCE_PHASES,
    refs_inventory_json,
    refs_plan_json,
)

_skip_no_refs = pytest.mark.skipif(
    not os.path.isdir(".refs"),
    reason=".refs/ directory not present (development-only)",
)


@_skip_no_refs
def test_refs_inventory_covers_requested_repositories():
    payload = json.loads(refs_inventory_json(".refs"))
    names = {item["name"] for item in payload["inventory"]}

    assert len(REFERENCE_PHASES) >= 15
    assert len(EXPECTED_REFERENCE_REPOS) == 9
    assert {
        "pickle-fuzzer",
        "defenseclaw",
        "aibom",
        "skill-scanner",
        "ai-defense-langchain-middleware",
        "mcp-scanner",
        "a2a-scanner",
        "adversarial-hubness-detector",
        "securebert2",
    }.issubset(names)


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
    assert payload["summary"]["expected"] == 9
    assert payload["summary"]["phases"] >= 15


@_skip_no_refs
def test_refs_plan_json_is_phase_focused():
    payload = json.loads(refs_plan_json(".refs"))

    assert "inventory" not in payload
    assert payload["summary"]["present"] == 9
    assert len(payload["phases"]) >= 15
