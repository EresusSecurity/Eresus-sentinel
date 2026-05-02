import json
import os
import subprocess
import sys

import pytest


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli.main", *args],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_artifact_subcommand_accepts_show_skipped_after_path(tmp_path):
    target = tmp_path / "artifacts"
    target.mkdir()
    (target / "note.txt").write_text("unsupported", encoding="utf-8")

    result = _run_cli("artifact", str(target), "--show-skipped")

    assert result.returncode == 0
    assert "unrecognized arguments" not in result.stderr


def test_mcp_stdio_command_accepts_command_flags(monkeypatch):
    import sentinel.cli.cmd_analysis as cmd_analysis_module
    from sentinel.cli.main import main

    seen = {}

    def fake_cmd_mcp(args):
        seen["stdio_command"] = args.stdio_command
        return 0

    monkeypatch.setattr(cmd_analysis_module, "cmd_mcp", fake_cmd_mcp)
    monkeypatch.setattr(
        sys,
        "argv",
        ["sentinel", "mcp", "scan", "--stdio-command", "python3", "-c", "import sys"],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    assert seen["stdio_command"] == ["python3", "-c", "import sys"]


def test_scan_plan_alias_outputs_standard_json_shape():
    result = _run_cli("scan", ".", "--plan", "--profile", "fast", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "scan"
    assert payload["summary"]["command"] == "scan"
    assert payload["summary"]["mode"] == "plan"
    assert payload["summary"]["profile"] == "fast"
    assert payload["totals"]["modules"] == 2
    assert payload["findings"] == []
    assert payload["errors"] == []


def test_scan_json_output_uses_standard_shape(tmp_path):
    result = _run_cli("scan", str(tmp_path), "--profile", "fast", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "scan"
    assert payload["summary"]["command"] == "scan"
    assert payload["summary"]["status"] == "clean"
    assert payload["totals"]["modules"] == 2
    assert payload["findings"] == []
    assert payload["errors"] == []


def test_scan_sarif_output_is_machine_readable(tmp_path):
    result = _run_cli("scan", str(tmp_path), "--profile", "fast", "-f", "sarif")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []


def test_doctor_json_is_machine_readable():
    result = _run_cli("doctor", "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] in {"ok", "degraded"}
    assert payload["checks_total"] >= payload["checks_passed"]


def test_config_explain_subcommand_outputs_json():
    result = _run_cli("config", "explain", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "0.1"
    assert payload["precedence"][0]["layer"] == "cli"
    assert payload["env"]["values_redacted"] is True


def test_rules_and_finding_explain_are_available():
    rules_result = _run_cli("rules", "list", "-f", "json")

    assert rules_result.returncode == 0
    payload = json.loads(rules_result.stdout)
    assert payload["total"] > 0

    finding_result = _run_cli("finding", "explain", "ARTIFACT-031", "-f", "json")

    assert finding_result.returncode == 0
    finding_payload = json.loads(finding_result.stdout)
    assert finding_payload["rule_id"] == "ARTIFACT-031"


def test_mcp_scan_json_writes_single_stdout_document(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "test-mcp",
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo text",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = _run_cli("mcp", "scan", str(manifest), "-f", "json")

    assert result.returncode in {0, 1}
    payload = json.loads(result.stdout)
    assert payload["transport"] == "manifest"
    assert payload["counts"]["tools"] == 1


def test_mcp_fingerprint_json_writes_single_stdout_document(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(json.dumps({"name": "test-mcp", "tools": []}), encoding="utf-8")

    result = _run_cli("mcp", "fingerprint", str(manifest), "-f", "json")

    assert result.returncode in {0, 1}
    payload = json.loads(result.stdout)
    assert payload["transport"] == "manifest"
    assert "finding_count" in payload


@pytest.mark.parametrize("command", ["skill-scan", "mcp-validate"])
def test_hook_commands_fail_closed_without_files(command):
    result = _run_cli(command)

    assert result.returncode == 2
    assert "requires at least one matching" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("command", ["skill-scan", "mcp-validate"])
def test_hook_commands_allow_empty_for_pre_commit_no_match(command):
    result = _run_cli(command, "--allow-empty", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == command
    assert payload["summary"]["status"] == "clean"
    assert payload["findings"] == []
