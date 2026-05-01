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
