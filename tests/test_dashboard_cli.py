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


def test_dashboard_command_is_listed_in_top_level_help():
    result = _run_cli("--help")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "dashboard" in result.stdout


def test_dashboard_help_exposes_web_ui_flags():
    result = _run_cli("dashboard", "--help")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "--host" in result.stdout
    assert "--port" in result.stdout
    assert "--policy" in result.stdout
    assert "--open" in result.stdout


def test_dashboard_dispatches_to_serve_with_ui_enabled(monkeypatch):
    import sentinel.cli.cmd_serve as cmd_serve_module
    from sentinel.cli.main import main

    seen = {}

    def fake_cmd_serve(args):
        seen["ui"] = args.ui
        seen["host"] = args.host
        seen["port"] = args.port
        return 0

    monkeypatch.setattr(cmd_serve_module, "cmd_serve", fake_cmd_serve)
    monkeypatch.setattr(
        sys,
        "argv",
        ["sentinel", "dashboard", "--host", "127.0.0.1", "--port", "9090"],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    assert seen == {"ui": True, "host": "127.0.0.1", "port": 9090}
