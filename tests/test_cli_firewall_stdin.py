import subprocess
import sys


def test_firewall_stdin_large_literal_is_not_treated_as_path():
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "firewall", "-"],
        input="0" * 20_000,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0
    assert "File name too long" not in proc.stderr
