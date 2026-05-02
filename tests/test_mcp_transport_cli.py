import json
import os
import subprocess
import sys


def test_mcp_transport_matrix_json_cli_is_machine_readable():
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(
        [sys.executable, "-m", "sentinel.cli.main", "mcp", "transports", "-f", "json"],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "mcp-transport-matrix.v1"
    assert payload["native_live"] >= 3
    names = {transport["name"] for transport in payload["transports"]}
    assert {"manifest", "http-jsonrpc", "stdio", "sse"}.issubset(names)
