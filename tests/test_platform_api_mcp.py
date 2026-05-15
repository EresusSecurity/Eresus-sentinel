import json

import yaml
from fastapi.testclient import TestClient

from sentinel.mcp.secure_server import SecureMCPServer
from sentinel.web.app import create_dashboard_app


def _suite(path):
    path.write_text(
        yaml.safe_dump(
            {
                "schema": "sentinel.eval.v1",
                "name": "api-suite",
                "providers": [{"id": "local", "type": "mock"}],
                "prompts": [{"id": "p", "template": "inspect {{input}}"}],
                "variables": [{"input": "alpha"}],
                "assertions": [{"type": "contains", "expected": "result:"}],
            }
        ),
        encoding="utf-8",
    )


def test_platform_api_surfaces_run_and_report(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())
    login = client.post("/api/auth/login", json={"username": "admin", "password": "Test-Pass1"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    config = {
        "schema": "sentinel.eval.v1",
        "name": "api-inline",
        "providers": [{"id": "local", "type": "mock"}],
        "prompts": [{"id": "p", "template": "inspect {{input}}"}],
        "variables": [{"input": "alpha"}],
        "assertions": [{"type": "contains", "expected": "result:"}],
    }

    providers = client.get("/api/providers", headers=headers)
    plan = client.post("/api/evals/plan", json={"config": config}, headers=headers)
    run = client.post("/api/evals/run", json={"config": config}, headers=headers)
    report = client.post("/api/reports/export", json={"run_id": run.json()["run"]["id"], "format": "markdown"}, headers=headers)
    redteam = client.post("/api/redteam/plan", json={"packs": ["prompt_extraction"]}, headers=headers)
    runtime = client.post(
        "/api/runtime-sessions/inspect",
        json={"mode": "enforce", "event": {"type": "tool", "tool": "shell", "text": "read private key"}},
        headers=headers,
    )

    assert providers.status_code == 200
    assert plan.json()["cell_count"] == 1
    assert run.json()["summary"]["failed"] == 0
    assert "Sentinel Evaluation Report" in report.json()["content"]
    assert redteam.json()["case_count"] == 1
    assert runtime.json()["decision"]["action"] == "block"


def test_secure_mcp_platform_tools(tmp_path):
    config_path = tmp_path / "suite.sntl"
    dataset_path = tmp_path / "cases.jsonl"
    _suite(config_path)
    dataset_path.write_text(json.dumps({"id": "one", "input": "alpha"}) + "\n", encoding="utf-8")
    server = SecureMCPServer(tmp_path)

    listed = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert any(tool["name"] == "sentinel.eval.run" for tool in listed["result"]["tools"])

    dataset = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "sentinel.dataset.inspect", "arguments": {"path": "cases.jsonl"}},
        }
    )
    run = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "sentinel.eval.run", "arguments": {"path": "suite.sntl"}},
        }
    )
    run_id = run["result"]["structuredContent"]["run"]["id"]
    replay = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "sentinel.eval.replay", "arguments": {"run_id": run_id}},
        }
    )
    redteam = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "sentinel.redteam.plan", "arguments": {"packs": ["prompt_extraction"]}},
        }
    )

    assert dataset["result"]["structuredContent"]["record_count"] == 1
    assert run["result"]["structuredContent"]["summary"]["failed"] == 0
    assert replay["result"]["structuredContent"]["run"]["id"] == run_id
    assert redteam["result"]["structuredContent"]["case_count"] == 1
