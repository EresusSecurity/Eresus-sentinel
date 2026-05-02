import json
import os
import subprocess
import sys

from sentinel.audit_store import AuditStore
from sentinel.notifier import Notification, WebhookNotifier


def _run_cli(*args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli.main", *args],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_audit_store_records_redacted_events_and_exports_jsonl(tmp_path):
    db_path = tmp_path / "audit.db"
    export_path = tmp_path / "audit.jsonl"
    store = AuditStore(db_path)

    store.record(
        event_type="firewall",
        target="prompt",
        verdict="block",
        session_id="s1",
        payload={"api_token": "secret-value", "risk": 9},
    )

    events = store.query(event_type="firewall", verdict="block")
    exported = store.export_jsonl(export_path)

    assert len(events) == 1
    assert events[0]["payload"]["api_token"] == "[REDACTED]"
    assert events[0]["evidence_hash"]
    assert exported == 1
    assert json.loads(export_path.read_text(encoding="utf-8").strip())["verdict"] == "block"


def test_audit_cli_query_export_and_tui_json(tmp_path):
    db_path = tmp_path / "audit.db"
    export_path = tmp_path / "audit.jsonl"
    AuditStore(db_path).record(event_type="artifact", target="model.pt", verdict="clean", payload={"finding_count": 0})

    query = _run_cli("audit", "query", "--db", str(db_path), "--type", "artifact", "--json")
    export = _run_cli("audit", "export", "--db", str(db_path), "--output-path", str(export_path), "--json")
    tui = _run_cli("tui", "--db", str(db_path), "--json")

    assert query.returncode == 0
    assert json.loads(query.stdout)["summary"]["event_count"] == 1
    assert export.returncode == 0
    assert export_path.exists()
    assert tui.returncode == 0
    assert json.loads(tui.stdout)["schema_version"] == "tui.status.v1"


def test_setup_commands_write_redacted_local_config(tmp_path):
    env = {"HOME": str(tmp_path)}

    webhook = _run_cli("setup", "webhook", "--url", "https://example.com/hook", "--events", "block,critical", "--json", env_extra=env)
    splunk = _run_cli("setup", "splunk", "--url", "https://splunk.example", "--token", "secret-token", "--json", env_extra=env)
    guardrail = _run_cli("setup", "guardrail", "--mode", "observe", "--json", env_extra=env)

    assert webhook.returncode == 0
    assert splunk.returncode == 0
    assert guardrail.returncode == 0
    config = json.loads((tmp_path / ".sentinel" / "setup.json").read_text(encoding="utf-8"))
    assert config["webhook"]["events"] == ["block", "critical"]
    assert config["splunk"]["token_configured"] is True
    assert "secret-token" not in json.dumps(config)
    assert config["guardrail"]["mode"] == "observe"


def test_proxy_accepts_observe_and_action_mode_aliases():
    observe = _run_cli("proxy", "--mode", "observe", "--transport", "stdio")
    action = _run_cli("proxy", "--mode", "action", "--transport", "stdio")

    assert observe.returncode == 2
    assert "invalid choice" not in observe.stderr
    assert action.returncode == 2
    assert "invalid choice" not in action.stderr


def test_webhook_notifier_posts_json(monkeypatch):
    seen = {}

    class Response:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["timeout"] = timeout
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    notifier = WebhookNotifier("https://example.com/webhook", token="tok", timeout=3)

    assert notifier.send(Notification(title="Blocked", message="finding", severity="high"))
    assert seen["url"] == "https://example.com/webhook"
    assert seen["timeout"] == 3
    assert seen["body"]["title"] == "Blocked"
