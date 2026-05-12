import json
import os
import subprocess
import sys


def _env() -> dict:
    e = os.environ.copy()
    e["PYTHONPATH"] = f"python{os.pathsep}{e.get('PYTHONPATH', '')}"
    return e

from urllib.error import URLError

from sentinel.artifact.huggingface_scanner import HuggingFaceScanner
from sentinel.hf_guard import HFGuard
from sentinel.supply_chain.hf_scanner import HFRemoteScanner
from sentinel.supply_chain.live_scanner import OSVClient


def test_hf_guard_offline_skips_hub_calls(monkeypatch):
    monkeypatch.setenv("SENTINEL_OFFLINE", "1")

    assessment = HFGuard().assess("org/model")

    assert assessment.metadata["offline"] is True
    assert assessment.total_files == 0
    assert assessment.recommendations == ["Offline mode: skipped HuggingFace Hub API calls"]


def test_artifact_hf_remote_scan_offline_returns_info(monkeypatch):
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")

    findings = HuggingFaceScanner().scan_remote_repo("org/model")

    assert [f.rule_id for f in findings] == ["HF-022"]
    assert "offline" in findings[0].evidence


def test_supply_chain_hf_remote_scan_offline_returns_info():
    findings = HFRemoteScanner(offline=True).scan_repo("org/model")

    assert [f.rule_id for f in findings] == ["HF-004"]
    assert findings[0].severity.value == "info"


def test_osv_offline_never_opens_network(monkeypatch):
    def fail_urlopen(*_args, **_kwargs):
        raise AssertionError("network should not be called")

    monkeypatch.setattr("sentinel.supply_chain.live_scanner.request.urlopen", fail_urlopen)

    client = OSVClient(offline=True)

    assert client.query_package("flask", "2.0.0") == []
    assert client.query_batch([("flask", "2.0.0", "PyPI")]) == {}


def test_osv_retries_transient_errors(monkeypatch):
    calls = {"count": 0}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        @staticmethod
        def read():
            return json.dumps({"vulns": []}).encode()

    def flaky_urlopen(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise URLError("rate limited")
        return Response()

    monkeypatch.setattr("sentinel.supply_chain.live_scanner.request.urlopen", flaky_urlopen)

    client = OSVClient(max_retries=1, retry_backoff=0)

    assert client.query_package("flask", "2.0.0") == []
    assert calls["count"] == 2


def test_dep_scan_offline_json_stdout(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("internal-company-sdk==1.2.3\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli.main",
            "dep-scan",
            str(tmp_path),
            "--offline",
            "-f",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=_env(),
    )

    assert result.returncode in (0, 1)
    payload = json.loads(result.stdout)
    assert payload["result_schema_version"] == "scan-result.v1"
    assert payload["command"] == "dep-scan"
