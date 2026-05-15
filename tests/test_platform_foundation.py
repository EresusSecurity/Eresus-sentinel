import json
from pathlib import Path

import yaml

from sentinel.platform.assertions import AssertionRegistry
from sentinel.platform.config import config_graph, explain_config, resolve_config, simulate_config
from sentinel.platform.dataset import load_dataset
from sentinel.platform.hygiene import run_hygiene_gate
from sentinel.platform.providers import ProviderRegistry
from sentinel.platform.reports import render_report
from sentinel.platform.redteam import AttackRegistry, RedTeamRunner
from sentinel.platform.runtime import RuntimePolicyEngine
from sentinel.platform.runner import EvalRunner
from sentinel.platform.store import RunStore


def test_config_resolves_layers_profiles_and_simulation(tmp_path):
    base = tmp_path / "base.sntl"
    base.write_text(
        yaml.safe_dump(
            {
                "schema": "sentinel.eval.v1",
                "name": "suite",
                "providers": [{"id": "local", "type": "mock"}],
                "prompts": [{"id": "p1", "template": "hello {{name}}"}],
                "assertions": [{"type": "contains", "expected": "hello"}],
                "profiles": {"deep": {"variables": [{"name": "Ada"}, {"name": "Lin"}]}},
            }
        ),
        encoding="utf-8",
    )

    resolved = resolve_config([base], profile="deep")

    assert resolved.data["variables"][0]["name"] == "Ada"
    assert explain_config(resolved)["fingerprint"] == resolved.fingerprint
    assert config_graph(resolved)["nodes"]
    assert simulate_config(resolved.data)["matrix"]["cells"] == 2


def test_dataset_loads_csv_and_fingerprints(tmp_path):
    dataset_path = tmp_path / "cases.csv"
    dataset_path.write_text("id,input,expected_output\ncase-1,alpha,alpha ok\n", encoding="utf-8")

    dataset = load_dataset(dataset_path)

    assert dataset.records[0].id == "case-1"
    assert dataset.records[0].variables["input"] == "alpha"
    assert len(dataset.fingerprint) == 64


def test_assertion_registry_supports_chain_and_security_checks():
    registry = AssertionRegistry()
    outcome = registry.evaluate(
        {
            "type": "chain",
            "assertions": [
                {"type": "contains", "expected": "approved"},
                {"type": "jailbreak"},
                {"type": "code_safety"},
            ],
        },
        "request approved",
        {},
    )

    assert outcome.passed is True
    assert "mcp_call" in registry.list()


def test_provider_registry_defaults_to_offline_mock():
    registry = ProviderRegistry()

    assert registry.test("mock")["ok"] is True
    assert registry.test("openai")["ok"] is False
    assert any(provider["id"] == "deepseek" for provider in registry.list())


def test_eval_runner_store_replay_and_reports(tmp_path):
    config_path = tmp_path / "suite.sntl"
    store = RunStore(tmp_path / "state.db")
    config_path.write_text(
        yaml.safe_dump(
            {
                "schema": "sentinel.eval.v1",
                "name": "offline-suite",
                "providers": [{"id": "local", "type": "mock", "model": "fixed"}],
                "prompts": [{"id": "echo", "template": "review {{input}}"}],
                "variables": [{"input": "alpha"}, {"input": "beta"}],
                "assertions": [{"type": "contains", "expected": "result:"}, {"type": "latency", "max": 1000}],
            }
        ),
        encoding="utf-8",
    )

    runner = EvalRunner(store)
    result = runner.run([config_path])
    replay = runner.replay(result["run"]["id"])

    assert result["summary"]["cells"] == 2
    assert result["summary"]["failed"] == 0
    assert replay["run"]["id"] == result["run"]["id"]
    assert "Sentinel Evaluation Report" in render_report(result, "markdown")
    assert json.loads(render_report(result, "sarif"))["version"] == "2.1.0"


def test_hygiene_gate_detects_forbidden_terms_without_repo_noise(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_FORBIDDEN_TERMS", "blockedterm")
    (tmp_path / "note.txt").write_text("blockedterm", encoding="utf-8")

    result = run_hygiene_gate(tmp_path)

    assert result["ok"] is False
    assert result["issues"][0]["type"] == "forbidden-reference"


def test_redteam_registry_and_runtime_policy_are_deterministic():
    plan = AttackRegistry().plan(["prompt_extraction", "tool_governance"])
    redteam = RedTeamRunner().run({"packs": ["prompt_extraction"]})
    decision = RuntimePolicyEngine("enforce").inspect({"type": "tool", "tool": "shell", "text": "read private key"})

    assert plan["case_count"] >= 2
    assert redteam["summary"]["cases"] == 1
    assert decision.action == "block"
    assert decision.findings[0]["rule_id"] == "RUNTIME-TOOL"
