"""Smoke tests for `.refs` parity foundations."""
from __future__ import annotations

from sentinel.finding import Severity
from sentinel.parity import STATUS_PARTIAL


def test_artifact_scan_file_public_api_detects_pickle(tmp_path):
    from sentinel.artifact import scan_file

    model_path = tmp_path / "evil.pkl"
    model_path.write_bytes(b"\x80\x02cos\nsystem\n(S'echo parity'\ntR.")

    findings = scan_file(model_path)

    assert findings
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_reference_style_probe_generates_attempts():
    from sentinel.redteam.probes.ascii_smuggling import ASCIISmugglingProbe

    probe = ASCIISmugglingProbe()
    attempts = probe.generate_attempts()

    assert probe.probe_name == "ascii_smuggling"
    assert len(attempts) >= 8
    assert attempts[0].prompt
    assert attempts[0].metadata["probe_name"] == "ascii_smuggling"


def test_strategy_registry_discovers_existing_strategies():
    from sentinel.redteam.strategies.base import StrategyRegistry

    StrategyRegistry.discover()
    strategies = StrategyRegistry.all_strategies()

    assert "base64" in strategies
    assert "rot13" in strategies


def test_redteam_quick_scan_report_shape():
    from sentinel.redteam.orchestrator import RedTeamOrchestrator

    report = RedTeamOrchestrator().run_quick_scan("echo")

    assert hasattr(report, "findings")
    assert hasattr(report, "summary")
    assert report.summary["total_attempts"] > 0


def test_refs_parity_manifest_covers_all_reference_tools():
    from sentinel.parity import build_parity_manifest, summarize_manifest

    manifest = build_parity_manifest()
    tools = {feature.tool for feature in manifest}
    expected = {
        "ref-llm-eval-suite",
        "ref-eval-action",
        "ref-code-review-action",
        "ref-artifact-scan-suite",
        "ref-model-audit-suite",
        "ref-mcp-security-suite",
        "ref-skill-security-suite",
        "ref-pickle-fuzz-suite",
        "ref-bom-suite",
        "ref-runtime-defense-suite",
        "ref-agent-runtime-adapter-a",
        "ref-agent-runtime-adapter-b",
        "ref-a2a-security-suite",
        "ref-vector-hubness-suite",
        "ref-cyber-model-suite",
    }

    assert expected.issubset(tools)
    assert summarize_manifest(manifest)["native-live"] >= 1
    assert len(manifest) >= 80


def test_refs_parity_manifest_uses_anonymous_tool_aliases():
    from sentinel.parity import build_parity_manifest

    manifest = build_parity_manifest()

    assert all(feature.tool.startswith("ref-") for feature in manifest)
    assert all(feature.feature_id.startswith(feature.tool) for feature in manifest)


def test_refs_parity_manifest_has_no_p0_partial_features():
    from sentinel.parity import build_parity_manifest

    manifest = build_parity_manifest()
    p0_partial = [
        feature.feature
        for feature in manifest
        if feature.priority == "P0" and feature.status == STATUS_PARTIAL
    ]

    assert p0_partial == []
