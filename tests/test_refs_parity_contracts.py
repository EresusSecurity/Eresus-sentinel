import json
import os
import subprocess
import sys

from sentinel.artifact.model_scanners import H5Scanner, SavedModelScanner
from sentinel.redteam.assertion_registry import AssertionRegistry, AssertionSpec, AssertionStatus


def test_reference_parity_exports_are_importable():
    from sentinel import EvalRunner, MCPLiveScanner, SentinelGateway, list_providers
    from sentinel.agent.mcp import MCPLiveScanner as PackageMCPLiveScanner
    from sentinel.redteam.probes import AegisViolentCrimesProbe, FinancialHallucinationProbe
    from sentinel.redteam.strategies import IndirectWebPwnStrategy, SimpleAudioStrategy

    assert SentinelGateway.__name__ == "SentinelGateway"
    assert EvalRunner.__name__ == "EvalRunner"
    assert MCPLiveScanner is PackageMCPLiveScanner
    assert AegisViolentCrimesProbe.probe_name
    assert FinancialHallucinationProbe.probe_name
    assert IndirectWebPwnStrategy.name == "indirect_web_pwn"
    assert SimpleAudioStrategy.name == "simple_audio"
    assert "openai" in list_providers()


    registry = AssertionRegistry()
    cases = [
        (
            AssertionSpec(
                id="faithful",
                type="contextFaithfulness",
                expected={"context": "Paris is the capital of France.", "threshold": 0.1},
            ),
            "Paris is the capital of France.",
        ),
        (
            AssertionSpec(id="html", type="html", expected={"selector": "p", "contains": "ok"}),
            "<html><body><p>ok</p></body></html>",
        ),
        (
            AssertionSpec(
                id="tool",
                type="toolCallF1",
                expected=[{"name": "search", "arguments": {"q": "sentinel"}}],
            ),
            json.dumps({"tool_calls": [{"name": "search", "arguments": {"q": "sentinel"}}]}),
        ),
    ]

    results = [registry.evaluate(spec, output) for spec, output in cases]

    assert registry.type_count >= 70
    assert all(result.status == AssertionStatus.PASS for result in results)


def test_model_scanner_compatibility_wrappers_return_findings(tmp_path):
    missing_h5 = tmp_path / "missing.h5"
    missing_saved_model = tmp_path / "missing_saved_model"

    assert H5Scanner().scan_file(str(missing_h5))[0].rule_id.startswith("ARTIFACT-H5")
    assert SavedModelScanner().scan_file(str(missing_saved_model))


def test_action_compatible_cli_flags_work(tmp_path):
    report_path = tmp_path / "sentinel-results.junit"
    aibom_path = tmp_path / "sentinel-aibom.json"
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"

    scan = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli.main",
            "scan",
            str(tmp_path),
            "--format",
            "junit",
            "--output",
            str(report_path),
            "--fail-on",
            "critical",
            "--ci",
        ],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    aibom = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli.main",
            "aibom",
            str(tmp_path),
            "--format",
            "cyclonedx",
            "--output",
            str(aibom_path),
            "--ci",
        ],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert scan.returncode == 0, scan.stderr + scan.stdout
    assert report_path.read_text(encoding="utf-8").startswith("<?xml")
    assert aibom.returncode == 0, aibom.stderr + aibom.stdout
    assert json.loads(aibom_path.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
