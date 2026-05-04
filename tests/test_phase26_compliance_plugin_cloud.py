import json
import os
import subprocess
import sys
import zipfile

from sentinel.aibom.compliance import evaluate
from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType
from sentinel.cloud import plan_cloud_scan
from sentinel.compliance import map_finding_to_frameworks, normalize_framework
from sentinel.finding import Finding, Severity
from sentinel.plugin_sdk import BaseScanner, ScannerPluginSpec, scaffold_plugin


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


def _sample_bom() -> AIBOMResult:
    bom = AIBOMResult()
    bom.add(AIComponent(type=AIComponentType.AGENT, name="planner", path="agent.py", properties={"permissions": ["*"]}))
    bom.add(AIComponent(type=AIComponentType.TOOL, name="shell", path="tool.py"))
    bom.add(AIComponent(type=AIComponentType.MODEL_LLM, name="llm", path="model.safetensors"))
    return bom


def test_owasp_llm_compliance_pack_evaluates_aibom_properties():
    results = evaluate(_sample_bom(), framework="owasp_llm")
    failed = {result.rule.id for result in results if not result.passed}

    assert "OWASP-LLM-001" in failed
    assert "OWASP-LLM-003" in failed
    assert "OWASP-LLM-006" in failed
    assert normalize_framework("owasp-llm") == "owasp_llm"


def test_compliance_cli_outputs_json_and_html(tmp_path):
    bom_path = tmp_path / "bom.json"
    html_path = tmp_path / "report.html"
    bom_path.write_text(json.dumps(_sample_bom().as_dict()), encoding="utf-8")

    json_result = _run_cli("compliance", "check", str(bom_path), "--framework", "owasp-llm", "-f", "json")
    html_result = _run_cli("compliance", "check", str(bom_path), "--framework", "owasp-llm", "-f", "html", "-o", str(html_path))

    assert json_result.returncode == 1
    payload = json.loads(json_result.stdout)
    assert payload["schema_version"] == "sentinel.compliance.v1"
    assert payload["summary"]["failed_rules"] >= 1
    assert any(item["rule_id"] == "OWASP-LLM-001" for item in payload["violations"])
    assert html_result.returncode == 1
    assert "Compliance Report" in html_path.read_text(encoding="utf-8")


def test_compliance_finding_mapping_covers_runtime_rules():
    finding = Finding(
        rule_id="TOOL-INSPECT-002",
        module="agent_mcp",
        title="dangerous command",
        description="dangerous command",
        severity=Severity.CRITICAL,
        confidence=0.9,
    )

    mappings = map_finding_to_frameworks(finding)

    assert mappings[0].framework == "owasp_llm"
    assert mappings[0].control == "LLM06"


def test_plugin_sdk_scaffolds_base_scanner(tmp_path):
    class DemoScanner(BaseScanner):
        spec = ScannerPluginSpec(name="demo")

        def scan_path(self, path):
            return []

    payload = scaffold_plugin("demo-scanner", tmp_path)

    assert DemoScanner().scan_path("x") == []
    assert payload["entry_point_group"] == "sentinel.scanners"
    assert (tmp_path / "demo_scanner" / "pyproject.toml").exists()
    assert "sentinel.scanners" in (tmp_path / "demo_scanner" / "pyproject.toml").read_text(encoding="utf-8")


def test_plugin_cli_new_and_install_pack(tmp_path):
    pack = tmp_path / "pack.zip"
    with zipfile.ZipFile(pack, "w") as archive:
        archive.writestr("plugin.toml", "name = 'demo'\n")

    new_result = _run_cli("plugin", "new", "demo-cli", "--output", str(tmp_path), "--json")
    install_result = _run_cli("plugin", "install", str(pack), "--json", env_extra={"HOME": str(tmp_path)})

    assert new_result.returncode == 0
    assert json.loads(new_result.stdout)["package"] == "demo_cli"
    assert install_result.returncode == 0
    installed = json.loads(install_result.stdout)["installed_path"]
    assert (tmp_path / ".sentinel" / "plugins" / "pack" / "plugin.toml").exists()
    assert installed.endswith("/pack")


def test_cloud_scan_plan_and_cli_supported_uris():
    payload = plan_cloud_scan("s3://bucket/model.pt")

    assert payload["schema_version"] == "sentinel.cloud-scan.v1"
    assert payload["target"]["provider"] == "s3"
    assert payload["auth"]["AWS_ACCESS_KEY_ID"] is False

    cli_result = _run_cli("cloud", "scan", "mlflow://Model/Production", "--json")
    unsupported = _run_cli("cloud", "scan", "ftp://example.com/model.pt", "--json")

    assert cli_result.returncode == 0
    assert json.loads(cli_result.stdout)["target"]["provider"] == "mlflow"
    assert unsupported.returncode == 2
