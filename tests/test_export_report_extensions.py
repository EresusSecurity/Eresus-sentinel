from types import SimpleNamespace

from sentinel.cli._export import _html_report
from sentinel.finding import Severity


def test_html_report_renders_optional_correlation_and_taint_sections():
    findings = [
        SimpleNamespace(
            rule_id="SAST-DF-001",
            title="Taint flow",
            description="Source reaches sink",
            evidence="request.json -> eval",
            remediation="Validate input",
            severity=Severity.HIGH,
            target="tool.py",
            fingerprint="group-a",
            taint_trace=["request.json", "payload", "eval"],
        ),
        SimpleNamespace(
            rule_id="MCP-DEF-001",
            title="Missing defense",
            description="Prompt lacks defense",
            evidence="role escape",
            remediation="Add guardrail",
            severity=Severity.MEDIUM,
            target="manifest.json",
            fingerprint="group-a",
        ),
    ]

    html = _html_report(findings)

    assert "<h2>Correlation</h2>" in html
    assert "<h2>Taint Diagrams</h2>" in html
    assert "request.json -&gt; payload -&gt; eval" in html
