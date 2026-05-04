from sentinel.finding import Finding, Severity
from sentinel.scan_report import (
    SCAN_REPORT_SCHEMA_VERSION,
    build_scan_envelope,
    finding_to_dict,
)


def test_scan_report_standardizes_findings_and_redacts_evidence():
    finding = Finding.sast(
        rule_id="SAST-999",
        title="Hardcoded token",
        description="A token was found in source.",
        severity=Severity.HIGH,
        target="app.py",
        evidence="token=sk-1234567890abcdefghijklmnop",
        remediation="Move the token to a secret manager.",
        confidence=0.88,
    )

    payload = build_scan_envelope([finding], command="sast")

    assert payload["schema_version"] == "0.1"
    assert payload["result_schema_version"] == SCAN_REPORT_SCHEMA_VERSION
    assert payload["summary"]["command"] == "sast"
    assert payload["summary"]["status"] == "findings"
    assert payload["totals"]["findings"] == 1
    assert payload["totals"]["severity"]["HIGH"] == 1
    assert payload["findings"][0]["rule_id"] == "SAST-999"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["confidence"] == 0.88
    assert "[REDACTED]" in payload["findings"][0]["evidence"]
    assert "sk-1234567890" not in payload["findings"][0]["evidence"]
    assert payload["errors"] == []


def test_finding_to_dict_handles_plain_finding_like_objects():
    class PlainFinding:
        rule_id = "PLAIN-1"
        severity = "MEDIUM"
        title = "Plain"
        description = "Plain object"
        target = "target"
        evidence = "password=supersecret"
        confidence = 0.5

    data = finding_to_dict(PlainFinding())

    assert data["rule_id"] == "PLAIN-1"
    assert data["severity"] == "medium"
    assert data["confidence"] == 0.5
    assert data["fingerprint"]
    assert data["evidence"] == "[REDACTED]"
