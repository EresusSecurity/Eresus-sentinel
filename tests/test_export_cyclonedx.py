"""Tests: CycloneDX 1.6 ML-BOM export format."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel.cli._export import _cyclonedx_report
from sentinel.finding import Severity


def _make_finding(
    rule_id: str = "TEST-001",
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    description: str = "Description",
    evidence: str = "evidence line",
    remediation: str = "Fix it",
    owasp_llm: str = "LLM01",
    target: str = "/path/to/file.py",
    line: int = 42,
):
    loc = SimpleNamespace(file=target, line_start=line, line_end=line)
    return SimpleNamespace(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        owasp_llm=owasp_llm,
        target=target,
        location=loc,
        module="sast",
    )


# ── Schema structure ───────────────────────────────────────────────

def test_cyclonedx_top_level_keys():
    report = _cyclonedx_report([])
    assert report["bomFormat"] == "CycloneDX"
    assert report["specVersion"] == "1.6"
    assert "serialNumber" in report
    assert report["version"] == 1
    assert "metadata" in report
    assert "vulnerabilities" in report


def test_cyclonedx_serial_number_format():
    report = _cyclonedx_report([])
    sn = report["serialNumber"]
    assert sn.startswith("urn:uuid:"), f"Expected urn:uuid: prefix, got {sn}"


def test_cyclonedx_metadata_structure():
    report = _cyclonedx_report([])
    meta = report["metadata"]
    assert "timestamp" in meta
    assert "tools" in meta
    tools = meta["tools"]
    assert len(tools) >= 1
    tool = tools[0]
    assert tool["name"] == "sentinel"
    assert tool["vendor"] == "Eresus"


def test_cyclonedx_empty_findings():
    report = _cyclonedx_report([])
    assert report["vulnerabilities"] == []


def test_cyclonedx_single_finding():
    f = _make_finding()
    report = _cyclonedx_report([f])
    vulns = report["vulnerabilities"]
    assert len(vulns) == 1
    v = vulns[0]
    assert "bom-ref" in v
    assert v["id"] == "TEST-001"
    assert "ratings" in v
    assert len(v["ratings"]) == 1
    assert v["ratings"][0]["severity"] == "high"
    assert v["ratings"][0]["method"] == "sentinel"


def test_cyclonedx_severity_mapping():
    cases = [
        (Severity.CRITICAL, "critical"),
        (Severity.HIGH, "high"),
        (Severity.MEDIUM, "medium"),
        (Severity.LOW, "low"),
        (Severity.INFO, "info"),
    ]
    for severity, expected_cdx_sev in cases:
        f = _make_finding(severity=severity)
        report = _cyclonedx_report([f])
        sev_in_report = report["vulnerabilities"][0]["ratings"][0]["severity"]
        assert sev_in_report == expected_cdx_sev, f"Severity {severity} → {sev_in_report}, expected {expected_cdx_sev}"


def test_cyclonedx_source_url():
    f = _make_finding(target="/app/scanner.py", line=99)
    report = _cyclonedx_report([f])
    v = report["vulnerabilities"][0]
    assert "source" in v
    assert "file:///app/scanner.py" in v["source"].get("url", "")
    assert "#L99" in v["source"].get("url", "")


def test_cyclonedx_description_and_remediation():
    f = _make_finding(description="A dangerous pattern", remediation="Use safe API")
    report = _cyclonedx_report([f])
    v = report["vulnerabilities"][0]
    assert v["description"] == "A dangerous pattern"
    assert v["recommendation"] == "Use safe API"


def test_cyclonedx_owasp_advisory():
    f = _make_finding(owasp_llm="LLM01")
    report = _cyclonedx_report([f])
    v = report["vulnerabilities"][0]
    assert "advisories" in v
    advisory = v["advisories"][0]
    assert "LLM01" in advisory["title"]
    assert "owasp.org" in advisory["url"]


def test_cyclonedx_no_advisory_when_no_owasp():
    f = _make_finding(owasp_llm="")
    report = _cyclonedx_report([f])
    v = report["vulnerabilities"][0]
    assert "advisories" not in v


def test_cyclonedx_multiple_findings():
    findings = [
        _make_finding(rule_id=f"RULE-{i:03d}", severity=Severity.HIGH)
        for i in range(5)
    ]
    report = _cyclonedx_report(findings)
    assert len(report["vulnerabilities"]) == 5


def test_cyclonedx_bom_ref_unique():
    findings = [_make_finding(rule_id="TEST-001") for _ in range(3)]
    report = _cyclonedx_report(findings)
    refs = [v["bom-ref"] for v in report["vulnerabilities"]]
    assert len(set(refs)) == 3, "bom-ref values should be unique per finding"


def test_cyclonedx_serializable_to_json():
    import json
    findings = [_make_finding(severity=s) for s in [Severity.CRITICAL, Severity.HIGH, Severity.LOW]]
    report = _cyclonedx_report(findings)
    dumped = json.dumps(report, default=str)
    parsed = json.loads(dumped)
    assert parsed["bomFormat"] == "CycloneDX"
