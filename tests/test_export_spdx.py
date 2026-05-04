"""Tests: SPDX 3.0 JSON-LD export format."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from sentinel.cli._export import _spdx_report
from sentinel.finding import Severity


def _make_finding(
    rule_id: str = "SPDX-TEST-001",
    severity: Severity = Severity.HIGH,
    title: str = "Test",
    description: str = "Desc",
    remediation: str = "Fix",
    target: str = "/code/app.py",
    line: int = 10,
    owasp_llm: str = "LLM01",
):
    loc = SimpleNamespace(file=target, line_start=line, line_end=line)
    return SimpleNamespace(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        target=target,
        location=loc,
        owasp_llm=owasp_llm,
        evidence="",
        module="sast",
    )


# ── Document structure ────────────────────────────────────────────

def test_spdx_top_level_keys():
    report = _spdx_report([])
    assert "@context" in report
    assert report["spdxVersion"] == "SPDX-3.0"
    assert "SPDXID" in report
    assert "elements" in report
    assert "creator" in report
    assert "created" in report


def test_spdx_context_url():
    report = _spdx_report([])
    assert "spdx.org" in report["@context"]


def test_spdx_empty_findings():
    report = _spdx_report([])
    assert report["elements"] == []


def test_spdx_data_license():
    report = _spdx_report([])
    assert report.get("dataLicense") == "CC0-1.0"


def test_spdx_tool_in_creator():
    report = _spdx_report([])
    assert "sentinel" in report["creator"].lower()


# ── Element structure ─────────────────────────────────────────────

def test_spdx_single_finding_element():
    f = _make_finding()
    report = _spdx_report([f])
    assert len(report["elements"]) == 1
    elem = report["elements"][0]
    assert elem["type"] == "security_VulnAssessmentRelationship"
    assert "spdxId" in elem
    assert elem["security_vuln"] == "SPDX-TEST-001"
    assert "security_cvssScore" in elem
    assert "security_severity" in elem
    assert "security_locator" in elem


def test_spdx_severity_to_score_mapping():
    score_map = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.5,
    }
    for severity, expected_score in score_map.items():
        f = _make_finding(severity=severity)
        report = _spdx_report([f])
        elem = report["elements"][0]
        assert elem["security_cvssScore"] == expected_score, (
            f"Severity {severity} → score {elem['security_cvssScore']}, expected {expected_score}"
        )


def test_spdx_severity_label_lowercase():
    f = _make_finding(severity=Severity.HIGH)
    elem = _spdx_report([f])["elements"][0]
    assert elem["security_severity"] == "high"


def test_spdx_locator_contains_path():
    f = _make_finding(target="/src/api.py", line=55)
    elem = _spdx_report([f])["elements"][0]
    assert "/src/api.py" in elem["security_locator"]
    assert "#L55" in elem["security_locator"]


def test_spdx_spdx_id_unique():
    findings = [_make_finding(rule_id=f"RULE-{i}") for i in range(5)]
    report = _spdx_report(findings)
    ids = [e["spdxId"] for e in report["elements"]]
    assert len(set(ids)) == 5, "spdxId should be unique per finding"


def test_spdx_name_and_comment():
    f = _make_finding(title="Dangerous eval", description="Code execution")
    elem = _spdx_report([f])["elements"][0]
    assert elem["name"] == "Dangerous eval"
    assert elem["comment"] == "Code execution"


def test_spdx_remediation_field():
    f = _make_finding(remediation="Sanitize input")
    elem = _spdx_report([f])["elements"][0]
    assert elem["security_remediation"] == "Sanitize input"


def test_spdx_multiple_findings():
    findings = [_make_finding(rule_id=f"R-{i:03d}") for i in range(10)]
    report = _spdx_report(findings)
    assert len(report["elements"]) == 10


def test_spdx_serializable_to_json():
    findings = [_make_finding(severity=s) for s in Severity]
    report = _spdx_report(findings)
    dumped = json.dumps(report, default=str)
    parsed = json.loads(dumped)
    assert parsed["spdxVersion"] == "SPDX-3.0"
    assert len(parsed["elements"]) == len(list(Severity))
