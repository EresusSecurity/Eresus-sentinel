"""Tests: Webhook push format — payload construction (no actual HTTP)."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from sentinel.cli._export import _webhook_report
from sentinel.finding import Severity


def _make_finding(
    rule_id: str = "WH-001",
    severity: Severity = Severity.HIGH,
    title: str = "Webhook test",
    description: str = "Description",
    evidence: str = "evidence",
    remediation: str = "Fix",
    owasp_llm: str = "LLM01",
    target: str = "/app/service.py",
):
    return SimpleNamespace(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        owasp_llm=owasp_llm,
        target=target,
        location=None,
        module="sast",
    )


def _capture_posted_payload(url: str, findings, token=None) -> dict:
    """Intercept the HTTP POST and return the decoded payload."""
    captured = {}

    class _FakeResponse:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["body"] = json.loads(req.data)
        captured["headers"] = dict(req.headers)
        return _FakeResponse()

    with patch("urllib.request.urlopen", fake_urlopen):
        _webhook_report(findings, url, token=token)

    return captured


# ── Standard webhook payload ───────────────────────────────────────

def test_webhook_standard_payload_structure():
    findings = [_make_finding()]
    captured = _capture_posted_payload("https://hooks.example.com/webhook", findings)
    body = captured["body"]
    assert body["tool"] == "sentinel"
    assert "scan_timestamp" in body
    assert body["total_findings"] == 1
    assert "summary" in body
    assert "findings" in body


def test_webhook_summary_counts():
    findings = [
        _make_finding(rule_id="C1", severity=Severity.CRITICAL),
        _make_finding(rule_id="H1", severity=Severity.HIGH),
        _make_finding(rule_id="H2", severity=Severity.HIGH),
        _make_finding(rule_id="M1", severity=Severity.MEDIUM),
    ]
    captured = _capture_posted_payload("https://hooks.example.com/webhook", findings)
    summary = captured["body"]["summary"]
    assert summary.get("CRITICAL") == 1
    assert summary.get("HIGH") == 2
    assert summary.get("MEDIUM") == 1


def test_webhook_finding_fields():
    f = _make_finding(rule_id="TEST-001", owasp_llm="LLM02")
    captured = _capture_posted_payload("https://hooks.example.com/webhook", [f])
    fl = captured["body"]["findings"][0]
    assert fl["rule_id"] == "TEST-001"
    assert fl["severity"] == "HIGH"
    assert fl["title"] == "Webhook test"
    assert fl["owasp_llm"] == "LLM02"


def test_webhook_empty_findings():
    captured = _capture_posted_payload("https://hooks.example.com/webhook", [])
    assert captured["body"]["total_findings"] == 0
    assert captured["body"]["findings"] == []


def test_webhook_content_type_header():
    captured = _capture_posted_payload("https://hooks.example.com/webhook", [])
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers.get("content-type") == "application/json"


def test_webhook_bearer_token():
    captured = _capture_posted_payload("https://hooks.example.com/webhook", [], token="mytoken123")
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert "authorization" in headers
    assert headers["authorization"] == "Bearer mytoken123"


def test_webhook_no_token_no_auth_header():
    captured = _capture_posted_payload("https://hooks.example.com/webhook", [], token=None)
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert "authorization" not in headers


def test_webhook_post_method():
    captured = _capture_posted_payload("https://hooks.example.com/webhook", [])
    assert captured["method"] == "POST"


# ── Slack Block Kit format ─────────────────────────────────────────

def test_webhook_slack_payload_has_blocks():
    findings = [_make_finding(severity=Severity.CRITICAL)]
    captured = _capture_posted_payload("https://hooks.slack.com/services/XXX/YYY/ZZZ", findings)
    body = captured["body"]
    assert "blocks" in body
    assert "text" in body


def test_webhook_slack_blocks_structure():
    captured = _capture_posted_payload("https://hooks.slack.com/services/X/Y/Z", [])
    blocks = captured["body"]["blocks"]
    assert isinstance(blocks, list)
    assert len(blocks) >= 2


# ── PagerDuty format ───────────────────────────────────────────────

def test_webhook_pagerduty_payload_structure():
    findings = [_make_finding(severity=Severity.CRITICAL)]
    captured = _capture_posted_payload("https://events.pagerduty.com/v2/enqueue", findings)
    body = captured["body"]
    assert "event_action" in body
    assert body["event_action"] == "trigger"
    assert "payload" in body
    assert body["payload"]["severity"] == "critical"


def test_webhook_pagerduty_severity_high():
    findings = [_make_finding(severity=Severity.HIGH)]
    captured = _capture_posted_payload("https://events.pagerduty.com/v2/enqueue", findings)
    assert captured["body"]["payload"]["severity"] == "error"


def test_webhook_pagerduty_severity_medium():
    findings = [_make_finding(severity=Severity.MEDIUM)]
    captured = _capture_posted_payload("https://events.pagerduty.com/v2/enqueue", findings)
    assert captured["body"]["payload"]["severity"] == "warning"


def test_webhook_pagerduty_routing_key_from_token():
    captured = _capture_posted_payload(
        "https://events.pagerduty.com/v2/enqueue", [], token="pd-routing-key-abc"
    )
    assert captured["body"]["routing_key"] == "pd-routing-key-abc"


# ── HTTP error handling ────────────────────────────────────────────

def test_webhook_http_error_returns_status_string():
    import urllib.error

    def raise_http_error(req, timeout=None):
        raise urllib.error.HTTPError(url="https://x.com", code=500, msg="Internal Server Error", hdrs={}, fp=None)

    with patch("urllib.request.urlopen", raise_http_error):
        result = _webhook_report([], "https://x.com/webhook")
    assert "500" in result


def test_webhook_connection_error_returns_error_string():
    def raise_error(req, timeout=None):
        raise OSError("Connection refused")

    with patch("urllib.request.urlopen", raise_error):
        result = _webhook_report([], "https://x.com/webhook")
    assert "error" in result.lower()
