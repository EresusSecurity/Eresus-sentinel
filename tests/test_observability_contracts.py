from types import SimpleNamespace

from sentinel.audit import AUDIT_RECORD_SCHEMA_VERSION, AuditLogger
from sentinel.event_schemas import build_gateway_event, build_scan_event, validate_event
from sentinel.firewall.base import ScanAction
from sentinel.metrics import METRICS_SCHEMA_VERSION, MetricsCollector
from sentinel.telemetry import (
    TELEMETRY_SCHEMA_VERSION,
    TelemetryPipeline,
    telemetry_enabled,
)


def test_audit_record_redacts_sensitive_metadata(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path=path)

    record = audit.log_scan(
        scanner="input",
        action="block",
        metadata={
            "api_key": "sk-secret",
            "nested": {"authorization": "Bearer token"},
            "safe": "kept",
        },
    )
    payload = record.to_dict()

    assert payload["schema_version"] == AUDIT_RECORD_SCHEMA_VERSION
    assert payload["metadata"]["api_key"] == "[REDACTED]"
    assert payload["metadata"]["nested"]["authorization"] == "[REDACTED]"
    assert payload["metadata"]["safe"] == "kept"
    assert "[REDACTED]" in path.read_text(encoding="utf-8")


def test_metrics_json_exposes_schema_and_metric_names():
    metrics = MetricsCollector()
    clean = SimpleNamespace(action=ScanAction.PASS, risk_score=0.1, findings=[])

    metrics.record_result("input_pipeline", "input", clean, duration_seconds=0.01)
    payload = metrics.export_json()

    assert payload["schema_version"] == METRICS_SCHEMA_VERSION
    assert payload["metric_names"]["scan_total"] == "sentinel_scan_total"
    assert payload["counters"]["scan_total"]


def test_telemetry_off_switch_suppresses_alerts(monkeypatch):
    monkeypatch.setenv("SENTINEL_TELEMETRY", "off")
    pipeline = TelemetryPipeline()
    pipeline.add_default_rules()

    alerts = pipeline.evaluate_rules({"critical_count": 1})
    pipeline.emit_findings(
        source="mcp_proxy",
        findings=[{"severity": "CRITICAL", "description": "blocked"}],
    )

    assert telemetry_enabled() is False
    assert alerts == []
    assert pipeline.get_alert_history() == []
    assert pipeline.get_summary()["enabled"] is False


def test_emit_findings_creates_alert_without_raw_data():
    pipeline = TelemetryPipeline(enabled=True)

    pipeline.emit_findings(
        source="mcp_proxy",
        findings=[{"severity": "HIGH", "description": "tool risk"}],
        metadata={"session_id": "s1", "risk": 0.9},
    )
    alert = pipeline.get_alert_history()[0]
    payload = alert.to_dict()

    assert payload["schema_version"] == TELEMETRY_SCHEMA_VERSION
    assert payload["severity"] == "ERROR"
    assert payload["details"]["finding_count"] == 1
    assert "tool risk" not in str(payload)


def test_event_builders_validate_against_schemas():
    scan_event = build_scan_event(domain="artifact", status="completed", finding_count=1)
    gateway_event = build_gateway_event(event_type="mcp.proxy.request", payload={"action": "audit"})

    assert validate_event(scan_event, "scan-event")[0] is True
    assert validate_event(gateway_event, "gateway-event-envelope")[0] is True
