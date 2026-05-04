from __future__ import annotations

import json
from types import SimpleNamespace

from sentinel.cli._export import _export
from sentinel.export.otlp import OTLPExporter
from sentinel.export.splunk import SplunkHECExporter
from sentinel.finding import Finding, Severity


def _finding() -> Finding:
    return Finding.agent_mcp(
        rule_id="MCP-OBS-001",
        title="Suspicious MCP binary",
        description="Bundled binary was flagged by reputation checks.",
        severity=Severity.HIGH,
        target="server/tool.bin",
        evidence="sha256=abc",
        confidence=0.8,
    )


def test_otlp_payload_contains_log_record_attributes():
    exporter = OTLPExporter(endpoint="")
    payload = exporter.build_payload([_finding()], scan_id="scan-1")

    resource_logs = payload["resourceLogs"]
    assert resource_logs[0]["resource"]["attributes"][0]["key"] == "service.name"

    records = resource_logs[0]["scopeLogs"][0]["logRecords"]
    assert len(records) == 1
    assert records[0]["severityText"] == "HIGH"

    attrs = {item["key"]: item["value"]["stringValue"] for item in records[0]["attributes"]}
    assert attrs["sentinel.rule_id"] == "MCP-OBS-001"
    assert attrs["sentinel.scan_id"] == "scan-1"

    body = json.loads(records[0]["body"]["stringValue"])
    assert body["target"] == "server/tool.bin"
    assert body["fingerprint"]


def test_splunk_hec_event_wraps_finding():
    exporter = SplunkHECExporter(url="", token="")
    events = exporter.build_events([_finding()], scan_id="scan-2")

    assert len(events) == 1
    assert events[0]["source"] == "eresus-sentinel"
    assert events[0]["sourcetype"] == "sentinel:finding"
    assert events[0]["event"]["rule_id"] == "MCP-OBS-001"
    assert events[0]["event"]["scan_id"] == "scan-2"


def test_export_writes_otlp_payload_to_file(tmp_path):
    out = tmp_path / "findings.otlp.json"
    args = SimpleNamespace(format="otlp", output=str(out), command="mcp")

    _export(args, [_finding()])

    payload = json.loads(out.read_text())
    records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert records[0]["severityText"] == "HIGH"


def test_export_writes_splunk_jsonl_to_file(tmp_path):
    out = tmp_path / "findings.splunk.jsonl"
    args = SimpleNamespace(format="splunk", output=str(out), command="mcp")

    _export(args, [_finding()])

    event = json.loads(out.read_text().strip())
    assert event["sourcetype"] == "sentinel:finding"
    assert event["event"]["rule_id"] == "MCP-OBS-001"
