import json

from sentinel.redteam.playbook_engine import (
    PLAYBOOK_REPORT_SCHEMA_VERSION,
    PLAYBOOK_SCHEMA_VERSION,
    GradeLevel,
    PlaybookLoader,
    PlaybookReport,
    ProbeExecutor,
    ProbeOutcome,
    ProbeResult,
    ProbeSpec,
    ProbeType,
    ReportGenerator,
)


def test_playbook_loader_accepts_schema_version_and_repeat_payload():
    spec = PlaybookLoader.load_string(
        f"""
schema_version: {PLAYBOOK_SCHEMA_VERSION}
id: schema-smoke
name: Schema Smoke
target:
  type: sentinel_proxy
variables:
  secret: TOKEN
probes:
  - id: repeated
    name: Repeated payload
    type: data_exfiltration
    payload: "leak {{{{secret}}}} "
    metadata:
      repeat_payload: 2
"""
    )

    payload = ProbeExecutor(spec.target_config, spec.variables)._resolve_payload(spec.probes[0])

    assert spec.schema_version == PLAYBOOK_SCHEMA_VERSION
    assert payload == "leak TOKEN leak TOKEN "


def test_playbook_loader_rejects_unknown_schema_version():
    try:
        PlaybookLoader.load_string(
            """
schema_version: redteam.playbook.v99
name: Bad Schema
probes: []
"""
        )
    except ValueError as exc:
        assert "Unsupported playbook schema_version" in str(exc)
    else:
        raise AssertionError("expected schema validation failure")


def test_blocked_sentinel_response_wins_over_failure_indicators():
    probe = ProbeSpec(
        probe_id="blocked",
        name="Blocked probe",
        type=ProbeType.COMMAND_INJECTION,
        payload="run command",
        failure_indicators=["execute", "path traversal"],
    )
    response = json.dumps(
        {
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": "Blocked by Sentinel: execute/path traversal risk",
            },
        }
    )

    result, indicators = ProbeExecutor({})._grade_response(probe, response)

    assert result == ProbeResult.PASS
    assert indicators[0].startswith("PASS:")


def test_playbook_json_report_uses_standard_envelope():
    report = _sample_report()

    payload = json.loads(ReportGenerator.to_json(report))

    assert payload["schema_version"] == PLAYBOOK_REPORT_SCHEMA_VERSION
    assert payload["summary"]["grade"] == "B"
    assert payload["totals"] == {
        "probes": 2,
        "passed": 1,
        "failed": 1,
        "errors": 0,
        "timeouts": 0,
    }
    assert payload["findings"][0]["probe_id"] == "fail-1"
    assert payload["playbook_id"] == "pb-1"


def test_playbook_sarif_contains_rules_and_failed_results_only():
    sarif = ReportGenerator.to_sarif(_sample_report())

    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"]
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "PLAYBOOK-DATA_EXFILTRATION"
    assert run["properties"]["schema_version"] == PLAYBOOK_REPORT_SCHEMA_VERSION


def _sample_report() -> PlaybookReport:
    return PlaybookReport(
        playbook_id="pb-1",
        playbook_name="Sample",
        target="local",
        grade=GradeLevel.B,
        total_probes=2,
        passed=1,
        failed=1,
        errors=0,
        timeouts=0,
        pass_rate=50.0,
        duration_sec=0.1,
        outcomes=[
            ProbeOutcome(
                probe_id="pass-1",
                probe_name="Pass",
                probe_type="prompt_injection",
                result=ProbeResult.PASS,
                severity="LOW",
                payload_sent="ignore",
                matched_indicators=["PASS:blocked"],
            ),
            ProbeOutcome(
                probe_id="fail-1",
                probe_name="Fail",
                probe_type="data_exfiltration",
                result=ProbeResult.FAIL,
                severity="HIGH",
                payload_sent="leak",
                matched_indicators=["FAIL:secret"],
            ),
        ],
    )
