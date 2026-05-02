from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from sentinel.finding import Severity


def test_pickle_protocol_matrix_has_no_high_severity_for_benign_payloads():
    from sentinel.artifact.pickle_scanner import PickleScanner

    scanner = PickleScanner(prefer_rust=False)

    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        data = pickle.dumps(
            {"numbers": [1, 2, 3], "metadata": {"safe": True}},
            protocol=protocol,
        )
        findings = scanner.scan_bytes(data, source=f"benign-p{protocol}.pkl")
        high_or_critical = [
            f for f in findings
            if f.severity in {Severity.HIGH, Severity.CRITICAL}
        ]

        assert high_or_critical == [], (
            protocol,
            [(f.rule_id, f.severity.value) for f in findings],
        )


@pytest.mark.parametrize(
    "payload_path",
    sorted((Path(__file__).parent / "adversarial_corpus" / "ghsa_pickles").glob("*.pkl")),
    ids=lambda p: p.name,
)
def test_ghsa_pickle_corpus_has_zero_bypass(payload_path: Path):
    from sentinel.artifact.pickle_scanner import PickleScanner

    findings = PickleScanner(prefer_rust=False).scan_file(str(payload_path))

    assert findings, f"GHSA pickle payload bypassed scanner: {payload_path.name}"
