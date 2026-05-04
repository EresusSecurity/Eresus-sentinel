from pathlib import Path

import pytest

from sentinel.finding import Severity
from sentinel.interfaces import ReporterProtocol, normalize_severity
from sentinel.networking import RetryConfig
from sentinel.optional_deps import OptionalDependencyError, import_optional, require_optional
from sentinel.quality_audit import collect_import_edges, dead_code_candidates, find_direct_import_cycles
from sentinel.reporters.base import BaseReporter


class DummyReporter(BaseReporter):
    def generate(self, findings, metadata=None) -> str:
        return "ok"


def test_reporter_protocol_accepts_base_reporter():
    assert isinstance(DummyReporter(), ReporterProtocol)


def test_normalize_severity_accepts_enum_names_and_values():
    assert normalize_severity(Severity.HIGH) is Severity.HIGH
    assert normalize_severity("CRITICAL") is Severity.CRITICAL
    assert normalize_severity("medium") is Severity.MEDIUM
    assert normalize_severity("unknown", default=Severity.LOW) is Severity.LOW


def test_optional_dependency_helper_returns_none_or_actionable_error():
    assert import_optional("definitely_missing_sentinel_optional_dep") is None

    with pytest.raises(OptionalDependencyError) as excinfo:
        require_optional(
            "definitely_missing_sentinel_optional_dep",
            extra="hf",
            purpose="test fixture",
        )

    assert 'pip install "eresus-sentinel[hf]"' in str(excinfo.value)
    assert "test fixture" in str(excinfo.value)


def test_retry_config_backoff_and_status_contract():
    cfg = RetryConfig(max_retries=2, backoff_seconds=0.5)

    assert cfg.delay_for_attempt(0) == 0
    assert cfg.delay_for_attempt(1) == 0.5
    assert cfg.delay_for_attempt(2) == 1.0
    assert cfg.should_retry_status(503, attempt=0)
    assert not cfg.should_retry_status(404, attempt=0)
    assert not cfg.should_retry_status(503, attempt=2)


def test_quality_audit_detects_direct_import_cycles(tmp_path):
    pkg = tmp_path / "sentinel"
    pkg.mkdir()
    (pkg / "a.py").write_text("import sentinel.b\n\ndef ok():\n    return 1\n", encoding="utf-8")
    (pkg / "b.py").write_text("import sentinel.a\n", encoding="utf-8")

    edges = collect_import_edges(pkg)

    assert ("sentinel.a", "sentinel.b") in {
        (edge.importer, edge.imported) for edge in edges
    }
    assert find_direct_import_cycles(edges) == [("sentinel.a", "sentinel.b")]


def test_quality_audit_private_dead_code_inventory(tmp_path):
    pkg = tmp_path / "sentinel"
    pkg.mkdir()
    (pkg / "module.py").write_text(
        "def _unused_helper():\n    return 1\n\n"
        "def public():\n    return 2\n",
        encoding="utf-8",
    )

    candidates = dead_code_candidates(pkg)

    assert any(candidate.name == "_unused_helper" for candidate in candidates)
    assert all(candidate.name != "public" for candidate in candidates)
