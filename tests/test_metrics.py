from types import SimpleNamespace

from sentinel.firewall.base import ScanAction
from sentinel.metrics import MetricsCollector


def test_prometheus_histogram_buckets_are_not_double_cumulative():
    metrics = MetricsCollector()
    clean = SimpleNamespace(action=ScanAction.PASS, risk_score=0.2, findings=[])

    metrics.record_result("input_pipeline", "input", clean, duration_seconds=0.01)
    metrics.record_result("input_pipeline", "input", clean, duration_seconds=0.2)

    output = metrics.export_prometheus()

    assert (
        'sentinel_scan_duration_seconds_count{scanner="input_pipeline",'
        'scanner_type="input"} 2'
    ) in output
    assert (
        'sentinel_scan_duration_seconds_bucket{scanner="input_pipeline",'
        'scanner_type="input",le="0.25"} 2'
    ) in output
    assert 'sentinel_risk_score_count{scanner="input_pipeline"} 2' in output
    assert 'sentinel_risk_score_bucket{scanner="input_pipeline",le="0.2"} 2' in output
