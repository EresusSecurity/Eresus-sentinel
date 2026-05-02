from __future__ import annotations

from types import SimpleNamespace


class _FakePickleSelfTest:
    score = None

    def __init__(self, *args, **kwargs):
        pass

    def run(self, output_dir=None):
        return self.score


def _score(**overrides):
    data = {
        "total_samples": 10,
        "malicious_samples": 8,
        "benign_samples": 2,
        "tpr": 1.0,
        "fpr": 0.0,
        "precision": 1.0,
        "f1": 1.0,
        "bypass_rate": 0.0,
        "scanner_crashes": 0,
        "bypassed_payloads": [],
        "false_positive_payloads": [],
        "avg_scan_time_ms": 1.0,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _args(**overrides):
    data = {
        "samples": 10,
        "seed": 123,
        "dir": None,
        "allow_bypass": False,
        "min_tpr": 0.95,
        "max_fpr": 0.03,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_fuzz_selftest_fails_when_false_positive_gate_is_exceeded(monkeypatch):
    from sentinel.cli.cmd_fuzz import _cmd_fuzz_selftest
    import sentinel.fuzzer.pickle.selftest as selftest_module

    _FakePickleSelfTest.score = _score(fpr=0.10, false_positive_payloads=["benign-p4"])
    monkeypatch.setattr(selftest_module, "PickleSelfTest", _FakePickleSelfTest)

    assert _cmd_fuzz_selftest(_args(max_fpr=0.03)) == 1


def test_fuzz_selftest_passes_when_quality_gates_are_met(monkeypatch):
    from sentinel.cli.cmd_fuzz import _cmd_fuzz_selftest
    import sentinel.fuzzer.pickle.selftest as selftest_module

    _FakePickleSelfTest.score = _score()
    monkeypatch.setattr(selftest_module, "PickleSelfTest", _FakePickleSelfTest)

    assert _cmd_fuzz_selftest(_args()) == 0
