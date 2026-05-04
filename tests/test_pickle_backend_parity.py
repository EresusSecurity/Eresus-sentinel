import os
import pickle

import pytest

from sentinel.artifact.pickle.parity import compare_pickle_backends
from sentinel.artifact.pickle.scanner import HAS_RUST_ENGINE


class _EvilReduce:
    def __reduce__(self):
        return (os.system, ("echo parity",))


def _safe_payload(protocol: int) -> bytes:
    return pickle.dumps(
        {"numbers": [1, 2, 3], "text": "hello", "nested": {"ok": True}},
        protocol=protocol,
    )


def _evil_payload(protocol: int) -> bytes:
    return pickle.dumps(_EvilReduce(), protocol=protocol)


@pytest.mark.parametrize("protocol", range(0, pickle.HIGHEST_PROTOCOL + 1))
def test_python_backend_protocol_matrix_has_no_high_safe_findings(protocol: int):
    result = compare_pickle_backends(_safe_payload(protocol), source=f"safe-p{protocol}")

    assert not result.python.has_blocking_findings


@pytest.mark.skipif(not HAS_RUST_ENGINE, reason="sentinel_pickle extension unavailable")
@pytest.mark.parametrize("protocol", range(0, pickle.HIGHEST_PROTOCOL + 1))
def test_rust_python_safe_protocol_matrix_agree_on_blocking_verdict(protocol: int):
    result = compare_pickle_backends(_safe_payload(protocol), source=f"safe-p{protocol}")

    assert result.rust_available
    assert result.blocking_verdict_matches


@pytest.mark.skipif(not HAS_RUST_ENGINE, reason="sentinel_pickle extension unavailable")
@pytest.mark.parametrize("protocol", range(0, pickle.HIGHEST_PROTOCOL + 1))
def test_rust_python_malicious_protocol_matrix_agree_on_blocking_verdict(protocol: int):
    result = compare_pickle_backends(_evil_payload(protocol), source=f"evil-p{protocol}")

    assert result.rust_available
    assert result.python.has_blocking_findings
    assert result.rust is not None and result.rust.has_blocking_findings
    assert result.blocking_verdict_matches
