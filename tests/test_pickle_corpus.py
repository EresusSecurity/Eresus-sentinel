"""Regression tests: run each adversarial pickle seed through the scanner.

Ensures the scanner never crashes (raises an unhandled exception) when
processing malicious or malformed inputs, and that the known-bad seeds
produce at least one finding.
"""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest

CORPUS_DIR = Path(__file__).parent / "adversarial_corpus" / "pickle"

# Seeds expected to produce findings in the scanner
MALICIOUS_SEEDS = {
    "seed_rce_reduce.pkl",
    "seed_subprocess_reduce.pkl",
    "seed_global_opcode.pkl",
}


def _corpus_seeds() -> list[Path]:
    if not CORPUS_DIR.exists():
        return []
    return sorted(CORPUS_DIR.glob("*.pkl"))


@pytest.mark.parametrize("seed_path", _corpus_seeds(), ids=lambda p: p.name)
def test_scanner_does_not_crash(seed_path: Path) -> None:
    """Scanner must never raise on any corpus seed."""
    data = seed_path.read_bytes()

    try:
        from sentinel.artifact.pickle_scanner import PickleScanner
    except ImportError:
        pytest.skip("pickle_scanner not available")

    scanner = PickleScanner()
    # Should return a list (possibly empty) — never raise
    result = scanner.scan_bytes(data, source=seed_path.name)
    assert isinstance(result, list)


@pytest.mark.parametrize("seed_path", _corpus_seeds(), ids=lambda p: p.name)
def test_raw_pickle_does_not_segfault(seed_path: Path) -> None:
    """Raw pickle.loads must not segfault — only raise a Python exception."""
    data = seed_path.read_bytes()
    try:
        pickle.loads(data)  # noqa: S301
    except Exception:
        pass  # Any Python exception is fine; segfault would fail the test


def test_empty_or_non_pickle_bytes_do_not_emit_parser_evasion_finding() -> None:
    try:
        from sentinel.artifact.pickle_scanner import PickleScanner
    except ImportError:
        pytest.skip("pickle_scanner not available")

    scanner = PickleScanner(prefer_rust=False)

    for data in (b"", b"not a pickle"):
        findings = scanner.scan_bytes(data, source="<edge>")
        assert all(finding.rule_id != "ARTIFACT-000" for finding in findings)


def test_pickle_backend_selector_honors_python_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinel.artifact.pickle_scanner import PickleScanner

    monkeypatch.setenv("SENTINEL_PICKLE_BACKEND", "python")

    scanner = PickleScanner()

    assert scanner.requested_backend == "python"
    assert scanner.engine == "python"


def test_pickle_backend_selector_rejects_unknown_backend() -> None:
    from sentinel.artifact.pickle_scanner import PickleScanner

    with pytest.raises(ValueError, match="pickle backend"):
        PickleScanner(backend="cuda")


def test_pickle_backend_selector_fails_loudly_when_rust_required_without_extension() -> None:
    from sentinel.artifact.pickle.scanner import HAS_RUST_ENGINE
    from sentinel.artifact.pickle_scanner import PickleScanner

    if HAS_RUST_ENGINE:
        pytest.skip("Rust extension is available in this environment")

    with pytest.raises(RuntimeError, match="Rust extension"):
        PickleScanner(backend="rust")


@pytest.mark.parametrize("seed_name", sorted(MALICIOUS_SEEDS))
def test_malicious_seed_produces_findings(seed_name: str) -> None:
    """Known-bad seeds must trigger at least one finding."""
    seed_path = CORPUS_DIR / seed_name
    if not seed_path.exists():
        pytest.skip(f"Corpus seed missing: {seed_name}")

    try:
        from sentinel.artifact.pickle_scanner import PickleScanner
    except ImportError:
        pytest.skip("pickle_scanner not available")

    data = seed_path.read_bytes()
    findings = PickleScanner().scan_bytes(data, source=seed_name)
    assert len(findings) > 0, (
        f"Expected findings for malicious seed {seed_name}, got none"
    )
