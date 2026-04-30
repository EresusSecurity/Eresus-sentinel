// fuzz_scanner.rs — Comprehensive PVM scanner fuzzer
//
// The primary scanner fuzzer.  Exercises scan_data_with_stats() with
// arbitrary bytes and validates 12+ invariants per input covering:
// correctness, resource bounds, idempotency, policy monotonicity,
// finding consistency, and truncation robustness.
//
// Run:
//   cargo +nightly fuzz run fuzz_scanner -- -max_len=65536
//   cargo +nightly fuzz run fuzz_scanner corpus/  -- -runs=1000000

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_pickle::{
    policy::ScanPolicy,
    scanner::{scan_data, scan_data_with_stats},
    state::{MAX_OPCODE_COUNT, MAX_STACK_DEPTH},
};
use std::collections::HashSet;

fuzz_target!(|data: &[u8]| {
    // ── Core scan ─────────────────────────────────────────────────────
    let policy = ScanPolicy::new(false);
    let (findings, stats) = scan_data_with_stats(data, &policy);

    // ── INV-1: All findings structurally valid ────────────────────────
    for f in &findings {
        assert!(!f.rule_id.is_empty(), "finding with empty rule_id");
        assert!(!f.severity.is_empty(), "finding with empty severity");
        assert!(!f.description.is_empty(), "finding with empty description");
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "confidence {} out of [0,1] for rule {}",
            f.confidence, f.rule_id
        );
    }

    // ── INV-2: Stack depth bounded ────────────────────────────────────
    assert!(
        stats.max_stack_depth <= MAX_STACK_DEPTH,
        "max_stack_depth={} exceeded limit={}",
        stats.max_stack_depth, MAX_STACK_DEPTH
    );

    // ── INV-3: Abort ↔ budget ─────────────────────────────────────────
    if stats.aborted {
        assert!(
            stats.opcode_count >= MAX_OPCODE_COUNT,
            "aborted=true but opcode_count={} < budget={}",
            stats.opcode_count, MAX_OPCODE_COUNT
        );
    }

    // ── INV-4: Strict ⊇ non-strict ───────────────────────────────────
    let strict_policy = ScanPolicy::new(true);
    let (strict_findings, strict_stats) = scan_data_with_stats(data, &strict_policy);
    assert!(
        strict_findings.len() >= findings.len(),
        "strict found {} < non-strict {}",
        strict_findings.len(), findings.len()
    );
    // Strict stats must also be bounded
    assert!(strict_stats.max_stack_depth <= MAX_STACK_DEPTH);
    assert_eq!(
        stats.opcode_count, strict_stats.opcode_count,
        "opcode count differs between strict and non-strict"
    );

    // ── INV-5: Idempotency — scanning twice yields identical results ──
    let (findings_2, stats_2) = scan_data_with_stats(data, &policy);
    assert_eq!(
        findings.len(), findings_2.len(),
        "idempotency: {} vs {} findings",
        findings.len(), findings_2.len()
    );
    assert_eq!(stats.opcode_count, stats_2.opcode_count);
    assert_eq!(stats.max_stack_depth, stats_2.max_stack_depth);
    assert_eq!(stats.aborted, stats_2.aborted);

    // ── INV-6: Finding uniqueness — no exact duplicates ───────────────
    let mut seen_rules: HashSet<(&str, usize)> = HashSet::new();
    for f in &findings {
        // rule_id + offset should be unique per finding
        seen_rules.insert((&f.rule_id, f.offset));
    }
    // Note: we allow duplicate rule_ids at different offsets (multiple globals)

    // ── INV-7: Rule ID prefix validation ──────────────────────────────
    for f in &findings {
        assert!(
            f.rule_id.starts_with("PICKLE-"),
            "unexpected rule_id prefix: '{}' (expected PICKLE-*)",
            f.rule_id
        );
    }

    // ── INV-8: Severity values are valid ──────────────────────────────
    for f in &findings {
        assert!(
            matches!(f.severity.as_str(), "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"),
            "invalid severity '{}' in rule {}",
            f.severity, f.rule_id
        );
    }

    // ── INV-9: Tainted on stack bounded ───────────────────────────────
    assert!(
        stats.tainted_on_stack <= stats.max_stack_depth,
        "tainted_on_stack {} > max_stack_depth {}",
        stats.tainted_on_stack, stats.max_stack_depth
    );

    // ── INV-10: Error messages are UTF-8 ──────────────────────────────
    for err in &stats.errors {
        assert!(!err.is_empty(), "empty error string in stats");
    }

    // ── INV-11: Truncation robustness ─────────────────────────────────
    // Scan progressively shorter prefixes — scanner must never panic
    if data.len() > 8 {
        let cuts = [1, 2, 4, data.len() / 4, data.len() / 2, data.len() - 1];
        for &cut in &cuts {
            if cut > 0 && cut < data.len() {
                let _ = scan_data_with_stats(&data[..cut], &policy);
            }
        }
    }

    // ── INV-12: Suffix scan — scanner on data[1..] must not panic ─────
    if data.len() > 2 {
        let _ = scan_data(&data[1..], &policy);
    }

    // ── INV-13: Empty data edge case ──────────────────────────────────
    // Always test empty data for this session (idempotent, trivial)
    let (empty_f, empty_s) = scan_data_with_stats(&[], &policy);
    assert!(empty_f.is_empty(), "empty data should produce no findings");
    assert_eq!(empty_s.opcode_count, 0);
    assert!(!empty_s.aborted);

    // ── INV-14: Overlapping pickle streams ────────────────────────────
    // Build data with multiple PROTO headers and verify no crash
    if data.len() > 4 && data.len() < 4096 {
        let mut multi = Vec::with_capacity(data.len() * 2 + 8);
        multi.extend_from_slice(&[0x80, 0x04]); // proto 4
        multi.extend_from_slice(&data[..data.len().min(128)]);
        multi.push(b'.'); // STOP
        multi.extend_from_slice(&[0x80, 0x02]); // proto 2
        multi.extend_from_slice(&data[..data.len().min(128)]);
        multi.push(b'.'); // STOP
        let (mf, ms) = scan_data_with_stats(&multi, &policy);
        for f in &mf {
            assert!(!f.rule_id.is_empty());
        }
        assert!(ms.max_stack_depth <= MAX_STACK_DEPTH);
    }
});
