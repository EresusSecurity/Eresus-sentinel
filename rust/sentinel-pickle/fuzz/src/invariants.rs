// fuzz/src/invariants.rs — Shared invariant checks for fuzz targets
//
// Central invariant library used by all 16 fuzz targets.  Provides
// structural validation for findings from all three scanner crates,
// resource bound checks, severity validation, and cross-scanner helpers.

use sentinel_pickle::report::Finding;
use sentinel_pickle::scanner::ScanStats;

// ── Pickle findings ──────────────────────────────────────────────────

/// Assert all findings have valid structure.
pub fn assert_findings_valid(findings: &[Finding]) {
    for f in findings {
        assert!(!f.rule_id.is_empty(), "Finding has empty rule_id");
        assert!(!f.description.is_empty(), "Finding has empty description");
        assert!(!f.severity.is_empty(), "Finding has empty severity");
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "confidence {} out of [0,1] for rule {}",
            f.confidence, f.rule_id
        );
        // rule_id must start with PICKLE-
        assert!(
            f.rule_id.starts_with("PICKLE-"),
            "unexpected rule_id prefix: '{}' (expected PICKLE-*)",
            f.rule_id
        );
        // severity must be a valid level
        assert!(
            matches!(f.severity.as_str(), "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"),
            "invalid severity '{}' for rule {}",
            f.severity, f.rule_id
        );
        // title should not be empty
        assert!(!f.title.is_empty(), "Finding has empty title for rule {}", f.rule_id);
    }
}

/// Assert findings + stats together.
pub fn assert_scan_result_valid(findings: &[Finding], stats: &ScanStats) {
    assert_findings_valid(findings);
    assert_stats_bounded(stats.opcode_count, stats.max_stack_depth);
    assert!(
        stats.tainted_on_stack <= stats.max_stack_depth,
        "tainted_on_stack {} > max_stack_depth {}",
        stats.tainted_on_stack, stats.max_stack_depth
    );
    for err in &stats.errors {
        assert!(!err.is_empty(), "empty error string in stats");
    }
}

/// Assert severity consistency: PICKLE-EXEC must always be CRITICAL.
pub fn assert_severity_consistency(findings: &[Finding]) {
    for f in findings {
        if f.rule_id == "PICKLE-EXEC" {
            assert_eq!(
                f.severity, "CRITICAL",
                "PICKLE-EXEC must be CRITICAL, got {} for {}.{}",
                f.severity, f.module_name, f.import_name
            );
            assert!(f.confidence >= 0.95,
                "PICKLE-EXEC confidence {} < 0.95", f.confidence);
        }
        if f.rule_id == "PICKLE-SAFE" {
            assert_eq!(
                f.severity, "INFO",
                "PICKLE-SAFE must be INFO, got {}",
                f.severity
            );
        }
    }
}

/// Assert strict mode finds at least as many findings as non-strict.
pub fn assert_strict_superset(
    findings: &[Finding],
    strict_findings: &[Finding],
) {
    assert!(
        strict_findings.len() >= findings.len(),
        "strict found {} < non-strict {}",
        strict_findings.len(), findings.len()
    );
}

// ── GGUF findings ────────────────────────────────────────────────────

/// Assert all GGUF findings have valid structure.
pub fn assert_gguf_findings_valid(findings: &[sentinel_gguf::report::GgufFinding]) {
    for f in findings {
        assert!(!f.rule_id.is_empty(), "GgufFinding has empty rule_id");
        assert!(!f.description.is_empty(), "GgufFinding has empty description");
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "GGUF confidence {} out of [0,1] for rule {}",
            f.confidence, f.rule_id
        );
        assert!(
            f.rule_id.starts_with("GGUF-"),
            "GGUF finding has non-GGUF rule_id: {}",
            f.rule_id
        );
    }
}

// ── Tokenizer findings ───────────────────────────────────────────────

/// Assert all tokenizer findings have valid structure.
pub fn assert_tokenizer_findings_valid(findings: &[sentinel_tokenizer::report::TokenizerFinding]) {
    for f in findings {
        assert!(!f.rule_id.is_empty(), "TokenizerFinding has empty rule_id");
        assert!(!f.description.is_empty(), "TokenizerFinding has empty description");
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "tokenizer confidence {} out of [0,1] for rule {}",
            f.confidence, f.rule_id
        );
        assert!(
            f.rule_id.starts_with("TOK-"),
            "tokenizer finding has non-TOK rule_id: {}",
            f.rule_id
        );
    }
}

// ── Stats bounds ─────────────────────────────────────────────────────

/// Assert scanner stats are within bounds.
pub fn assert_stats_bounded(
    opcode_count: usize,
    max_stack_depth: usize,
) {
    assert!(
        max_stack_depth <= sentinel_pickle::state::MAX_STACK_DEPTH,
        "stack depth {} exceeded MAX_STACK_DEPTH {}",
        max_stack_depth, sentinel_pickle::state::MAX_STACK_DEPTH
    );
    assert!(
        opcode_count <= sentinel_pickle::state::MAX_OPCODE_COUNT + 1,
        "opcode count {} exceeded limit {}",
        opcode_count, sentinel_pickle::state::MAX_OPCODE_COUNT
    );
}

/// Assert scan stats and abort flag are consistent.
pub fn assert_stats_consistent(stats: &ScanStats) {
    if stats.aborted {
        assert!(
            stats.opcode_count >= sentinel_pickle::state::MAX_OPCODE_COUNT,
            "aborted=true but opcode_count={} < budget={}",
            stats.opcode_count, sentinel_pickle::state::MAX_OPCODE_COUNT
        );
    }
    assert!(stats.max_stack_depth <= sentinel_pickle::state::MAX_STACK_DEPTH);
    assert!(stats.tainted_on_stack <= stats.max_stack_depth);
}
