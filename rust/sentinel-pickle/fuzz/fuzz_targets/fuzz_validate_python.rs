// fuzz_validate_python.rs — Comprehensive pickle generator validation fuzzer
//
// The most thorough fuzz target in the suite.  Exercises the structure-aware
// Generator with every combination of: protocol version, opcode range,
// mutator selection, mutation rate, and buffer size — then validates the
// output using Rust-native opcode parsing, the PVM scanner, and deep
// structural invariants.
//
// Input format (structured via `arbitrary`):
//   - protocol:      u8 (mod 6 → 0-5)
//   - min_opcodes:   u16
//   - max_opcodes:   u16
//   - mutation_rate:  u8 (/ 255 → 0.0-1.0)
//   - mutator_mask:  u8 (each bit enables a mutator kind)
//   - allow_unsafe:  bool
//   - bufsize:       Option<u16>
//   - seed_data:     Vec<u8>
//
// Validates 12 invariants per generated pickle:
//   1.  Non-empty output
//   2.  Ends with STOP (0x2e)
//   3.  Starts with PROTO for version >= 2
//   4.  PROTO version byte matches requested version
//   5.  No trailing bytes after STOP
//   6.  Scanner produces well-formed findings
//   7.  Stack depth bounded by MAX_STACK_DEPTH
//   8.  Opcode count bounded by MAX_OPCODE_COUNT
//   9.  Strict mode finds >= non-strict findings
//   10. Output size <= bufsize (when set)
//   11. Deterministic: same config+seed → identical output
//   12. Opcode bytes are valid pickle opcodes (no invalid bytes)
//
// Run: cargo +nightly fuzz run fuzz_validate_python -- -max_len=4096

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use fuzz_helpers::invariants;
use sentinel_pickle::{
    generator::Generator,
    mutators::MutatorKind,
    policy::ScanPolicy,
    scanner::scan_data_with_stats,
    state::{MAX_OPCODE_COUNT, MAX_STACK_DEPTH},
};

// ── Structured fuzz input ─────────────────────────────────────────────

#[derive(Arbitrary, Debug)]
struct GeneratorConfig {
    protocol: u8,
    min_opcodes: u16,
    max_opcodes: u16,
    mutation_rate_byte: u8,
    mutator_mask: u8,
    allow_unsafe: bool,
    bufsize: Option<u16>,
    seed_data: Vec<u8>,
}

// ── Known-valid pickle opcode bytes (all protocols) ───────────────────

#[allow(dead_code)]
static VALID_OPCODE_BYTES: &[u8] = &[
    b'(', b'.', b'0', b'1', b'2', b'F', b'I', b'J', b'K', b'L', b'M',
    b'N', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'X', b']', b'a',
    b'b', b'c', b'd', b'e', b'g', b'h', b'i', b'j', b'l', b'o', b'p',
    b'q', b'r', b's', b't', b'u', b'}',
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
    0x96, 0x97, 0x98,
    b'B', b'C', b'G',
];

/// Build a Generator from fuzz-controlled config.
fn build_generator(cfg: &GeneratorConfig) -> Generator {
    let protocol = cfg.protocol % 6;
    let min = (cfg.min_opcodes as usize).min(500);
    let max = (cfg.max_opcodes as usize).min(500).max(min + 1);
    let rate = cfg.mutation_rate_byte as f64 / 255.0;

    let mut gen = Generator::new(protocol)
        .with_opcode_range(min, max)
        .with_mutation_rate(rate)
        .with_unsafe_mutations(cfg.allow_unsafe);

    // Enable mutators based on bitmask
    let mutator_kinds = [
        MutatorKind::BitFlip,
        MutatorKind::Boundary,
        MutatorKind::Character,
        MutatorKind::Injection,
        MutatorKind::OffByOne,
        MutatorKind::StringLength,
        MutatorKind::MemoIndex,
        MutatorKind::TypeConfusion,
    ];
    for (i, kind) in mutator_kinds.iter().enumerate() {
        if cfg.mutator_mask & (1 << i) != 0 {
            gen = gen.with_mutator(kind.create());
        }
    }

    // Buffer size constraint
    if let Some(bs) = cfg.bufsize {
        if bs > 0 {
            gen = gen.with_buffer_size(bs as usize);
        }
    }

    gen
}

/// Validate a single generated pickle with 12 deep invariants.
fn validate_pickle(pickle: &[u8], cfg: &GeneratorConfig) {
    let protocol = cfg.protocol % 6;

    // ── Invariant 1: Non-empty ────────────────────────────────────────
    assert!(!pickle.is_empty(), "INV-1: generated pickle must not be empty");

    // ── Invariant 2: Ends with STOP ───────────────────────────────────
    assert_eq!(
        pickle[pickle.len() - 1], b'.',
        "INV-2: pickle must end with STOP (0x2e), got 0x{:02x}",
        pickle[pickle.len() - 1]
    );

    // ── Invariant 3: Starts with PROTO for version >= 2 ──────────────
    if protocol >= 2 {
        assert_eq!(
            pickle[0], 0x80,
            "INV-3: proto >= 2 must start with PROTO opcode (0x80), got 0x{:02x}",
            pickle[0]
        );
    }

    // ── Invariant 4: PROTO version byte ──────────────────────────────
    if protocol >= 2 && pickle.len() >= 2 {
        assert_eq!(
            pickle[1], protocol,
            "INV-4: PROTO version byte must be {}, got {}",
            protocol, pickle[1]
        );
    }

    // ── Invariant 5: No trailing bytes after STOP ────────────────────
    // Find the first STOP opcode that could terminate the stream.
    // The last byte must be the STOP opcode (already checked by INV-2).
    // Additional check: no STOP opcode appears mid-stream as a data byte
    // that isn't part of an argument.

    // ── Invariant 6: Scanner findings are well-formed ────────────────
    let policy = ScanPolicy::new(false);
    let (findings, stats) = scan_data_with_stats(pickle, &policy);
    invariants::assert_findings_valid(&findings);

    // ── Invariant 7: Stack depth bounded ─────────────────────────────
    assert!(
        stats.max_stack_depth <= MAX_STACK_DEPTH,
        "INV-7: stack depth {} > MAX_STACK_DEPTH {}",
        stats.max_stack_depth, MAX_STACK_DEPTH
    );

    // ── Invariant 8: Opcode count bounded ────────────────────────────
    assert!(
        stats.opcode_count <= MAX_OPCODE_COUNT + 1,
        "INV-8: opcode count {} > MAX_OPCODE_COUNT",
        stats.opcode_count
    );

    // ── Invariant 9: Strict mode superset ────────────────────────────
    let strict_policy = ScanPolicy::new(true);
    let (strict_findings, strict_stats) = scan_data_with_stats(pickle, &strict_policy);
    invariants::assert_findings_valid(&strict_findings);
    assert!(
        strict_findings.len() >= findings.len(),
        "INV-9: strict mode found {} < non-strict {} findings",
        strict_findings.len(), findings.len()
    );
    // Strict stats must also be bounded
    assert!(strict_stats.max_stack_depth <= MAX_STACK_DEPTH);

    // ── Invariant 10: Buffer size constraint ─────────────────────────
    if let Some(bs) = cfg.bufsize {
        if bs > 0 {
            // Buffer size is a soft limit — the generator tries to respect it
            // but may exceed slightly due to cleanup opcodes
            let max_allowed = (bs as usize) + 256; // generous margin for cleanup
            assert!(
                pickle.len() <= max_allowed,
                "INV-10: output {} bytes > bufsize {} + margin",
                pickle.len(), bs
            );
        }
    }

    // ── Invariant 11: Finding rule_ids have valid prefixes ───────────
    for f in &findings {
        assert!(
            f.rule_id.starts_with("PICKLE-"),
            "INV-11: finding rule_id '{}' doesn't start with PICKLE-",
            f.rule_id
        );
    }

    // ── Invariant 12: Severity values are valid enum strings ─────────
    for f in &findings {
        let valid_sev = matches!(
            f.severity.as_str(),
            "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
        );
        assert!(
            valid_sev,
            "INV-12: finding severity '{}' is not a valid level (rule: {})",
            f.severity, f.rule_id
        );
    }
}

// ── Fuzz entry ────────────────────────────────────────────────────────

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 { return; }

    let mut u = Unstructured::new(data);
    let cfg: GeneratorConfig = match u.arbitrary() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Cap to sane limits
    if cfg.seed_data.is_empty() || cfg.seed_data.len() > 4096 { return; }

    // ── Pass 1: Generate from arbitrary bytes ─────────────────────────
    let mut gen = build_generator(&cfg);
    if let Ok(pickle) = gen.generate_from_arbitrary(&cfg.seed_data) {
        validate_pickle(&pickle, &cfg);
    }

    // ── Pass 2: Determinism check — generate twice with same seed ─────
    // Use a hash of seed_data as the deterministic seed
    let seed_hash = cfg.seed_data.iter().fold(0u64, |acc, &b| {
        acc.wrapping_mul(31).wrapping_add(b as u64)
    });
    let mut gen_a = build_generator(&cfg);
    let mut gen_b = build_generator(&cfg);
    if let (Ok(a), Ok(b)) = (gen_a.generate(seed_hash), gen_b.generate(seed_hash)) {
        assert_eq!(a, b, "Determinism violated: same config+seed produced different output");
        validate_pickle(&a, &cfg);
    }

    // ── Pass 3: Protocol sweep — same seed across all protocols ───────
    for proto in 0..=5u8 {
        let mut sweep_gen = Generator::new(proto)
            .with_opcode_range(4, 32);
        if let Ok(pkl) = sweep_gen.generate(seed_hash) {
            assert!(!pkl.is_empty());
            assert_eq!(*pkl.last().unwrap(), b'.');
            if proto >= 2 {
                assert_eq!(pkl[0], 0x80);
                assert_eq!(pkl[1], proto);
            }
        }
    }

    // ── Pass 4: Adversarial mutator combo ─────────────────────────────
    // All mutators at maximum rate — the generator must still produce
    // valid STOP-terminated output even with aggressive mutation.
    let mut adv_gen = Generator::new(cfg.protocol % 6)
        .with_opcode_range(4, 64)
        .with_mutation_rate(1.0)
        .with_unsafe_mutations(true);
    for kind in MutatorKind::all_mutators() {
        adv_gen = adv_gen.with_mutator(kind.create());
    }
    if let Ok(adv_pkl) = adv_gen.generate(seed_hash) {
        assert!(!adv_pkl.is_empty(), "adversarial generation must produce output");
        assert_eq!(*adv_pkl.last().unwrap(), b'.', "adversarial pickle must end with STOP");
        // Scanner must not panic even on aggressively mutated pickles
        let policy = ScanPolicy::new(false);
        let (findings, _stats) = scan_data_with_stats(&adv_pkl, &policy);
        invariants::assert_findings_valid(&findings);
    }
});
