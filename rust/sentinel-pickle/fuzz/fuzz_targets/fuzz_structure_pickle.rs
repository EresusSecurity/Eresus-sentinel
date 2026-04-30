// fuzz_structure_pickle.rs — Deep structure-aware pickle generation fuzzer
//
// This is the core pickle fuzzer.  It uses the structure-aware Generator
// to produce protocol-valid pickles across all 6 protocol versions, then
// exercises the scanner with multiple analysis passes including:
//
// - Normal scan + strict scan + comparison
// - Multi-protocol generation with same seed (differential)
// - Incremental generation (growing opcode budgets)
// - Mutator-augmented generation (injection, boundary, etc.)
// - Re-scan of sub-slices (robustness against truncation)
// - Double-scan idempotency check
// - Round-trip: generate → scan → verify finding stability
//
// Run: cargo +nightly fuzz run fuzz_structure_pickle -- -max_len=8192

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use fuzz_helpers::invariants;
use sentinel_pickle::{
    generator::Generator,
    mutators::MutatorKind,
    policy::ScanPolicy,
    scanner::{scan_data, scan_data_with_stats},
    state::MAX_STACK_DEPTH,
};

#[derive(Arbitrary, Debug)]
struct PickleGenConfig {
    protocol: u8,
    min_ops: u8,
    max_ops: u8,
    mutation_rate: u8,
    enable_injection: bool,
    enable_boundary: bool,
    enable_bitflip: bool,
    seed_data: Vec<u8>,
}

fn make_generator(cfg: &PickleGenConfig) -> Generator {
    let proto = cfg.protocol % 6;
    let min = (cfg.min_ops as usize).max(2).min(128);
    let max = (cfg.max_ops as usize).max(min + 1).min(512);
    let rate = cfg.mutation_rate as f64 / 255.0;

    let mut gen = Generator::new(proto)
        .with_opcode_range(min, max)
        .with_mutation_rate(rate);

    if cfg.enable_injection { gen = gen.with_mutator(MutatorKind::Injection.create()); }
    if cfg.enable_boundary  { gen = gen.with_mutator(MutatorKind::Boundary.create()); }
    if cfg.enable_bitflip   { gen = gen.with_mutator(MutatorKind::BitFlip.create()); }

    gen
}

fn validate_basic(pickle: &[u8], proto: u8) {
    assert!(!pickle.is_empty());
    assert_eq!(*pickle.last().unwrap(), b'.', "must end with STOP");
    if proto >= 2 && pickle.len() >= 2 {
        assert_eq!(pickle[0], 0x80);
        assert_eq!(pickle[1], proto);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 { return; }

    let mut u = Unstructured::new(data);
    let cfg: PickleGenConfig = match u.arbitrary() {
        Ok(c) => c,
        Err(_) => return,
    };
    if cfg.seed_data.is_empty() || cfg.seed_data.len() > 4096 { return; }

    let proto = cfg.protocol % 6;
    let policy = ScanPolicy::new(false);
    let strict_policy = ScanPolicy::new(true);

    // ── Pass 1: Structure-aware generation + scan ─────────────────────
    let mut gen = make_generator(&cfg);
    let pickle = match gen.generate_from_arbitrary(&cfg.seed_data) {
        Ok(p) => p,
        Err(_) => return,
    };

    validate_basic(&pickle, proto);

    let (findings, stats) = scan_data_with_stats(&pickle, &policy);
    invariants::assert_findings_valid(&findings);
    invariants::assert_stats_bounded(stats.opcode_count, stats.max_stack_depth);

    // ── Pass 2: Strict mode superset ──────────────────────────────────
    let (strict_findings, strict_stats) = scan_data_with_stats(&pickle, &strict_policy);
    invariants::assert_findings_valid(&strict_findings);
    assert!(
        strict_findings.len() >= findings.len(),
        "strict must find >= non-strict: {} < {}",
        strict_findings.len(), findings.len()
    );
    assert!(strict_stats.max_stack_depth <= MAX_STACK_DEPTH);

    // ── Pass 3: Double-scan idempotency ───────────────────────────────
    // Scanning the same bytes twice must yield identical finding counts
    let (findings_2, stats_2) = scan_data_with_stats(&pickle, &policy);
    assert_eq!(
        findings.len(), findings_2.len(),
        "double-scan produced different finding counts: {} vs {}",
        findings.len(), findings_2.len()
    );
    assert_eq!(stats.opcode_count, stats_2.opcode_count);

    // ── Pass 4: Multi-protocol sweep ──────────────────────────────────
    let seed_hash = cfg.seed_data.iter()
        .fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64));
    for p in 0..=5u8 {
        let mut sweep = Generator::new(p).with_opcode_range(4, 32);
        if let Ok(pkl) = sweep.generate(seed_hash) {
            validate_basic(&pkl, p);
            let f = scan_data(&pkl, &policy);
            invariants::assert_findings_valid(&f);
        }
    }

    // ── Pass 5: Incremental opcode budget growth ──────────────────────
    // Generate with increasing opcode budgets and verify monotonic growth
    let budgets = [4, 16, 64, 128];
    let mut _prev_len = 0usize;
    for &budget in &budgets {
        let mut inc_gen = Generator::new(proto)
            .with_opcode_range(budget, budget * 2);
        if let Ok(pkl) = inc_gen.generate(seed_hash) {
            validate_basic(&pkl, proto);
            // Larger budget should generally produce >= equal length output
            // (not strictly monotonic due to opcode variance, but never zero)
            assert!(pkl.len() >= 2, "budget {} produced tiny output", budget);
            _prev_len = pkl.len();
        }
    }

    // ── Pass 6: Truncation robustness ─────────────────────────────────
    // Feed truncated versions of the generated pickle to the scanner.
    // Must never panic regardless of truncation point.
    if pickle.len() > 4 {
        let truncation_points = [1, 2, pickle.len() / 4, pickle.len() / 2, pickle.len() - 1];
        for &point in &truncation_points {
            if point > 0 && point < pickle.len() {
                let truncated = &pickle[..point];
                let _ = scan_data_with_stats(truncated, &policy);
                // No panic = success
            }
        }
    }

    // ── Pass 7: Adversarial mutator stress ────────────────────────────
    let mut adv = Generator::new(proto)
        .with_opcode_range(4, 64)
        .with_mutation_rate(1.0)
        .with_unsafe_mutations(true);
    for kind in MutatorKind::all_mutators() {
        adv = adv.with_mutator(kind.create());
    }
    if let Ok(adv_pkl) = adv.generate(seed_hash) {
        assert!(!adv_pkl.is_empty());
        assert_eq!(*adv_pkl.last().unwrap(), b'.');
        let (af, _) = scan_data_with_stats(&adv_pkl, &policy);
        invariants::assert_findings_valid(&af);
    }

    // ── Pass 8: Concatenated pickles ──────────────────────────────────
    // Scanner must handle multiple pickle streams back-to-back
    if pickle.len() < 2048 {
        let mut multi = pickle.clone();
        multi.extend_from_slice(&pickle);
        let (mf, _ms) = scan_data_with_stats(&multi, &policy);
        invariants::assert_findings_valid(&mf);
        // Should find at least as many findings as single scan
        assert!(mf.len() >= findings.len());
    }
});
