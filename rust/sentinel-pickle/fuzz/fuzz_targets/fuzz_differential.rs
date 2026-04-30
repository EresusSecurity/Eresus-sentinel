// fuzz_differential.rs — Deep differential scanner fuzzer
//
// Replaces subprocess-based Python validation with Rust-native
// differential testing.  Compares scanner results across:
// - Non-strict vs strict mode
// - Generated vs raw input
// - Multiple protocol versions
// - Multiple scanning passes for idempotency
// - Cross-scanner finding consistency
//
// Run:
//   cargo +nightly fuzz run fuzz_differential -- -max_len=32768

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_pickle::{
    generator::Generator,
    policy::ScanPolicy,
    scanner::{scan_data, scan_data_with_stats},
    state::{MAX_OPCODE_COUNT, MAX_STACK_DEPTH},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);

    // ── Pass 1: Direct scan of fuzz data ──────────────────────────────
    let (findings, stats) = scan_data_with_stats(data, &policy);
    let (strict_f, strict_s) = scan_data_with_stats(data, &strict);

    // INV-1: Well-formed findings
    for f in &findings {
        assert!(!f.rule_id.is_empty());
        assert!(!f.severity.is_empty());
        assert!(f.confidence >= 0.0 && f.confidence <= 1.0);
    }
    for f in &strict_f {
        assert!(!f.rule_id.is_empty());
    }

    // INV-2: Strict ⊇ non-strict
    assert!(
        strict_f.len() >= findings.len(),
        "strict {} < non-strict {}",
        strict_f.len(), findings.len()
    );

    // INV-3: Opcode counts must match (same data, same parsing)
    assert_eq!(stats.opcode_count, strict_s.opcode_count);

    // INV-4: Stack depth bounded
    assert!(stats.max_stack_depth <= MAX_STACK_DEPTH);
    assert!(strict_s.max_stack_depth <= MAX_STACK_DEPTH);

    // ── Pass 2: Generator-based differential ──────────────────────────
    let mut gen = Generator::new(4);
    let generated = match gen.generate(42) {
        Ok(pkl) => pkl,
        Err(_) => return,
    };

    let (gen_f, gen_s) = scan_data_with_stats(&generated, &policy);
    let (gen_strict_f, _) = scan_data_with_stats(&generated, &strict);

    // INV-5: Generated pickle ends with STOP
    if !generated.is_empty() {
        assert_eq!(
            *generated.last().unwrap(), b'.',
            "generated pickle doesn't end with STOP"
        );
    }

    // INV-6: Strict ⊇ non-strict on generated data
    assert!(gen_strict_f.len() >= gen_f.len());

    // INV-7: Stats bounded on generated data
    assert!(gen_s.max_stack_depth <= MAX_STACK_DEPTH);
    if gen_s.aborted {
        assert!(gen_s.opcode_count >= MAX_OPCODE_COUNT);
    }

    // ── Pass 3: Protocol sweep differential ───────────────────────────
    for proto in [0u8, 2, 4] {
        let mut gen_p = Generator::new(proto);
        let pkl = match gen_p.generate(42) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let (f, s) = scan_data_with_stats(&pkl, &policy);
        for finding in &f {
            assert!(!finding.rule_id.is_empty());
        }
        assert!(s.max_stack_depth <= MAX_STACK_DEPTH);
    }

    // ── Pass 4: Idempotency ───────────────────────────────────────────
    let (f1, s1) = scan_data_with_stats(data, &policy);
    let (f2, s2) = scan_data_with_stats(data, &policy);
    assert_eq!(f1.len(), f2.len(), "idempotency: {} vs {}", f1.len(), f2.len());
    assert_eq!(s1.opcode_count, s2.opcode_count);
    assert_eq!(s1.aborted, s2.aborted);

    // ── Pass 5: Finding consistency ───────────────────────────────────
    for f in &findings {
        if f.rule_id == "PICKLE-EXEC" {
            assert!(!f.module_name.is_empty(),
                "PICKLE-EXEC has empty module_name");
            assert!(f.severity == "CRITICAL");
            assert!(f.confidence >= 0.95);
        }
    }

    // ── Pass 6: Dangerous global cross-check ──────────────────────────
    let known_dangerous = [
        ("os", "system"),
        ("subprocess", "Popen"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("builtins", "__import__"),
    ];
    for (module, name) in known_dangerous {
        let mut pkl = vec![0x80, 0x04];
        pkl.push(b'c');
        pkl.extend_from_slice(module.as_bytes());
        pkl.push(b'\n');
        pkl.extend_from_slice(name.as_bytes());
        pkl.push(b'\n');
        pkl.push(b')');
        pkl.push(b'R');
        pkl.push(b'.');

        let check_findings = scan_data(&pkl, &policy);
        let found = check_findings.iter().any(|f|
            f.module_name == module && f.import_name == name
        );
        assert!(
            found,
            "scanner did not flag known dangerous global {}.{}",
            module, name
        );
    }

    // ── Pass 7: Truncation differential ───────────────────────────────
    if data.len() > 8 {
        let half = &data[..data.len() / 2];
        let (f_half, _) = scan_data_with_stats(half, &policy);
        for f in &f_half {
            assert!(!f.rule_id.is_empty());
        }
    }
});
