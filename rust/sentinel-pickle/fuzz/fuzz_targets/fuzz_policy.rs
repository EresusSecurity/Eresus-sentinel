// fuzz_policy.rs — Deep security policy engine fuzzer
//
// Generates arbitrary (module, name) string pairs and validates policy
// evaluation invariants.  Covers 14 invariants including:
// - Dangerous globals can never be downgraded to Safe
// - Policy bypass attempts via Unicode normalization, null bytes, path traversal
// - Allowlist/blocklist interaction edge cases
// - Module name obfuscation attacks
// - Strict mode always >= non-strict severity
// - Policy determinism
//
// Run:
//   cargo +nightly fuzz run fuzz_policy -- -max_len=512

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sentinel_pickle::policy::{PolicyVerdict, ScanPolicy};

#[derive(Arbitrary, Debug)]
struct PolicyInput {
    module: String,
    name: String,
    extra_allow: Vec<(String, String)>,
    extra_block: Vec<(String, String)>,
    strict: bool,
    bypass_module: String,
    bypass_name: String,
}

/// Known-dangerous (module, name) pairs that must NEVER be Safe.
static ALWAYS_DANGEROUS: &[(&str, &str)] = &[
    ("os", "system"),
    ("os", "popen"),
    ("os", "exec"),
    ("os", "execl"),
    ("os", "execve"),
    ("os", "spawn"),
    ("os", "makedirs"),
    ("os", "remove"),
    ("os", "unlink"),
    ("subprocess", "Popen"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("builtins", "compile"),
    ("builtins", "getattr"),
    ("ctypes", "CDLL"),
    ("ctypes", "windll"),
    ("marshal", "loads"),
    ("marshal", "load"),
    ("pickle", "loads"),
    ("pickle", "load"),
    ("_pickle", "loads"),
    ("_pickle", "load"),
    ("importlib", "import_module"),
    ("importlib", "__import__"),
    ("code", "InteractiveInterpreter"),
    ("code", "InteractiveConsole"),
    ("shutil", "rmtree"),
    ("socket", "socket"),
    ("webbrowser", "open"),
    ("nt", "system"),
    ("posix", "system"),
];

/// Bypass attempts — obfuscated forms of dangerous modules.
static BYPASS_ATTEMPTS: &[(&str, &str)] = &[
    ("os ", "system"),          // trailing space
    (" os", "system"),          // leading space
    ("Os", "system"),           // case change
    ("OS", "SYSTEM"),           // all caps
    ("o\x00s", "system"),       // null byte injection
    ("os\n", "system"),         // newline injection
    ("os\r", "system"),         // carriage return
    ("os\t", "system"),         // tab injection
    ("builtins", "eval "),      // trailing space in name
    ("builtins", " eval"),      // leading space in name
    ("builtins", "ev\x00al"),   // null in name
    ("subprocess", "Popen\n"),  // newline in name
    ("os.path", "system"),      // dotted module confusion
    ("__builtins__", "eval"),   // dunder variant
];

fuzz_target!(|input: PolicyInput| {
    // ── Setup ─────────────────────────────────────────────────────────
    let mut policy = ScanPolicy::new(input.strict);

    for (m, n) in input.extra_allow.iter().take(32) {
        if !m.is_empty() && !n.is_empty() && m.len() < 128 && n.len() < 128 {
            policy.allow(m, n);
        }
    }
    for (m, n) in input.extra_block.iter().take(32) {
        if !m.is_empty() && !n.is_empty() && m.len() < 128 && n.len() < 128 {
            policy.block(m, n);
        }
    }

    // ── INV-1: Dangerous pairs NEVER Safe ─────────────────────────────
    for (m, n) in ALWAYS_DANGEROUS {
        let verdict = policy.evaluate_internal(m, n);
        assert_ne!(
            verdict,
            PolicyVerdict::Safe,
            "BYPASS: {m}.{n} evaluated to Safe!"
        );
    }

    // ── INV-2: Arbitrary (module, name) never panics ──────────────────
    let _ = policy.evaluate_internal(&input.module, &input.name);

    // ── INV-3: Empty module.name → not Dangerous ──────────────────────
    let v_empty = policy.evaluate_internal("", "");
    assert_ne!(v_empty, PolicyVerdict::Dangerous,
        "empty module.name should not be Dangerous");

    // ── INV-4: Freshly allowed → not Dangerous ────────────────────────
    {
        let m = "fuzz_safe_module_xyz";
        let n = "fuzz_safe_name_xyz";
        policy.allow(m, n);
        let v = policy.evaluate_internal(m, n);
        assert_ne!(v, PolicyVerdict::Dangerous,
            "explicitly allowed {m}.{n} evaluated to Dangerous");
    }

    // ── INV-5: Bypass attempts must NOT be Safe ───────────────────────
    // Obfuscated variants of dangerous globals
    for (m, n) in BYPASS_ATTEMPTS {
        let verdict = policy.evaluate_internal(m, n);
        // The policy should NOT classify these as Safe
        // (they should be Unknown, Suspicious, or Dangerous)
        // We don't assert Dangerous because the policy may not recognize
        // the obfuscated form — but it must never say "Safe"
        assert_ne!(
            verdict,
            PolicyVerdict::Safe,
            "BYPASS via obfuscation: '{m}'.'{n}' classified as Safe!"
        );
    }

    // ── INV-6: Fuzz-supplied bypass attempt ───────────────────────────
    if !input.bypass_module.is_empty() && !input.bypass_name.is_empty()
        && input.bypass_module.len() < 256 && input.bypass_name.len() < 256
    {
        let _ = policy.evaluate_internal(&input.bypass_module, &input.bypass_name);
        // No panic = pass
    }

    // ── INV-7: Strict mode severity >= non-strict ─────────────────────
    {
        let non_strict = ScanPolicy::new(false);
        let strict = ScanPolicy::new(true);
        for (m, n) in ALWAYS_DANGEROUS.iter().take(5) {
            let v_ns = non_strict.evaluate_internal(m, n);
            let v_s = strict.evaluate_internal(m, n);
            let sev_ns = verdict_severity(&v_ns);
            let sev_s = verdict_severity(&v_s);
            assert!(
                sev_s >= sev_ns,
                "strict severity ({}) < non-strict ({}) for {m}.{n}",
                sev_s, sev_ns
            );
        }
    }

    // ── INV-8: Determinism — same policy + same input → same verdict ──
    {
        let p1 = ScanPolicy::new(input.strict);
        let p2 = ScanPolicy::new(input.strict);
        let v1 = p1.evaluate_internal(&input.module, &input.name);
        let v2 = p2.evaluate_internal(&input.module, &input.name);
        assert_eq!(v1, v2, "policy determinism violated");
    }

    // ── INV-9: Block overrides allow ──────────────────────────────────
    {
        let mut p = ScanPolicy::new(false);
        let m = "test_block_override";
        let n = "test_block_func";
        p.allow(m, n);
        p.block(m, n);
        let v = p.evaluate_internal(m, n);
        // After blocking, it should NOT be Safe anymore
        assert_ne!(v, PolicyVerdict::Safe,
            "block should override allow for {m}.{n}");
    }

    // ── INV-10: Known-safe modules are not Dangerous ──────────────────
    let safe_pairs = [
        ("collections", "OrderedDict"),
        ("datetime", "datetime"),
        ("math", "sqrt"),
        ("itertools", "chain"),
        ("functools", "partial"),
    ];
    for (m, n) in safe_pairs {
        let v = policy.evaluate_internal(m, n);
        // Safe modules should be Safe or Unknown, never Dangerous
        assert_ne!(v, PolicyVerdict::Dangerous,
            "safe module {m}.{n} classified as Dangerous");
    }

    // ── INV-11: Very long module/name → no panic ──────────────────────
    {
        let long_m = "a".repeat(10_000);
        let long_n = "b".repeat(10_000);
        let _ = policy.evaluate_internal(&long_m, &long_n);
    }

    // ── INV-12: Unicode module names ──────────────────────────────────
    {
        let unicode_pairs = [
            ("оs", "system"),      // Cyrillic 'о' (U+043E) in 'os'
            ("os", "ꜱystem"),      // small cap S
            ("ᴏs", "system"),      // small cap O
            ("builtins", "еval"),   // Cyrillic 'е' (U+0435)
        ];
        for (m, n) in unicode_pairs {
            let v = policy.evaluate_internal(m, n);
            // Homoglyph attacks should NOT be classified as Safe
            assert_ne!(v, PolicyVerdict::Safe,
                "Unicode homoglyph bypass: {m}.{n} classified as Safe");
        }
    }

    // ── INV-13: Null bytes in module ──────────────────────────────────
    {
        let v = policy.evaluate_internal("os\x00injected", "system");
        assert_ne!(v, PolicyVerdict::Safe,
            "null byte module bypass classified as Safe");
    }

    // ── INV-14: scan_data integration — build pickle with fuzz global ─
    if input.module.len() < 64 && input.name.len() < 64
        && !input.module.contains('\n') && !input.name.contains('\n')
        && !input.module.is_empty() && !input.name.is_empty()
    {
        let mut pkl = vec![0x80, 0x02]; // proto 2
        pkl.push(b'c'); // GLOBAL
        pkl.extend_from_slice(input.module.as_bytes());
        pkl.push(b'\n');
        pkl.extend_from_slice(input.name.as_bytes());
        pkl.push(b'\n');
        pkl.push(b')'); // empty tuple
        pkl.push(b'R'); // REDUCE
        pkl.push(b'.'); // STOP

        let findings = sentinel_pickle::scanner::scan_data(&pkl, &policy);
        for f in &findings {
            assert!(!f.rule_id.is_empty());
            assert!(f.confidence >= 0.0 && f.confidence <= 1.0);
        }
    }
});

/// Map verdict to severity number for comparison.
fn verdict_severity(v: &PolicyVerdict) -> u8 {
    match v {
        PolicyVerdict::Safe => 0,
        PolicyVerdict::Unknown => 1,
        PolicyVerdict::Suspicious => 2,
        PolicyVerdict::Dangerous => 3,
    }
}
