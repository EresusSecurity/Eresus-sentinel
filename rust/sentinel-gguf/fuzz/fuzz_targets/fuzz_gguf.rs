// fuzz_gguf.rs — libFuzzer target for sentinel-gguf
//
// Feeds arbitrary bytes to scan() and verifies:
//   1. No panic.
//   2. Every returned GgufFinding has a non-empty rule_id and description.
//   3. confidence is in [0.0, 1.0].
//
// Run:
//   cargo +nightly fuzz run fuzz_gguf -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Bare fuzz bytes
    assert_findings_valid(&sentinel_gguf::scan(data));

    // 2. With valid GGUF magic prefix
    let mut with_magic = b"GGUF".to_vec();
    with_magic.extend_from_slice(data);
    assert_findings_valid(&sentinel_gguf::scan(&with_magic));

    // 3. With bad version (0xFFFFFFFF after magic)
    let mut bad_ver: Vec<u8> = b"GGUF".to_vec();
    bad_ver.extend_from_slice(&u32::MAX.to_le_bytes());
    bad_ver.extend_from_slice(data);
    assert_findings_valid(&sentinel_gguf::scan(&bad_ver));
});

fn assert_findings_valid(findings: &[sentinel_gguf::report::GgufFinding]) {
    for f in findings {
        assert!(!f.rule_id.is_empty(), "GgufFinding has empty rule_id");
        assert!(!f.description.is_empty(), "GgufFinding has empty description");
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "confidence out of range: {}",
            f.confidence
        );
    }
}

