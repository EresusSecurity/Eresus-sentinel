// fuzz_tokenizer.rs — libFuzzer target for sentinel-tokenizer
//
// Feeds arbitrary bytes to scan() and verifies:
//   1. No panic.
//   2. Every returned TokenizerFinding has a non-empty rule_id and description.
//   3. confidence is in [0.0, 1.0].
//
// Run:
//   cargo +nightly fuzz run fuzz_tokenizer -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Bare bytes (may not be valid JSON — scanner should handle gracefully)
    assert_findings_valid(&sentinel_tokenizer::scan(data));

    // 2. JSON object prefix
    let mut json_prefix = b"{".to_vec();
    json_prefix.extend_from_slice(data);
    assert_findings_valid(&sentinel_tokenizer::scan(&json_prefix));

    // 3. Minimal well-formed tokenizer skeleton
    let skeleton = b"{\"version\":\"1.0\",\"added_tokens\":[]}";
    let mut with_skeleton = skeleton.to_vec();
    with_skeleton.extend_from_slice(data);
    assert_findings_valid(&sentinel_tokenizer::scan(&with_skeleton));
});

fn assert_findings_valid(findings: &[sentinel_tokenizer::report::TokenizerFinding]) {
    for f in findings {
        assert!(!f.rule_id.is_empty(), "TokenizerFinding has empty rule_id");
        assert!(!f.description.is_empty(), "TokenizerFinding has empty description");
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "confidence out of range: {}",
            f.confidence
        );
    }
}
