// fuzz_lora.rs — Deep LoRA adapter ZIP fuzzer
//
// Exercises LoRA adapter scanning with adversarial payloads:
// - Malicious adapter_config.json
// - Safetensors header overflow/injection
// - ZIP slip in adapter paths
// - Cross-scanner validation (tokenizer + pickle)
// - Target module injection payloads
//
// Run: cargo +nightly fuzz run fuzz_lora -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::{builders, invariants};
use sentinel_pickle::{policy::ScanPolicy, scanner::scan_data};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);
    let mid = data.len() / 2;
    let config_json = &data[..mid];
    let safetensors_data = &data[mid..];

    // ── Pass 1: Standard LoRA ZIP ─────────────────────────────────────
    let zip_bytes = builders::build_lora_zip(config_json, safetensors_data);
    if !zip_bytes.is_empty() {
        let findings = scan_data(&zip_bytes, &policy);
        invariants::assert_findings_valid(&findings);

        let strict_f = scan_data(&zip_bytes, &strict);
        assert!(strict_f.len() >= findings.len());
    }

    // ── Pass 2: Safetensors header ────────────────────────────────────
    let mut st = b"\x08\x00\x00\x00\x00\x00\x00\x00{".to_vec();
    st.extend_from_slice(safetensors_data);
    let findings = scan_data(&st, &policy);
    invariants::assert_findings_valid(&findings);

    // ── Pass 3: Cross-scanner — JSON as tokenizer input ───────────────
    invariants::assert_tokenizer_findings_valid(&sentinel_tokenizer::scan(config_json));

    // ── Pass 4: Malicious adapter configs ─────────────────────────────
    let evil_configs: &[&[u8]] = &[
        b"{\"r\":8,\"lora_alpha\":16,\"target_modules\":[\"__import__('os').system('id')\"]}",
        b"{\"r\":8,\"base_model_name_or_path\":\"../../../etc/passwd\"}",
        b"{\"r\":8,\"target_modules\":[\"q_proj\"],\"fan_in_fan_out\":true,\"modules_to_save\":[\"eval(input())\"]}",
        b"{\"r\":999999999,\"lora_alpha\":0,\"lora_dropout\":-1}",
    ];
    for config in evil_configs {
        let zip = builders::build_lora_zip(config, &[0x08, 0, 0, 0, 0, 0, 0, 0, b'{', b'}']);
        if !zip.is_empty() {
            let _ = scan_data(&zip, &policy);
        }
    }

    // ── Pass 5: Safetensors with overflow header ──────────────────────
    {
        // Absurdly large header length
        let mut overflow_st = u64::MAX.to_le_bytes().to_vec();
        overflow_st.extend_from_slice(safetensors_data);
        let _ = scan_data(&overflow_st, &policy);

        // Zero-length header
        let mut zero_st = 0u64.to_le_bytes().to_vec();
        zero_st.extend_from_slice(safetensors_data);
        let _ = scan_data(&zero_st, &policy);
    }

    // ── Pass 6: ZIP slip paths ────────────────────────────────────────
    {
        let entries = [
            ("../../.ssh/authorized_keys", config_json),
            ("adapter_config.json", b"{\"r\":8}" as &[u8]),
        ];
        let zip = builders::build_zip(&entries);
        if !zip.is_empty() {
            let _ = scan_data(&zip, &policy);
        }
    }

    // ── Pass 7: Idempotency ───────────────────────────────────────────
    if !zip_bytes.is_empty() {
        let f1 = scan_data(&zip_bytes, &policy);
        let f2 = scan_data(&zip_bytes, &policy);
        assert_eq!(f1.len(), f2.len());
    }
});
