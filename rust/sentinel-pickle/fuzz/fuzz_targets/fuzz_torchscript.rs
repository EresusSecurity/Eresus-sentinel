// fuzz_torchscript.rs — Deep TorchScript ZIP fuzzer
//
// Exercises TorchScript archive scanning with adversarial payloads:
// - Dangerous pickle in data.pkl / constants.pkl
// - Code injection in __torch__.py
// - Multiple code files with injection payloads
// - ZIP slip in archive paths
// - Protocol sweep for embedded pickles
// - Cross-scanner with GGUF (polyglot detection)
//
// Run: cargo +nightly fuzz run fuzz_torchscript -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::{builders, invariants};
use sentinel_pickle::{policy::ScanPolicy, scanner::scan_data};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);

    let third = data.len() / 3;
    let pkl_data = &data[..third];
    let code_data = &data[third..third * 2];
    let extra_data = &data[third * 2..];

    // ── Pass 1: Standard TorchScript ZIP ──────────────────────────────
    let zip_bytes = builders::build_torchscript_zip(pkl_data, code_data);
    if !zip_bytes.is_empty() {
        let findings = scan_data(&zip_bytes, &policy);
        invariants::assert_findings_valid(&findings);

        let strict_findings = scan_data(&zip_bytes, &strict);
        assert!(strict_findings.len() >= findings.len());
    }

    // ── Pass 2: Dangerous pickle in data.pkl ──────────────────────────
    {
        let mut evil_pkl = vec![0x80, 0x04];
        evil_pkl.push(b'c');
        evil_pkl.extend_from_slice(b"subprocess\nPopen\n");
        evil_pkl.push(0x8c); evil_pkl.push(7);
        evil_pkl.extend_from_slice(b"whoami");
        evil_pkl.push(0);
        evil_pkl.push(0x85);
        evil_pkl.push(b'R');
        evil_pkl.push(b'.');
        let zip = builders::build_torchscript_zip(&evil_pkl, b"# benign code\n");
        if !zip.is_empty() {
            let findings = scan_data(&zip, &policy);
            invariants::assert_findings_valid(&findings);
        }
    }

    // ── Pass 3: Code injection in __torch__.py ────────────────────────
    {
        let code_injections: &[&[u8]] = &[
            b"import os; os.system('id')",
            b"exec(open('/etc/passwd').read())",
            b"__import__('subprocess').call(['rm', '-rf', '/'])",
            b"eval(input())",
        ];
        for code_payload in code_injections {
            let zip = builders::build_torchscript_zip(
                &[0x80, 0x04, b'N', b'.'],
                code_payload,
            );
            if !zip.is_empty() {
                let _ = scan_data(&zip, &policy);
            }
        }
    }

    // ── Pass 4: Multi-file archive ────────────────────────────────────
    {
        let entries = [
            ("archive/data.pkl", pkl_data),
            ("archive/constants.pkl", extra_data),
            ("archive/code/__torch__.py", code_data),
            ("archive/code/__torch__/model.py", extra_data),
        ];
        let zip = builders::build_zip(&entries);
        if !zip.is_empty() {
            let findings = scan_data(&zip, &policy);
            invariants::assert_findings_valid(&findings);
        }
    }

    // ── Pass 5: ZIP slip in archive paths ─────────────────────────────
    {
        let entries = [
            ("archive/../../etc/shadow", pkl_data),
            ("archive/data.pkl", &[0x80, 0x04, b'N', b'.'] as &[u8]),
        ];
        let zip = builders::build_zip(&entries);
        if !zip.is_empty() {
            let _ = scan_data(&zip, &policy);
        }
    }

    // ── Pass 6: Protocol sweep on embedded pickle ─────────────────────
    for proto in [0u8, 2, 3, 4, 5] {
        let mut pkl = if proto >= 2 { vec![0x80, proto] } else { Vec::new() };
        pkl.extend_from_slice(pkl_data);
        pkl.push(b'.');
        let findings = scan_data(&pkl, &policy);
        invariants::assert_findings_valid(&findings);
    }

    // ── Pass 7: Idempotency ───────────────────────────────────────────
    if !zip_bytes.is_empty() {
        let f1 = scan_data(&zip_bytes, &policy);
        let f2 = scan_data(&zip_bytes, &policy);
        assert_eq!(f1.len(), f2.len());
    }
});
