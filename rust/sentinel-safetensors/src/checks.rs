// Security checks run against a parsed safetensors header.

use crate::header::Header;
use crate::report::{SafetensorsFinding, Severity};

const SUSPICIOUS_METADATA_KEYS: &[&str] = &[
    "__reduce__", "__reduce_ex__", "pickle_bytes", "pickle_data",
    "__class__", "__module__", "__import__", "exec(", "eval(",
];

const SUSPICIOUS_DTYPE_PATTERNS: &[&str] = &[
    "pickle", "object", "void", "unknown",
];

/// Run all checks and return every finding.
pub fn run(header: &Header) -> Vec<SafetensorsFinding> {
    let mut findings = Vec::new();
    check_metadata_keys(header, &mut findings);
    check_dtype_anomalies(header, &mut findings);
    check_header_size(header, &mut findings);
    findings
}

fn check_metadata_keys(header: &Header, out: &mut Vec<SafetensorsFinding>) {
    let meta = match header.get("__metadata__").and_then(|v| v.as_object()) {
        Some(m) => m,
        None    => return,
    };
    for key in meta.keys() {
        for pattern in SUSPICIOUS_METADATA_KEYS {
            if key.to_lowercase().contains(pattern) {
                out.push(SafetensorsFinding {
                    rule_id:     "ST-001".into(),
                    severity:    Severity::High,
                    title:       "Suspicious metadata key".into(),
                    evidence:    key.clone(),
                    description: format!("Metadata key '{key}' matches suspicious pattern '{pattern}'"),
                });
            }
        }
    }
}

fn check_dtype_anomalies(header: &Header, out: &mut Vec<SafetensorsFinding>) {
    for (name, value) in header {
        if name == "__metadata__" {
            continue;
        }
        let dtype = value.get("dtype").and_then(|d| d.as_str()).unwrap_or("");
        for pattern in SUSPICIOUS_DTYPE_PATTERNS {
            if dtype.to_lowercase().contains(pattern) {
                out.push(SafetensorsFinding {
                    rule_id:     "ST-002".into(),
                    severity:    Severity::Medium,
                    title:       "Suspicious dtype value".into(),
                    evidence:    format!("tensor={name} dtype={dtype}"),
                    description: format!("Tensor '{name}' has unusual dtype '{dtype}'"),
                });
            }
        }
    }
}

fn check_header_size(header: &Header, out: &mut Vec<SafetensorsFinding>) {
    // More than 50 000 tensors in a single file is anomalous
    let tensor_count = header.keys().filter(|k| *k != "__metadata__").count();
    if tensor_count > 50_000 {
        out.push(SafetensorsFinding {
            rule_id:     "ST-003".into(),
            severity:    Severity::Low,
            title:       "Abnormally large tensor count".into(),
            evidence:    format!("count={tensor_count}"),
            description: format!("Header declares {tensor_count} tensors, which is unusually high"),
        });
    }
}
