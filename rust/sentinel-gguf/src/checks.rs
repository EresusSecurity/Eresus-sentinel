// checks.rs — Security checks for parsed GGUF headers

use crate::header::{GgufHeader, GgufType};
use crate::report::{GgufFinding, Severity};

/// Suspicious patterns in KV string values — code injection / path traversal / SSRF
const INJECTION_PATTERNS: &[&str] = &[
    "__import__",
    "os.system",
    "subprocess",
    "eval(",
    "exec(",
    "compile(",
    "builtins",
    "getattr(",
    "setattr(",
    "__reduce__",
    "__class__",
];

const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows",
    "file:///",
];

const SSRF_PATTERNS: &[&str] = &[
    "http://169.254.",
    "http://metadata.",
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "gopher://",
    "ftp://",
];

const SHELL_METACHAR_PATTERNS: &[&str] = &[
    "$(", "`", "| ", "&&", "||", "; ", ">{", ">>",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
];

/// Maximum "normal" string value length in a GGUF KV (64 KiB).
const MAX_SAFE_STRING_LEN: usize = 65_536;

/// Maximum sane tensor count.
const MAX_SANE_TENSOR_COUNT: u64 = 1_000_000;

/// Maximum sane KV count.
const MAX_SANE_KV_COUNT: u64 = 100_000;

/// Run all checks and return all findings.
pub fn run(header: &GgufHeader, _raw: &[u8]) -> Vec<GgufFinding> {
    let mut findings = Vec::new();
    check_tensor_count(header, &mut findings);
    check_kv_count(header, &mut findings);
    check_zero_tensor_with_kv(header, &mut findings);
    check_kv_injection(header, &mut findings);
    check_kv_path_traversal(header, &mut findings);
    check_kv_ssrf(header, &mut findings);
    check_kv_shell_metachar(header, &mut findings);
    check_kv_oversized_string(header, &mut findings);
    check_kv_key_injection(header, &mut findings);
    findings
}

fn check_tensor_count(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    if hdr.tensor_count > MAX_SANE_TENSOR_COUNT {
        out.push(GgufFinding {
            rule_id:     "GGUF-001".into(),
            severity:    Severity::Medium,
            title:       "Abnormally high tensor count".into(),
            evidence:    format!("tensor_count={}", hdr.tensor_count),
            description: format!(
                "GGUF header declares {} tensors (max sane: {}). \
                 May indicate a DoS payload or corrupted file.",
                hdr.tensor_count, MAX_SANE_TENSOR_COUNT
            ),
            confidence:  0.85,
        });
    }
}

fn check_kv_count(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    if hdr.kv_count > MAX_SANE_KV_COUNT {
        out.push(GgufFinding {
            rule_id:     "GGUF-002".into(),
            severity:    Severity::Medium,
            title:       "Abnormally high KV count".into(),
            evidence:    format!("kv_count={}", hdr.kv_count),
            description: format!(
                "GGUF header declares {} KV pairs (max sane: {}). \
                 May indicate a DoS payload or corrupted file.",
                hdr.kv_count, MAX_SANE_KV_COUNT
            ),
            confidence:  0.85,
        });
    }
}

fn check_zero_tensor_with_kv(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    if hdr.tensor_count == 0 && hdr.kv_count > 10 {
        out.push(GgufFinding {
            rule_id:     "GGUF-003".into(),
            severity:    Severity::Low,
            title:       "Zero tensors with many KV entries".into(),
            evidence:    format!("tensor_count=0 kv_count={}", hdr.kv_count),
            description: "GGUF file has no tensors but many metadata entries — anomalous structure.".into(),
            confidence:  0.6,
        });
    }
}

fn check_kv_injection(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    for entry in &hdr.kv_entries {
        if entry.value_type != GgufType::String {
            continue;
        }
        let lower = entry.value_str.to_lowercase();
        for pattern in INJECTION_PATTERNS {
            if lower.contains(pattern) {
                out.push(GgufFinding {
                    rule_id:     "GGUF-010".into(),
                    severity:    Severity::Critical,
                    title:       "Code injection in KV string value".into(),
                    evidence:    format!("key='{}' matched='{}'", entry.key, pattern),
                    description: format!(
                        "KV entry '{}' contains code injection pattern '{}' in its string value.",
                        entry.key, pattern
                    ),
                    confidence:  0.95,
                });
                break;
            }
        }
    }
}

fn check_kv_path_traversal(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    for entry in &hdr.kv_entries {
        if entry.value_type != GgufType::String {
            continue;
        }
        for pattern in PATH_TRAVERSAL_PATTERNS {
            if entry.value_str.contains(pattern) {
                out.push(GgufFinding {
                    rule_id:     "GGUF-011".into(),
                    severity:    Severity::High,
                    title:       "Path traversal in KV string value".into(),
                    evidence:    format!("key='{}' matched='{}'", entry.key, pattern),
                    description: format!(
                        "KV entry '{}' contains path traversal pattern '{}'. \
                         An attacker may be trying to read or write files outside the model directory.",
                        entry.key, pattern
                    ),
                    confidence:  0.9,
                });
                break;
            }
        }
    }
}

fn check_kv_ssrf(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    for entry in &hdr.kv_entries {
        if entry.value_type != GgufType::String {
            continue;
        }
        let lower = entry.value_str.to_lowercase();
        for pattern in SSRF_PATTERNS {
            if lower.contains(pattern) {
                out.push(GgufFinding {
                    rule_id:     "GGUF-012".into(),
                    severity:    Severity::High,
                    title:       "SSRF URL in KV string value".into(),
                    evidence:    format!("key='{}' matched='{}'", entry.key, pattern),
                    description: format!(
                        "KV entry '{}' contains SSRF-indicative URL pattern '{}'. \
                         May be an attempt to reach internal services.",
                        entry.key, pattern
                    ),
                    confidence:  0.9,
                });
                break;
            }
        }
    }
}

fn check_kv_shell_metachar(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    for entry in &hdr.kv_entries {
        if entry.value_type != GgufType::String {
            continue;
        }
        for pattern in SHELL_METACHAR_PATTERNS {
            if entry.value_str.contains(pattern) {
                out.push(GgufFinding {
                    rule_id:     "GGUF-013".into(),
                    severity:    Severity::High,
                    title:       "Shell metacharacters in KV string value".into(),
                    evidence:    format!("key='{}' matched='{}'", entry.key, pattern),
                    description: format!(
                        "KV entry '{}' contains shell metacharacter/command pattern '{}'. \
                         May indicate command injection via model metadata.",
                        entry.key, pattern
                    ),
                    confidence:  0.8,
                });
                break;
            }
        }
    }
}

fn check_kv_oversized_string(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    for entry in &hdr.kv_entries {
        if entry.value_type == GgufType::String && entry.value_len > MAX_SAFE_STRING_LEN {
            out.push(GgufFinding {
                rule_id:     "GGUF-014".into(),
                severity:    Severity::Low,
                title:       "Oversized KV string value".into(),
                evidence:    format!("key='{}' len={}", entry.key, entry.value_len),
                description: format!(
                    "KV entry '{}' has a string value of {} bytes (max sane: {}). \
                     May indicate a data-exfiltration payload or DoS attempt.",
                    entry.key, entry.value_len, MAX_SAFE_STRING_LEN
                ),
                confidence:  0.7,
            });
        }
    }
}

fn check_kv_key_injection(hdr: &GgufHeader, out: &mut Vec<GgufFinding>) {
    for entry in &hdr.kv_entries {
        let lower = entry.key.to_lowercase();
        let is_injection = INJECTION_PATTERNS.iter().any(|p| lower.contains(p))
            || PATH_TRAVERSAL_PATTERNS.iter().any(|p| entry.key.contains(p));
        if is_injection {
            out.push(GgufFinding {
                rule_id:     "GGUF-015".into(),
                severity:    Severity::Critical,
                title:       "Injection pattern in KV key name".into(),
                evidence:    format!("key='{}'", entry.key),
                description: format!(
                    "KV key '{}' itself contains code injection or path traversal patterns. \
                     This is highly unusual and indicates a crafted malicious GGUF file.",
                    entry.key
                ),
                confidence:  0.95,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::KVEntry;

    fn make_header(tensor_count: u64, kv_count: u64, entries: Vec<KVEntry>) -> GgufHeader {
        GgufHeader {
            version: 3,
            tensor_count,
            kv_count,
            kv_entries: entries,
            data_len: 100,
        }
    }

    fn str_entry(key: &str, value: &str) -> KVEntry {
        KVEntry {
            key: key.to_string(),
            value_type: GgufType::String,
            value_str: value.to_string(),
            value_len: value.len(),
            offset: 0,
        }
    }

    #[test]
    fn test_clean_header() {
        let hdr = make_header(10, 2, vec![
            str_entry("general.name", "llama-3"),
            str_entry("general.architecture", "llama"),
        ]);
        let findings = run(&hdr, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_code_injection_in_value() {
        let hdr = make_header(1, 1, vec![
            str_entry("general.name", "__import__('os').system('id')"),
        ]);
        let findings = run(&hdr, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "GGUF-010"));
    }

    #[test]
    fn test_path_traversal_in_value() {
        let hdr = make_header(1, 1, vec![
            str_entry("general.name", "../../../etc/passwd"),
        ]);
        let findings = run(&hdr, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "GGUF-011"));
    }

    #[test]
    fn test_ssrf_in_value() {
        let hdr = make_header(1, 1, vec![
            str_entry("tokenizer.ggml.model", "http://169.254.169.254/latest/meta-data/"),
        ]);
        let findings = run(&hdr, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "GGUF-012"));
    }

    #[test]
    fn test_high_tensor_count() {
        let hdr = make_header(2_000_000, 0, vec![]);
        let findings = run(&hdr, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "GGUF-001"));
    }

    #[test]
    fn test_injection_in_key() {
        let hdr = make_header(1, 1, vec![
            str_entry("__import__('os').system('id')", "harmless"),
        ]);
        let findings = run(&hdr, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "GGUF-015"));
    }

    #[test]
    fn test_shell_metachar() {
        let hdr = make_header(1, 1, vec![
            str_entry("general.name", "model; /bin/sh"),
        ]);
        let findings = run(&hdr, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "GGUF-013"));
    }
}
