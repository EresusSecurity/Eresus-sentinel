// strings.rs — Embedded string extraction from pickle streams
// Extracts all string literals pushed onto the pickle stack for
// secondary analysis (URL detection, secret detection, etc.).

use crate::state::{PVMState, StackValue};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub source: StringSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringSource {
    StackLiteral,
    GlobalModule,
    GlobalName,
    MemoEntry,
    BytesDecoded,
}

pub fn extract_strings(state: &PVMState) -> Vec<ExtractedString> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for gref in &state.global_refs {
        let key = format!("{}.{}", gref.module, gref.name);
        if seen.insert(key.clone()) {
            result.push(ExtractedString {
                value: gref.module.clone(),
                offset: gref.offset,
                source: StringSource::GlobalModule,
            });
            result.push(ExtractedString {
                value: gref.name.clone(),
                offset: gref.offset,
                source: StringSource::GlobalName,
            });
        }
    }

    for (idx, val) in state.memo.iter() {
        if let StackValue::String(s) = val {
            if s.len() >= 3 && seen.insert(s.clone()) {
                result.push(ExtractedString {
                    value: s.clone(),
                    offset: 0,
                    source: StringSource::MemoEntry,
                });
            }
        }
    }

    for val in &state.stack {
        extract_from_value(val, &mut seen, &mut result);
    }

    result
}

fn extract_from_value(val: &StackValue, seen: &mut HashSet<String>, result: &mut Vec<ExtractedString>) {
    match val {
        StackValue::String(s) => {
            if s.len() >= 3 && seen.insert(s.clone()) {
                result.push(ExtractedString {
                    value: s.clone(),
                    offset: 0,
                    source: StringSource::StackLiteral,
                });
            }
        }
        StackValue::Bytes(b) => {
            if let Ok(s) = String::from_utf8(b.clone()) {
                if s.len() >= 3 && seen.insert(s.clone()) {
                    result.push(ExtractedString {
                        value: s,
                        offset: 0,
                        source: StringSource::BytesDecoded,
                    });
                }
            }
        }
        StackValue::Reduced { callable } => extract_from_value(callable, seen, result),
        StackValue::Built { base } => extract_from_value(base, seen, result),
        _ => {}
    }
}

pub fn find_urls(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    strings.iter().filter(|s| {
        s.value.starts_with("http://") || s.value.starts_with("https://")
            || s.value.starts_with("ftp://") || s.value.starts_with("file://")
    }).collect()
}

pub fn find_ips(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    strings.iter().filter(|s| {
        let parts: Vec<&str> = s.value.split('.').collect();
        if parts.len() == 4 {
            parts.iter().all(|p| p.parse::<u8>().is_ok())
        } else {
            false
        }
    }).collect()
}

pub fn find_suspicious_strings(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    let suspicious_patterns = [
        "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
        "base64", "eval(", "exec(", "__import__",
        "reverse_shell", "backdoor", "exploit",
        "password", "secret", "token", "api_key", "apikey",
    ];
    strings.iter().filter(|s| {
        let lower = s.value.to_lowercase();
        suspicious_patterns.iter().any(|p| lower.contains(p))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_detection() {
        let strings = vec![
            ExtractedString { value: "https://evil.com/payload".to_string(), offset: 0, source: StringSource::StackLiteral },
            ExtractedString { value: "hello world".to_string(), offset: 0, source: StringSource::StackLiteral },
        ];
        let urls = find_urls(&strings);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].value.contains("evil.com"));
    }

    #[test]
    fn test_ip_detection() {
        let strings = vec![
            ExtractedString { value: "192.168.1.1".to_string(), offset: 0, source: StringSource::StackLiteral },
            ExtractedString { value: "not.an.ip".to_string(), offset: 0, source: StringSource::StackLiteral },
        ];
        let ips = find_ips(&strings);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_suspicious_strings() {
        let strings = vec![
            ExtractedString { value: "/bin/bash -i".to_string(), offset: 0, source: StringSource::StackLiteral },
            ExtractedString { value: "normal_data".to_string(), offset: 0, source: StringSource::StackLiteral },
        ];
        let sus = find_suspicious_strings(&strings);
        assert_eq!(sus.len(), 1);
    }
}
