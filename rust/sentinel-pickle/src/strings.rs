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

    for (_idx, val) in state.memo.iter() {
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

fn extract_from_value(
    val: &StackValue,
    seen: &mut HashSet<String>,
    result: &mut Vec<ExtractedString>,
) {
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
    strings
        .iter()
        .filter(|s| {
            s.value.starts_with("http://")
                || s.value.starts_with("https://")
                || s.value.starts_with("ftp://")
                || s.value.starts_with("file://")
        })
        .collect()
}

pub fn find_ips(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    strings
        .iter()
        .filter(|s| {
            let parts: Vec<&str> = s.value.split('.').collect();
            if parts.len() == 4 {
                parts.iter().all(|p| p.parse::<u8>().is_ok())
            } else {
                false
            }
        })
        .collect()
}

pub fn find_suspicious_strings(strings: &[ExtractedString]) -> Vec<&ExtractedString> {
    let suspicious_patterns = [
        "/bin/sh",
        "/bin/bash",
        "cmd.exe",
        "powershell",
        "base64",
        "eval(",
        "exec(",
        "__import__",
        "reverse_shell",
        "backdoor",
        "exploit",
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
    ];
    strings
        .iter()
        .filter(|s| {
            let lower = s.value.to_lowercase();
            suspicious_patterns.iter().any(|p| lower.contains(p))
        })
        .collect()
}

/// S601: base64-encoded pickle payload inside a string literal.
/// Detects strings that, when base64-decoded, begin with pickle protocol markers.
pub fn find_nested_pickle_b64(strings: &[ExtractedString]) -> Vec<NestedPickleHit> {
    let mut hits = Vec::new();
    for s in strings {
        let trimmed = s.value.trim();
        if trimmed.len() < 8 {
            continue;
        }
        if let Ok(decoded) = base64_decode_permissive(trimmed) {
            if is_pickle_stream(&decoded) {
                hits.push(NestedPickleHit {
                    rule_id: "S601".to_string(),
                    encoding: "base64".to_string(),
                    value_preview: trimmed[..trimmed.len().min(64)].to_string(),
                    offset: s.offset,
                    decoded_len: decoded.len(),
                });
            }
        }
    }
    hits
}

/// S602: hex-encoded pickle payload inside a string literal.
pub fn find_nested_pickle_hex(strings: &[ExtractedString]) -> Vec<NestedPickleHit> {
    let mut hits = Vec::new();
    for s in strings {
        let trimmed = s.value.trim();
        if trimmed.len() < 8 {
            continue;
        }
        let candidate = trimmed
            .strip_prefix("0x")
            .or(trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if candidate.chars().all(|c| c.is_ascii_hexdigit()) && candidate.len() % 2 == 0 {
            if let Ok(decoded) = hex_decode(candidate) {
                if is_pickle_stream(&decoded) {
                    hits.push(NestedPickleHit {
                        rule_id: "S602".to_string(),
                        encoding: "hex".to_string(),
                        value_preview: trimmed[..trimmed.len().min(64)].to_string(),
                        offset: s.offset,
                        decoded_len: decoded.len(),
                    });
                }
            }
        }
    }
    hits
}

/// S213: raw (unencoded) nested pickle payload inside a bytes field.
pub fn find_nested_pickle_raw_bytes(state: &crate::state::PVMState) -> Vec<NestedPickleHit> {
    let mut hits = Vec::new();
    for val in &state.stack {
        if let crate::state::StackValue::Bytes(b) = val {
            if b.len() >= 4 && is_pickle_stream(b) {
                hits.push(NestedPickleHit {
                    rule_id: "S213".to_string(),
                    encoding: "raw".to_string(),
                    value_preview: format!("<bytes len={}>", b.len()),
                    offset: 0,
                    decoded_len: b.len(),
                });
            }
        }
    }
    for (_idx, val) in &state.memo {
        if let crate::state::StackValue::Bytes(b) = val {
            if b.len() >= 4 && is_pickle_stream(b) {
                hits.push(NestedPickleHit {
                    rule_id: "S213".to_string(),
                    encoding: "raw_memo".to_string(),
                    value_preview: format!("<bytes len={}>", b.len()),
                    offset: 0,
                    decoded_len: b.len(),
                });
            }
        }
    }
    hits
}

#[derive(Debug, Clone)]
pub struct NestedPickleHit {
    pub rule_id: String,
    pub encoding: String,
    pub value_preview: String,
    pub offset: usize,
    pub decoded_len: usize,
}

/// Returns true if bytes look like a pickle stream (protocol 0-5 marker or protocol 0 text marker).
fn is_pickle_stream(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // Protocol 1-5: starts with \x80 followed by protocol version byte 1-5
    if data[0] == 0x80 && data[1] >= 1 && data[1] <= 5 {
        return true;
    }
    // Protocol 0: starts with common text opcodes and contains STOP '.'
    if matches!(
        data[0],
        b'c' | b'(' | b'l' | b'd' | b']' | b'}' | b'I' | b'F' | b'S' | b'V' | b'N'
    ) {
        return data.contains(&b'.');
    }
    false
}

fn base64_decode_permissive(s: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [0xffu8; 256];
    for (i, &b) in TABLE.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }
    lookup[b'-' as usize] = 62;
    lookup[b'_' as usize] = 63;

    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut v = [0u8; 4];
        let mut padding = 0usize;
        for (idx, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                if idx < 2 {
                    return Err(());
                }
                padding += 1;
                v[idx] = 0;
                continue;
            }
            if padding > 0 {
                return Err(());
            }
            let decoded = lookup[b as usize];
            if decoded == 0xff {
                return Err(());
            }
            v[idx] = decoded;
        }
        if padding > 2 {
            return Err(());
        }
        let n =
            ((v[0] as u32) << 18) | ((v[1] as u32) << 12) | ((v[2] as u32) << 6) | (v[3] as u32);
        out.push((n >> 16) as u8);
        if padding < 2 {
            out.push((n >> 8) as u8);
        }
        if padding < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(());
    }
    let nibble = |b: u8| -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_detection() {
        let strings = vec![
            ExtractedString {
                value: "https://evil.com/payload".to_string(),
                offset: 0,
                source: StringSource::StackLiteral,
            },
            ExtractedString {
                value: "hello world".to_string(),
                offset: 0,
                source: StringSource::StackLiteral,
            },
        ];
        let urls = find_urls(&strings);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].value.contains("evil.com"));
    }

    #[test]
    fn test_ip_detection() {
        let strings = vec![
            ExtractedString {
                value: "192.168.1.1".to_string(),
                offset: 0,
                source: StringSource::StackLiteral,
            },
            ExtractedString {
                value: "not.an.ip".to_string(),
                offset: 0,
                source: StringSource::StackLiteral,
            },
        ];
        let ips = find_ips(&strings);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_suspicious_strings() {
        let strings = vec![
            ExtractedString {
                value: "/bin/bash -i".to_string(),
                offset: 0,
                source: StringSource::StackLiteral,
            },
            ExtractedString {
                value: "normal_data".to_string(),
                offset: 0,
                source: StringSource::StackLiteral,
            },
        ];
        let sus = find_suspicious_strings(&strings);
        assert_eq!(sus.len(), 1);
    }

    #[test]
    fn test_nested_pickle_base64_detection_handles_padding() {
        let strings = vec![ExtractedString {
            value: "gAROLg==".to_string(),
            offset: 7,
            source: StringSource::StackLiteral,
        }];

        let hits = find_nested_pickle_b64(&strings);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "S601");
        assert_eq!(hits[0].decoded_len, 4);
    }

    #[test]
    fn test_nested_pickle_hex_detection() {
        let strings = vec![ExtractedString {
            value: "80044e2e".to_string(),
            offset: 11,
            source: StringSource::StackLiteral,
        }];

        let hits = find_nested_pickle_hex(&strings);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "S602");
        assert_eq!(hits[0].decoded_len, 4);
    }
}
