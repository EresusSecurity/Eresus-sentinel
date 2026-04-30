// mutators/character.rs — Inject special / control characters into string args
//
// Pickle SHORT_BINUNICODE / BINUNICODE carry raw UTF-8 strings.  This
// mutator injects null bytes, path separators, null terminators, newlines
// and other characters that are known to cause issues in downstream
// string processing.

use super::Mutator;

const SPECIAL_CHARS: [u8; 8] = [
    0x00, // null byte
    0x0A, // newline
    0x0D, // carriage return
    0x2F, // '/'  — path separator
    0x5C, // '\\' — Windows path separator
    0x2E, // '.'  — dot (for ../traversal)
    0x22, // '"'  — double quote
    0x27, // '\'' — single quote
];

pub struct CharacterMutator;

impl Mutator for CharacterMutator {
    fn name(&self) -> &'static str {
        "character"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if buf.is_empty() || offset >= buf.len() {
            return false;
        }
        let ch = SPECIAL_CHARS[offset % SPECIAL_CHARS.len()];
        if buf[offset] == ch {
            return false;
        }
        buf[offset] = ch;
        true
    }

    fn mutate_string(&self, value: String, rate: f64) -> Option<String> {
        if rate <= 0.0 || value.is_empty() { return None; }
        let mut chars: Vec<char> = value.chars().collect();
        let pos = value.len() % chars.len();
        let inject = SPECIAL_CHARS[pos % SPECIAL_CHARS.len()] as char;
        chars[pos] = inject;
        Some(chars.into_iter().collect())
    }

    fn mutate_bytes(&self, value: Vec<u8>, rate: f64) -> Option<Vec<u8>> {
        if rate <= 0.0 || value.is_empty() { return None; }
        let mut result = value;
        let pos = result.len() % result.len().max(1);
        result[pos] = SPECIAL_CHARS[pos % SPECIAL_CHARS.len()];
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_null() {
        let mut buf = vec![b'A', b'B'];
        assert!(CharacterMutator.mutate(&mut buf, 0));
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn mutate_string_injects_special() {
        let result = CharacterMutator.mutate_string("hello".to_string(), 1.0);
        assert!(result.is_some());
        assert_ne!(result.unwrap(), "hello");
    }

    #[test]
    fn mutate_string_empty() {
        assert!(CharacterMutator.mutate_string("".to_string(), 1.0).is_none());
    }
}
