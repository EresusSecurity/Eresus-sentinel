// mutators/stringlen.rs — Corrupt the length prefix of string / bytes opcodes
//
// BINUNICODE / SHORT_BINUNICODE / BINBYTES / SHORT_BINBYTES all have a
// length header (1 or 4 bytes, little-endian) followed by raw data.  If
// the declared length exceeds the remaining buffer this should produce a
// clean parse error, not a panic.  This mutator sets the length bytes to
// a value that is much larger than the actual remaining data.

use super::Mutator;

pub struct StringLengthMutator;

impl Mutator for StringLengthMutator {
    fn name(&self) -> &'static str {
        "stringlen"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if offset + 4 > buf.len() {
            if offset < buf.len() {
                buf[offset] = 0xFF;
                return true;
            }
            return false;
        }
        let big: [u8; 4] = u32::MAX.to_le_bytes();
        if &buf[offset..offset + 4] == &big {
            return false;
        }
        buf[offset..offset + 4].copy_from_slice(&big);
        true
    }

    fn mutate_string(&self, value: String, rate: f64) -> Option<String> {
        if rate <= 0.0 { return None; }
        // Alternate between empty string and oversized string
        if value.len() % 2 == 0 {
            Some(String::new()) // empty
        } else {
            // 65K+ string
            Some("A".repeat(65537))
        }
    }

    fn mutate_bytes(&self, value: Vec<u8>, rate: f64) -> Option<Vec<u8>> {
        if rate <= 0.0 { return None; }
        if value.len() % 2 == 0 {
            Some(Vec::new())
        } else {
            Some(vec![0x41; 65537])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_u32_max() {
        let mut buf = vec![0x00u8; 8];
        assert!(StringLengthMutator.mutate(&mut buf, 0));
        assert_eq!(&buf[0..4], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn fallback_single_byte() {
        let mut buf = vec![0x00u8, 0x00];
        assert!(StringLengthMutator.mutate(&mut buf, 0));
        // When < 4 bytes remain it falls back to single-byte 0xFF
        // (offset + 4 > 2 so the fallback path fires).
        assert_eq!(buf[0], 0xFF);
    }
}
