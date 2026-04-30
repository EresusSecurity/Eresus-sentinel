// mutators/memoindex.rs — Write out-of-range memo indices
//
// Pickle's GET / PUT / BINGET / BINPUT / LONG_BINGET / LONG_BINPUT
// opcodes carry memo indices.  An out-of-range GET should produce an
// error, not a panic.  This mutator rewrites the two bytes at `offset`
// as a u16 that is guaranteed to exceed any reasonable memo table size.

use super::Mutator;

/// Indices that are likely to be out of range in any real pickle.
const OOB_INDICES: [[u8; 2]; 4] = [
    [0xFF, 0xFF], // 65535
    [0x80, 0x00], // 32768
    [0xFF, 0x00], // 65280
    [0x00, 0x80], // 128 (might be in range — still interesting)
];

pub struct MemoIndexMutator;

impl Mutator for MemoIndexMutator {
    fn name(&self) -> &'static str {
        "memoindex"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if offset + 1 >= buf.len() {
            return false;
        }
        let pair = OOB_INDICES[offset % OOB_INDICES.len()];
        if buf[offset] == pair[0] && buf[offset + 1] == pair[1] {
            return false;
        }
        buf[offset]     = pair[0];
        buf[offset + 1] = pair[1];
        true
    }

    fn mutate_memo_index(&self, idx: usize, rate: f64) -> Option<usize> {
        if rate <= 0.0 { return None; }
        // Choose an OOB index
        let oob = [0xFFFF_usize, 0x8000, 0, 0xFF00];
        let pick = oob[idx % oob.len()];
        if pick == idx { None } else { Some(pick) }
    }

    fn is_unsafe_mutator(&self) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_oob_index() {
        let mut buf = vec![0x00u8, 0x00, 0x00];
        assert!(MemoIndexMutator.mutate(&mut buf, 0));
        assert_eq!(&buf[0..2], &OOB_INDICES[0]);
    }

    #[test]
    fn requires_two_bytes() {
        let mut buf = vec![0x00u8];
        assert!(!MemoIndexMutator.mutate(&mut buf, 0));
    }
}
