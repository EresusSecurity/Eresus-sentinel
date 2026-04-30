// mutators/typeconfusion.rs — Substitute a type-bearing opcode with another
//
// Many opcode handlers assume the top-of-stack has a specific type.
// Replacing, say, BINUNICODE (text) with BINBYTES (bytes) while keeping
// the same argument bytes forces the scanner's type-dispatch code to
// handle an unexpected type without panicking.
//
// This mutator replaces the byte at `offset` with a different opcode
// from a fixed substitution table.

use super::Mutator;

/// (original_opcode_byte, replacement_opcode_byte) pairs.
/// Values taken from pickle protocol 2-5 opcode table.
const SUBSTITUTIONS: &[(u8, u8)] = &[
    (b'X', b'B'),   // SHORT_BINUNICODE → SHORT_BINBYTES
    (b'B', b'X'),   // SHORT_BINBYTES   → SHORT_BINUNICODE
    (b'C', b'U'),   // SHORT_BINBYTES   → SHORT_BINUNICODE (proto-1)
    (b'K', b'M'),   // BININT1          → BININT2
    (b'M', b'K'),   // BININT2          → BININT1
    (b'J', b'K'),   // BININT           → BININT1
    (b'F', b'G'),   // FLOAT            → BINFLOAT
    (b'G', b'F'),   // BINFLOAT         → FLOAT (text)
    (b']', b')'),   // EMPTY_LIST       → EMPTY_TUPLE
    (b')', b']'),   // EMPTY_TUPLE      → EMPTY_LIST
    (b'}', b']'),   // EMPTY_DICT       → EMPTY_LIST
];

pub struct TypeConfusionMutator;

impl Mutator for TypeConfusionMutator {
    fn name(&self) -> &'static str {
        "typeconfusion"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if buf.is_empty() || offset >= buf.len() {
            return false;
        }
        let original = buf[offset];
        for &(from, to) in SUBSTITUTIONS {
            if original == from {
                buf[offset] = to;
                return true;
            }
        }
        false
    }

    fn is_unsafe_mutator(&self) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_known_opcode() {
        let mut buf = vec![b'X']; // SHORT_BINUNICODE
        assert!(TypeConfusionMutator.mutate(&mut buf, 0));
        assert_eq!(buf[0], b'B');
    }

    #[test]
    fn no_sub_for_unknown() {
        let mut buf = vec![0xAAu8];
        assert!(!TypeConfusionMutator.mutate(&mut buf, 0));
    }
}
