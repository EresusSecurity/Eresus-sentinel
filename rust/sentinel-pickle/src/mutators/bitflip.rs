// mutators/bitflip.rs — Flip individual bits in integer opcode arguments
//
// Targets opcodes that carry 1- or 4-byte integer arguments so the
// scanner sees every possible bit-pattern without waiting for libFuzzer
// to stumble onto them.

use super::Mutator;

pub struct BitFlipMutator;

impl Mutator for BitFlipMutator {
    fn name(&self) -> &'static str {
        "bitflip"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if buf.is_empty() || offset >= buf.len() {
            return false;
        }
        // Flip bit 0 of the target byte — deterministic, reproducible.
        buf[offset] ^= 0x01;
        true
    }

    fn mutate_int(&self, value: i32, rate: f64) -> Option<i32> {
        if rate <= 0.0 { return None; }
        // Flip a deterministic bit based on value
        let bit_pos = (value.unsigned_abs() as usize) % 32;
        Some(value ^ (1 << bit_pos))
    }

    fn mutate_long(&self, value: i64, rate: f64) -> Option<i64> {
        if rate <= 0.0 { return None; }
        let bit_pos = (value.unsigned_abs() as usize) % 64;
        Some(value ^ (1 << bit_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flips_lsb() {
        let mut buf = vec![0b1010_1010u8];
        let m = BitFlipMutator;
        assert!(m.mutate(&mut buf, 0));
        assert_eq!(buf[0], 0b1010_1011);
    }

    #[test]
    fn out_of_bounds_is_noop() {
        let mut buf = vec![0xFFu8];
        assert!(!BitFlipMutator.mutate(&mut buf, 99));
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn mutate_int_flips_bit() {
        let result = BitFlipMutator.mutate_int(0b1010_1010, 1.0);
        assert!(result.is_some());
        let mutated = result.unwrap();
        let diff = 0b1010_1010_i32 ^ mutated;
        assert_eq!(diff.count_ones(), 1);
    }

    #[test]
    fn mutate_int_rate_zero() {
        assert!(BitFlipMutator.mutate_int(42, 0.0).is_none());
    }

    #[test]
    fn mutate_long_flips_bit() {
        let result = BitFlipMutator.mutate_long(0x1234_5678, 1.0);
        assert!(result.is_some());
        let diff = 0x1234_5678_i64 ^ result.unwrap();
        assert_eq!(diff.count_ones(), 1);
    }
}
