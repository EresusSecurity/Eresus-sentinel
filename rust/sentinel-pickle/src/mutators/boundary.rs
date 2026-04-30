// mutators/boundary.rs — Replace integer argument bytes with boundary values
//
// Boundary values (0, 1, -1, i8::MAX, i32::MAX, u32::MAX, …) are the
// most common source of integer overflow / underflow bugs.  This mutator
// overwrites the byte(s) at `offset` with one of these canonical values
// cycling through them round-robin based on offset.

use super::Mutator;

/// Canonical boundary byte sequences (big-endian / little-endian as needed
/// by pickle — most integer args are 1 byte or 4-byte little-endian).
const BOUNDARIES_U8: [u8; 6] = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF];

pub struct BoundaryMutator;

const BOUNDARY_I32: [i32; 6] = [0, 1, -1, i32::MAX, i32::MIN, 0x7FFF];
const BOUNDARY_I64: [i64; 6] = [0, 1, -1, i64::MAX, i64::MIN, 0x7FFF_FFFF];
const BOUNDARY_F64: [f64; 6] = [0.0, -0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MIN_POSITIVE];

impl Mutator for BoundaryMutator {
    fn name(&self) -> &'static str {
        "boundary"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if buf.is_empty() || offset >= buf.len() {
            return false;
        }
        let val = BOUNDARIES_U8[offset % BOUNDARIES_U8.len()];
        if buf[offset] == val {
            return false;
        }
        buf[offset] = val;
        true
    }

    fn mutate_int(&self, value: i32, rate: f64) -> Option<i32> {
        if rate <= 0.0 { return None; }
        let idx = (value.unsigned_abs() as usize) % BOUNDARY_I32.len();
        let bv = BOUNDARY_I32[idx];
        if bv == value { None } else { Some(bv) }
    }

    fn mutate_long(&self, value: i64, rate: f64) -> Option<i64> {
        if rate <= 0.0 { return None; }
        let idx = (value.unsigned_abs() as usize) % BOUNDARY_I64.len();
        let bv = BOUNDARY_I64[idx];
        if bv == value { None } else { Some(bv) }
    }

    fn mutate_float(&self, _value: f64, rate: f64) -> Option<f64> {
        if rate <= 0.0 { return None; }
        let idx = (_value.to_bits() as usize) % BOUNDARY_F64.len();
        Some(BOUNDARY_F64[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_boundary_value() {
        let mut buf = vec![0x42u8, 0x42, 0x42];
        assert!(BoundaryMutator.mutate(&mut buf, 0));
        assert_eq!(buf[0], BOUNDARIES_U8[0]);
    }

    #[test]
    fn no_change_if_already_boundary() {
        let mut buf = vec![0x00u8]; // BOUNDARIES_U8[0]
        assert!(!BoundaryMutator.mutate(&mut buf, 0));
    }

    #[test]
    fn mutate_int_boundary() {
        let result = BoundaryMutator.mutate_int(42, 1.0);
        assert!(result.is_some());
        assert!(BOUNDARY_I32.contains(&result.unwrap()));
    }

    #[test]
    fn mutate_float_boundary() {
        let result = BoundaryMutator.mutate_float(3.14, 1.0);
        assert!(result.is_some());
    }
}
