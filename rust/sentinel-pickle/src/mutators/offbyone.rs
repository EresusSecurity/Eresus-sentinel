// mutators/offbyone.rs — Increment or decrement integer argument by 1
//
// Off-by-one errors are a classic source of buffer overreads and
// length miscalculations.  This mutator adds 1 to the byte at `offset`
// (wrapping) so that, for example, a BINUNICODE length field is one
// larger than the actual data that follows.

use super::Mutator;

pub struct OffByOneMutator;

impl Mutator for OffByOneMutator {
    fn name(&self) -> &'static str {
        "offbyone"
    }

    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool {
        if buf.is_empty() || offset >= buf.len() {
            return false;
        }
        buf[offset] = buf[offset].wrapping_add(1);
        true
    }

    fn mutate_int(&self, value: i32, rate: f64) -> Option<i32> {
        if rate <= 0.0 { return None; }
        // Alternate between +1 and -1 based on value
        if value % 2 == 0 {
            Some(value.wrapping_add(1))
        } else {
            Some(value.wrapping_sub(1))
        }
    }

    fn mutate_long(&self, value: i64, rate: f64) -> Option<i64> {
        if rate <= 0.0 { return None; }
        if value % 2 == 0 {
            Some(value.wrapping_add(1))
        } else {
            Some(value.wrapping_sub(1))
        }
    }

    fn mutate_memo_index(&self, idx: usize, rate: f64) -> Option<usize> {
        if rate <= 0.0 { return None; }
        Some(idx.wrapping_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments() {
        let mut buf = vec![0x41u8];
        assert!(OffByOneMutator.mutate(&mut buf, 0));
        assert_eq!(buf[0], 0x42);
    }

    #[test]
    fn wraps_on_max() {
        let mut buf = vec![0xFFu8];
        assert!(OffByOneMutator.mutate(&mut buf, 0));
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn oob_is_noop() {
        let mut buf = vec![0x01u8];
        assert!(!OffByOneMutator.mutate(&mut buf, 5));
    }
}
