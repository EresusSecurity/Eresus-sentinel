// generator/validation.rs — Opcode validation and selection
//
// Determines which opcodes can be safely emitted given current
// protocol version and stack/memo state.

use super::Generator;
use super::source::{EntropySource, GenerationSource};
use crate::opcode::Opcode;

/// Weight for opcode selection.  Dangerous opcodes get 3× weight.
fn op_weight(op: Opcode) -> usize {
    match op {
        Opcode::Global | Opcode::Inst | Opcode::StackGlobal |
        Opcode::Reduce | Opcode::Newobj | Opcode::NewobjEx |
        Opcode::Build | Opcode::Persid | Opcode::BinPersid => 3,
        _ => 1,
    }
}

/// All opcodes available per protocol version.
/// Returns opcodes valid for the given version, excluding STOP/PROTO
/// (those are handled specially by the generation loop).
pub(super) fn opcodes_for_version(version: u8) -> &'static [Opcode] {
    match version {
        0 => &PROTO0_OPS,
        1 => &PROTO1_OPS,
        2 => &PROTO2_OPS,
        3 => &PROTO3_OPS,
        4 | 5 => &PROTO4_OPS,
        _ => &PROTO4_OPS,
    }
}

static PROTO0_OPS: [Opcode; 25] = [
    Opcode::Int, Opcode::Long, Opcode::String, Opcode::NoneOp,
    Opcode::Unicode, Opcode::Float, Opcode::Append, Opcode::Build,
    Opcode::Global, Opcode::Inst, Opcode::Pop, Opcode::PopMark,
    Opcode::Dup, Opcode::Get, Opcode::Put, Opcode::Dict,
    Opcode::List, Opcode::Tuple, Opcode::Setitem, Opcode::Setitems,
    Opcode::Mark, Opcode::Reduce, Opcode::Persid, Opcode::BinString,
    Opcode::ShortBinString,
];

static PROTO1_OPS: [Opcode; 38] = [
    Opcode::Int, Opcode::Long, Opcode::String, Opcode::NoneOp,
    Opcode::Unicode, Opcode::Float, Opcode::Append, Opcode::Build,
    Opcode::Global, Opcode::Inst, Opcode::Pop, Opcode::PopMark,
    Opcode::Dup, Opcode::Get, Opcode::Put, Opcode::Dict,
    Opcode::List, Opcode::Tuple, Opcode::Setitem, Opcode::Setitems,
    Opcode::Mark, Opcode::Reduce, Opcode::Persid, Opcode::BinPersid,
    Opcode::EmptyDict, Opcode::EmptyList, Opcode::EmptyTuple,
    Opcode::Appends, Opcode::BinFloat, Opcode::BinInt, Opcode::BinInt1,
    Opcode::BinInt2, Opcode::BinGet, Opcode::LongBinGet,
    Opcode::BinPut, Opcode::LongBinPut, Opcode::BinString,
    Opcode::ShortBinString,
];

static PROTO2_OPS: [Opcode; 45] = [
    Opcode::Int, Opcode::Long, Opcode::String, Opcode::NoneOp,
    Opcode::Unicode, Opcode::Float, Opcode::Append, Opcode::Build,
    Opcode::Global, Opcode::Inst, Opcode::Pop, Opcode::PopMark,
    Opcode::Dup, Opcode::Get, Opcode::Put, Opcode::Dict,
    Opcode::List, Opcode::Tuple, Opcode::Setitem, Opcode::Setitems,
    Opcode::Mark, Opcode::Reduce, Opcode::Persid, Opcode::BinPersid,
    Opcode::EmptyDict, Opcode::EmptyList, Opcode::EmptyTuple,
    Opcode::Appends, Opcode::BinFloat, Opcode::BinInt, Opcode::BinInt1,
    Opcode::BinInt2, Opcode::BinGet, Opcode::LongBinGet,
    Opcode::BinPut, Opcode::LongBinPut, Opcode::BinString,
    Opcode::ShortBinString,
    Opcode::Newobj, Opcode::Tuple1, Opcode::Tuple2, Opcode::Tuple3,
    Opcode::NewTrue, Opcode::NewFalse, Opcode::Long1,
];

static PROTO3_OPS: [Opcode; 49] = [
    Opcode::Int, Opcode::Long, Opcode::String, Opcode::NoneOp,
    Opcode::Unicode, Opcode::Float, Opcode::Append, Opcode::Build,
    Opcode::Global, Opcode::Inst, Opcode::Pop, Opcode::PopMark,
    Opcode::Dup, Opcode::Get, Opcode::Put, Opcode::Dict,
    Opcode::List, Opcode::Tuple, Opcode::Setitem, Opcode::Setitems,
    Opcode::Mark, Opcode::Reduce, Opcode::Persid, Opcode::BinPersid,
    Opcode::EmptyDict, Opcode::EmptyList, Opcode::EmptyTuple,
    Opcode::Appends, Opcode::BinFloat, Opcode::BinInt, Opcode::BinInt1,
    Opcode::BinInt2, Opcode::BinGet, Opcode::LongBinGet,
    Opcode::BinPut, Opcode::LongBinPut, Opcode::BinString,
    Opcode::ShortBinString,
    Opcode::Newobj, Opcode::Tuple1, Opcode::Tuple2, Opcode::Tuple3,
    Opcode::NewTrue, Opcode::NewFalse, Opcode::Long1, Opcode::Long4,
    Opcode::BinUnicode, Opcode::BinBytes, Opcode::ShortBinBytes,
];

static PROTO4_OPS: [Opcode; 59] = [
    Opcode::Int, Opcode::Long, Opcode::String, Opcode::NoneOp,
    Opcode::Unicode, Opcode::Float, Opcode::Append, Opcode::Build,
    Opcode::Global, Opcode::Inst, Opcode::Pop, Opcode::PopMark,
    Opcode::Dup, Opcode::Get, Opcode::Put, Opcode::Dict,
    Opcode::List, Opcode::Tuple, Opcode::Setitem, Opcode::Setitems,
    Opcode::Mark, Opcode::Reduce, Opcode::Persid, Opcode::BinPersid,
    Opcode::EmptyDict, Opcode::EmptyList, Opcode::EmptyTuple,
    Opcode::Appends, Opcode::BinFloat, Opcode::BinInt, Opcode::BinInt1,
    Opcode::BinInt2, Opcode::BinGet, Opcode::LongBinGet,
    Opcode::BinPut, Opcode::LongBinPut, Opcode::BinString,
    Opcode::ShortBinString,
    Opcode::Newobj, Opcode::NewobjEx, Opcode::Tuple1, Opcode::Tuple2,
    Opcode::Tuple3, Opcode::NewTrue, Opcode::NewFalse,
    Opcode::Long1, Opcode::Long4,
    Opcode::BinUnicode, Opcode::BinBytes, Opcode::ShortBinBytes,
    Opcode::ShortBinUnicode, Opcode::BinUnicode8, Opcode::BinBytes8,
    Opcode::Bytearray8,
    Opcode::EmptySet, Opcode::Additems, Opcode::Frozenset,
    Opcode::StackGlobal, Opcode::Memoize,
];

impl Generator {
    /// Get all opcodes valid for current state.
    pub(super) fn get_valid_opcodes(&self) -> Vec<Opcode> {
        let all = opcodes_for_version(self.version);
        all.iter().copied().filter(|&op| self.can_emit(op)).collect()
    }

    /// Choose an opcode using weighted selection.
    ///
    /// Dangerous opcodes (GLOBAL, INST, REDUCE, STACK_GLOBAL, NEWOBJ,
    /// NEWOBJ_EX) get 3× weight so the generator exercises the scanner's
    /// critical detection paths more frequently.  All other opcodes get
    /// weight 1.
    pub(super) fn weighted_choice(
        &self,
        opcodes: &[Opcode],
        source: &mut GenerationSource,
    ) -> Opcode {
        if opcodes.is_empty() {
            return Opcode::NoneOp;
        }
        let total_weight: usize = opcodes.iter().map(|op| op_weight(*op)).sum();
        let mut pick = source.gen_range(0, total_weight);
        for &op in opcodes {
            let w = op_weight(op);
            if pick < w {
                return op;
            }
            pick -= w;
        }
        *opcodes.last().unwrap()
    }

    /// Can we emit this opcode in the current state?
    pub(super) fn can_emit(&self, op: Opcode) -> bool {
        let depth = self.stack_depth();
        match op {
            // Value producers — always valid (push one item)
            Opcode::NoneOp | Opcode::NewTrue | Opcode::NewFalse |
            Opcode::Int | Opcode::Long | Opcode::Long1 | Opcode::Long4 |
            Opcode::Float | Opcode::BinFloat |
            Opcode::BinInt | Opcode::BinInt1 | Opcode::BinInt2 |
            Opcode::String | Opcode::BinString | Opcode::ShortBinString |
            Opcode::BinUnicode | Opcode::ShortBinUnicode |
            Opcode::BinUnicode8 | Opcode::Unicode |
            Opcode::BinBytes | Opcode::ShortBinBytes | Opcode::BinBytes8 |
            Opcode::Bytearray8 |
            Opcode::EmptyList | Opcode::EmptyDict | Opcode::EmptyTuple |
            Opcode::EmptySet |
            Opcode::Persid => depth < 4000,

            // Mark — always valid (but limit nesting)
            Opcode::Mark => depth < 4000,

            // Pop — need at least 1 item
            Opcode::Pop => depth >= 1,

            // Dup — need at least 1 non-mark item
            Opcode::Dup => depth >= 1 && !matches!(self.peek(), Some(super::state::GenStackValue::Mark)),

            // PopMark — need mark on stack
            Opcode::PopMark => self.has_mark(),

            // BinPersid — need TOS as pid
            Opcode::BinPersid => depth >= 1,

            // Get from memo — need memo entries
            Opcode::Get | Opcode::BinGet | Opcode::LongBinGet => self.has_memo(),

            // Put into memo — need something on stack
            Opcode::Put | Opcode::BinPut | Opcode::LongBinPut => depth >= 1 && !matches!(self.peek(), Some(super::state::GenStackValue::Mark)),

            // Memoize — like put
            Opcode::Memoize => depth >= 1 && !matches!(self.peek(), Some(super::state::GenStackValue::Mark)),

            // Global / Inst — always valid (produces a callable)
            Opcode::Global => depth < 4000,

            // Inst — need mark on stack (pops args from mark)
            Opcode::Inst => self.has_mark(),

            // StackGlobal — need two strings on stack
            Opcode::StackGlobal => depth >= 2 && self.tos_is_string() && self.tos1_is_string(),

            // Reduce — need callable + args tuple on stack
            Opcode::Reduce => depth >= 2 && self.tos_is_callable() || depth >= 2,

            // Newobj — need cls + args on stack
            Opcode::Newobj => depth >= 2,

            // NewobjEx — need cls + args + kwargs on stack
            Opcode::NewobjEx => depth >= 3,

            // Build — need object + state on stack
            Opcode::Build => depth >= 2,

            // Tuple1/2/3 — need N items
            Opcode::Tuple1 => depth >= 1,
            Opcode::Tuple2 => depth >= 2,
            Opcode::Tuple3 => depth >= 3,

            // Tuple/List/Dict from mark — need mark on stack
            Opcode::Tuple | Opcode::List | Opcode::Dict | Opcode::Frozenset => self.has_mark(),

            // Append — need list + item
            Opcode::Append => depth >= 2 && self.tos_is_list(),

            // Appends — need mark, and list below mark
            Opcode::Appends => self.has_mark() && depth >= 2,

            // Setitem — need dict + key + value
            Opcode::Setitem => depth >= 3,

            // Setitems — need mark + dict below
            Opcode::Setitems => self.has_mark() && depth >= 2,

            // Additems — need mark + set below
            Opcode::Additems => self.has_mark() && depth >= 2,

            // Anything else — conservative: no
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto0_has_global() {
        let ops = opcodes_for_version(0);
        assert!(ops.contains(&Opcode::Global));
    }

    #[test]
    fn test_proto4_has_stack_global() {
        let ops = opcodes_for_version(4);
        assert!(ops.contains(&Opcode::StackGlobal));
    }

    #[test]
    fn test_proto4_has_memoize() {
        let ops = opcodes_for_version(4);
        assert!(ops.contains(&Opcode::Memoize));
    }

    #[test]
    fn test_proto0_has_inst() {
        let ops = opcodes_for_version(0);
        assert!(ops.contains(&Opcode::Inst));
        assert!(ops.contains(&Opcode::Persid));
        assert!(ops.contains(&Opcode::PopMark));
    }

    #[test]
    fn test_proto2_has_long4() {
        // Long4 available from proto 3+
        let ops2 = opcodes_for_version(2);
        assert!(!ops2.contains(&Opcode::Long4));
        let ops3 = opcodes_for_version(3);
        assert!(ops3.contains(&Opcode::Long4));
    }

    #[test]
    fn test_proto4_has_newobj_ex() {
        let ops = opcodes_for_version(4);
        assert!(ops.contains(&Opcode::NewobjEx));
        assert!(ops.contains(&Opcode::Bytearray8));
        assert!(ops.contains(&Opcode::LongBinGet));
        assert!(ops.contains(&Opcode::LongBinPut));
    }

    #[test]
    fn test_op_weight_dangerous_higher() {
        assert_eq!(op_weight(Opcode::Global), 3);
        assert_eq!(op_weight(Opcode::Inst), 3);
        assert_eq!(op_weight(Opcode::Reduce), 3);
        assert_eq!(op_weight(Opcode::NewobjEx), 3);
        assert_eq!(op_weight(Opcode::NoneOp), 1);
        assert_eq!(op_weight(Opcode::BinInt), 1);
    }

    #[test]
    fn test_each_proto_superset_of_previous() {
        let p0 = opcodes_for_version(0);
        let p1 = opcodes_for_version(1);
        let p2 = opcodes_for_version(2);
        let p3 = opcodes_for_version(3);
        let p4 = opcodes_for_version(4);

        // Each version should contain at least all opcodes from the previous
        for &op in p0 { assert!(p1.contains(&op), "proto1 missing {op:?}"); }
        for &op in p1 { assert!(p2.contains(&op), "proto2 missing {op:?}"); }
        for &op in p2 { assert!(p3.contains(&op), "proto3 missing {op:?}"); }
        for &op in p3 { assert!(p4.contains(&op), "proto4 missing {op:?}"); }
    }
}
