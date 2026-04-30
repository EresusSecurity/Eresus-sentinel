// opcode.rs — Pickle protocol 0-5 opcode definitions
// ---------------------------------------------------
// Every opcode the CPython pickletools module knows about is represented
// here as a Rust enum.  We derive the opcode from a single byte and
// carry metadata about how many additional bytes the opcode consumes
// so the scanner can advance the cursor correctly even on opcodes it
// does not need to analyse.

use std::fmt;

/// Severity level for findings produced by the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info     => write!(f, "INFO"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Pickle opcodes across protocol versions 0-5.
///
/// Each variant stores the single-byte opcode value for easy matching.
/// Opcodes that are security-relevant (i.e. they can trigger arbitrary
/// code execution during unpickling) are documented with `/// DANGER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // ── Protocol 0 ──────────────────────────────────────────────────
    /// Push an integer from a decimal string on the next line.
    Int            = b'I',
    /// Push a long integer from a decimal string.
    Long           = b'L',
    /// Push a string (repr-style) on the next line.
    String         = b'S',
    /// Push None.
    NoneOp         = b'N',
    /// Push True  (protocol 0 encodes as I01).
    TrueOp         = 0x01, // sentinel — we map I01 here
    /// Push False (protocol 0 encodes as I00).
    FalseOp        = 0x00, // sentinel — we map I00 here
    /// Push a Unicode string (next line, raw-unicode-escape).
    Unicode        = b'V',
    /// Push a float from a decimal string on the next line.
    Float          = b'F',
    /// Append to list (TOS is item, TOS-1 is list).
    Append         = b'a',
    /// Build (call __setstate__ or __dict__.update).
    Build          = b'b',
    /// DANGER — push self.find_class(module, name) — arbitrary import.
    Global         = b'c',
    /// Pop and discard TOS.
    Pop            = b'0',
    /// Pop everything down to and including the topmost mark.
    PopMark        = b'1',
    /// Duplicate TOS.
    Dup            = b'2',
    /// Push a get from the memo (decimal index on next line).
    Get            = b'g',
    /// DANGER — push self.find_class(module, name) — like GLOBAL.
    Inst           = b'i',
    /// Push a counted string.
    BinString      = b'T',
    /// Push a 1-byte-length string.
    ShortBinString = b'U',
    /// Finish pickling — push TOS as the result.
    Stop           = b'.',
    /// Store TOS in memo under decimal key on next line.
    Put            = b'p',
    /// Build a dict from stack pairs.
    Dict           = b'd',
    /// Build a list from stack items.
    List           = b'l',
    /// Build a tuple from stack items.
    Tuple          = b't',
    /// Set dict[TOS-2][TOS-1] = TOS.
    Setitem        = b's',
    /// Set multiple dict items.
    Setitems       = b'u',
    /// Push a mark (grouping sentinel).
    Mark           = b'(',
    /// DANGER — call a callable with args.
    Reduce         = b'R',
    /// Push a class (like GLOBAL, for protocol 0 compatibility).
    Persid         = b'P',
    /// Push a class by persistent id (binary).
    BinPersid      = b'Q',

    // ── Protocol 1 ──────────────────────────────────────────────────
    /// Push an empty dict.
    EmptyDict      = b'}',
    /// Push an empty list.
    EmptyList      = b']',
    /// Push an empty tuple.
    EmptyTuple     = b')',
    /// Extend list with TOS items.
    Appends        = b'e',
    /// Push an 8-byte IEEE 754 float.
    BinFloat       = b'G',
    /// Push a 4-byte signed int.
    BinInt         = b'J',
    /// Push a 1-byte unsigned int.
    BinInt1        = b'K',
    /// Push a 2-byte unsigned int (little-endian).
    BinInt2        = b'M',
    /// Get from memo by 1-byte index.
    BinGet         = b'h',
    /// Get from memo by 4-byte index.
    LongBinGet     = b'j',
    /// Put into memo by 1-byte index.
    BinPut         = b'q',
    /// Put into memo by 4-byte index.
    LongBinPut     = b'r',
    /// Push a 4-byte-length Unicode string.
    BinUnicode     = b'X',
    /// Push a 4-byte-length bytes object.
    BinBytes       = b'B',
    /// Push a 1-byte-length bytes object.
    ShortBinBytes  = b'C',

    // ── Protocol 2 ──────────────────────────────────────────────────
    /// Protocol indicator — first byte of a protocol-2+ pickle.
    Proto          = 0x80,
    /// DANGER — push obj.__new__(cls) — can invoke arbitrary __new__.
    Newobj         = 0x81,
    /// Build a 2-tuple from TOS-1, TOS.
    Tuple1         = 0x85,
    /// Build a 3-tuple.
    Tuple2         = 0x86,
    /// Build a tuple of N items.
    Tuple3         = 0x87,
    /// Push True (binary).
    NewTrue        = 0x88,
    /// Push False (binary).
    NewFalse       = 0x89,
    /// Push a long integer from a counted byte string.
    Long1          = 0x8a,
    /// Push a long integer from a 4-byte-counted byte string.
    Long4          = 0x8b,

    // ── Protocol 4 ──────────────────────────────────────────────────
    /// Push a short (1-byte length) binary Unicode string.
    ShortBinUnicode = 0x8c,
    /// Push an 8-byte-length binary Unicode string.
    BinUnicode8    = 0x8d,
    /// Push an 8-byte-length bytes object.
    BinBytes8      = 0x8e,
    /// Push an empty set.
    EmptySet       = 0x8f,
    /// Add items to a set.
    Additems       = 0x90,
    /// Freeze a set (make it a frozenset).
    Frozenset      = 0x91,
    /// DANGER — like NEWOBJ but takes **kwargs too.
    NewobjEx       = 0x92,
    /// DANGER — STACK_GLOBAL: pop name, pop module, push find_class result.
    StackGlobal    = 0x93,
    /// Memoize TOS with the next available memo index.
    Memoize        = 0x94,
    /// Frame — a length-prefixed chunk (for efficient reads).
    Frame          = 0x95,

    // ── Protocol 5 ──────────────────────────────────────────────────
    /// Push a bytearray from inline data.
    Bytearray8     = 0x96,
    /// Push a PickleBuffer pointing at the next out-of-band buffer.
    NextBuffer     = 0x97,
    /// Make TOS read-only.
    ReadonlyBuffer = 0x98,

    // ── Catch-all ────────────────────────────────────────────────────
    /// An opcode we do not recognise — may indicate corruption or a
    /// future protocol extension.  Always flagged.
    Unknown        = 0xFF,
}

impl Opcode {
    /// Decode a single byte into an `Opcode`.
    ///
    /// Unknown bytes map to `Opcode::Unknown` and will be reported
    /// as a coverage gap.
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            b'I' => Opcode::Int,
            b'L' => Opcode::Long,
            b'S' => Opcode::String,
            b'N' => Opcode::NoneOp,
            b'V' => Opcode::Unicode,
            b'F' => Opcode::Float,
            b'a' => Opcode::Append,
            b'b' => Opcode::Build,
            b'c' => Opcode::Global,
            b'0' => Opcode::Pop,
            b'1' => Opcode::PopMark,
            b'2' => Opcode::Dup,
            b'g' => Opcode::Get,
            b'i' => Opcode::Inst,
            b'T' => Opcode::BinString,
            b'U' => Opcode::ShortBinString,
            b'.' => Opcode::Stop,
            b'p' => Opcode::Put,
            b'd' => Opcode::Dict,
            b'l' => Opcode::List,
            b't' => Opcode::Tuple,
            b's' => Opcode::Setitem,
            b'u' => Opcode::Setitems,
            b'(' => Opcode::Mark,
            b'R' => Opcode::Reduce,
            b'P' => Opcode::Persid,
            b'Q' => Opcode::BinPersid,
            b'}' => Opcode::EmptyDict,
            b']' => Opcode::EmptyList,
            b')' => Opcode::EmptyTuple,
            b'e' => Opcode::Appends,
            b'G' => Opcode::BinFloat,
            b'J' => Opcode::BinInt,
            b'K' => Opcode::BinInt1,
            b'M' => Opcode::BinInt2,
            b'h' => Opcode::BinGet,
            b'j' => Opcode::LongBinGet,
            b'q' => Opcode::BinPut,
            b'r' => Opcode::LongBinPut,
            b'X' => Opcode::BinUnicode,
            b'B' => Opcode::BinBytes,
            b'C' => Opcode::ShortBinBytes,
            0x80 => Opcode::Proto,
            0x81 => Opcode::Newobj,
            0x85 => Opcode::Tuple1,
            0x86 => Opcode::Tuple2,
            0x87 => Opcode::Tuple3,
            0x88 => Opcode::NewTrue,
            0x89 => Opcode::NewFalse,
            0x8a => Opcode::Long1,
            0x8b => Opcode::Long4,
            0x8c => Opcode::ShortBinUnicode,
            0x8d => Opcode::BinUnicode8,
            0x8e => Opcode::BinBytes8,
            0x8f => Opcode::EmptySet,
            0x90 => Opcode::Additems,
            0x91 => Opcode::Frozenset,
            0x92 => Opcode::NewobjEx,
            0x93 => Opcode::StackGlobal,
            0x94 => Opcode::Memoize,
            0x95 => Opcode::Frame,
            0x96 => Opcode::Bytearray8,
            0x97 => Opcode::NextBuffer,
            0x98 => Opcode::ReadonlyBuffer,
            _    => Opcode::Unknown,
        }
    }

    /// Whether this opcode can trigger arbitrary code execution during
    /// unpickling.  These are the opcodes the policy engine must inspect.
    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            Opcode::Global
                | Opcode::Inst
                | Opcode::Reduce
                | Opcode::Newobj
                | Opcode::NewobjEx
                | Opcode::StackGlobal
                | Opcode::Build
        )
    }

    /// Whether this opcode creates a callable reference that might later
    /// be invoked via REDUCE.
    pub fn is_global_resolver(&self) -> bool {
        matches!(
            self,
            Opcode::Global | Opcode::Inst | Opcode::StackGlobal
        )
    }

    /// Human-readable name matching CPython's pickletools naming.
    pub fn name(&self) -> &'static str {
        match self {
            Opcode::Int            => "INT",
            Opcode::Long           => "LONG",
            Opcode::String         => "STRING",
            Opcode::NoneOp         => "NONE",
            Opcode::TrueOp         => "TRUE",
            Opcode::FalseOp        => "FALSE",
            Opcode::Unicode        => "UNICODE",
            Opcode::Float          => "FLOAT",
            Opcode::Append         => "APPEND",
            Opcode::Build          => "BUILD",
            Opcode::Global         => "GLOBAL",
            Opcode::Pop            => "POP",
            Opcode::PopMark        => "POP_MARK",
            Opcode::Dup            => "DUP",
            Opcode::Get            => "GET",
            Opcode::Inst           => "INST",
            Opcode::BinString      => "BINSTRING",
            Opcode::ShortBinString => "SHORT_BINSTRING",
            Opcode::Stop           => "STOP",
            Opcode::Put            => "PUT",
            Opcode::Dict           => "DICT",
            Opcode::List           => "LIST",
            Opcode::Tuple          => "TUPLE",
            Opcode::Setitem        => "SETITEM",
            Opcode::Setitems       => "SETITEMS",
            Opcode::Mark           => "MARK",
            Opcode::Reduce         => "REDUCE",
            Opcode::Persid         => "PERSID",
            Opcode::BinPersid      => "BINPERSID",
            Opcode::EmptyDict      => "EMPTY_DICT",
            Opcode::EmptyList      => "EMPTY_LIST",
            Opcode::EmptyTuple     => "EMPTY_TUPLE",
            Opcode::Appends        => "APPENDS",
            Opcode::BinFloat       => "BINFLOAT",
            Opcode::BinInt         => "BININT",
            Opcode::BinInt1        => "BININT1",
            Opcode::BinInt2        => "BININT2",
            Opcode::BinGet         => "BINGET",
            Opcode::LongBinGet     => "LONG_BINGET",
            Opcode::BinPut         => "BINPUT",
            Opcode::LongBinPut     => "LONG_BINPUT",
            Opcode::BinUnicode     => "BINUNICODE",
            Opcode::BinBytes       => "BINBYTES",
            Opcode::ShortBinBytes  => "SHORT_BINBYTES",
            Opcode::Proto          => "PROTO",
            Opcode::Newobj         => "NEWOBJ",
            Opcode::Tuple1         => "TUPLE1",
            Opcode::Tuple2         => "TUPLE2",
            Opcode::Tuple3         => "TUPLE3",
            Opcode::NewTrue        => "NEWTRUE",
            Opcode::NewFalse       => "NEWFALSE",
            Opcode::Long1          => "LONG1",
            Opcode::Long4          => "LONG4",
            Opcode::ShortBinUnicode=> "SHORT_BINUNICODE",
            Opcode::BinUnicode8    => "BINUNICODE8",
            Opcode::BinBytes8      => "BINBYTES8",
            Opcode::EmptySet       => "EMPTY_SET",
            Opcode::Additems       => "ADDITEMS",
            Opcode::Frozenset      => "FROZENSET",
            Opcode::NewobjEx       => "NEWOBJ_EX",
            Opcode::StackGlobal    => "STACK_GLOBAL",
            Opcode::Memoize        => "MEMOIZE",
            Opcode::Frame          => "FRAME",
            Opcode::Bytearray8     => "BYTEARRAY8",
            Opcode::NextBuffer     => "NEXT_BUFFER",
            Opcode::ReadonlyBuffer => "READONLY_BUFFER",
            Opcode::Unknown        => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_opcodes() {
        assert!(Opcode::Global.is_dangerous());
        assert!(Opcode::Reduce.is_dangerous());
        assert!(Opcode::StackGlobal.is_dangerous());
        assert!(!Opcode::Stop.is_dangerous());
        assert!(!Opcode::Mark.is_dangerous());
    }

    #[test]
    fn test_from_byte_round_trip() {
        assert_eq!(Opcode::from_byte(b'c'), Opcode::Global);
        assert_eq!(Opcode::from_byte(b'R'), Opcode::Reduce);
        assert_eq!(Opcode::from_byte(0x93), Opcode::StackGlobal);
        assert_eq!(Opcode::from_byte(0xFF), Opcode::Unknown);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
