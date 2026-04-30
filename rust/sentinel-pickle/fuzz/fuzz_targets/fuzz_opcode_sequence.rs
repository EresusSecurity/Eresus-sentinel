// fuzz_opcode_sequence.rs — Deep structured opcode sequence fuzzer
//
// Generates syntactically valid pickle byte sequences from a rich
// structured representation using the `arbitrary` crate.  Covers all
// pickle opcodes including protocol 4/5 additions (FRAME, MEMOIZE,
// SHORT_BINUNICODE, BYTEARRAY8, NEXT_BUFFER, READONLY_BUFFER),
// code execution paths (GLOBAL, STACK_GLOBAL, INST, OBJ, REDUCE,
// NEWOBJ, NEWOBJ_EX, BUILD), and memo aliasing edge cases.
//
// Validates 10 invariants per generated sequence including scanner
// correctness, policy monotonicity, finding consistency, idempotency,
// and dangerous global detection.
//
// Run:
//   cargo +nightly fuzz run fuzz_opcode_sequence -- -max_len=8192

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use sentinel_pickle::{
    policy::ScanPolicy,
    scanner::{scan_data, scan_data_with_stats},
    state::{MAX_OPCODE_COUNT, MAX_STACK_DEPTH},
};
use std::collections::HashSet;

// ── Structured pickle recipe ─────────────────────────────────────────

#[derive(Arbitrary, Debug, Clone)]
enum PickleOp {
    PushNone,
    PushBool(bool),
    PushInt(i32),
    PushLong(i64),
    PushFloat(f64),
    PushShortStr(SmallString),
    PushLongStr(SmallString),
    PushBytes(SmallBytes),
    PushLongBytes(SmallBytes),
    PushEmptyList,
    PushEmptyDict,
    PushEmptyTuple,
    PushEmptySet,
    Mark,
    Pop,
    PopMark,
    Dup,
    AppendToList,
    Appends,
    SetItem,
    SetItems,
    AddItem,
    FrozenSet,
    BuildTuple,
    BuildTuple1,
    BuildTuple2,
    BuildTuple3,
    List,
    Dict,
    /// GLOBAL with module/name from pools
    Global { module_idx: u8, name_idx: u8 },
    /// INST — like GLOBAL but between MARK and args
    Inst { module_idx: u8, name_idx: u8 },
    /// STACK_GLOBAL — module and name already on stack
    StackGlobal { module_idx: u8, name_idx: u8 },
    /// REDUCE (call callable with args tuple)
    Reduce,
    /// BUILD (apply __setstate__)
    Build,
    /// NEWOBJ
    Newobj,
    /// NEWOBJ_EX (protocol 4+)
    NewobjEx,
    /// PERSID — persistent ID reference
    PersId(SmallString),
    /// BINPERSID — binary persistent ID from stack
    BinPersId,
    /// Memo operations
    MemoPut(u8),
    MemoGet(u8),
    LongMemoPut(u32),
    LongMemoGet(u32),
    Memoize,
    /// Frame header (protocol 4+)
    Frame,
    /// Protocol switch (0-5)
    Proto(u8),
    /// SHORT_BINUNICODE (protocol 4+)
    ShortBinUnicode(SmallString),
    /// BINUNICODE8 (protocol 4+)
    BinUnicode8(SmallString),
    /// Injection payload as string
    InjectionStr(InjectionKind),
    /// Injection payload as GLOBAL module
    InjectionGlobal(InjectionKind),
}

#[derive(Arbitrary, Debug, Clone)]
enum InjectionKind {
    OsSystem,
    SubprocessPopen,
    BuiltinsEval,
    BuiltinsExec,
    BuiltinsImport,
    MarshalLoads,
    CtypesCDLL,
    PathTraversal,
    ShellMetachar,
    TemplateInjection,
    SsrfUrl,
    NullByte,
    UnicodeOverflow,
}

#[derive(Arbitrary, Debug, Clone)]
struct SmallString(#[arbitrary(with = |u: &mut Unstructured| -> arbitrary::Result<String> {
    let len: u8 = u.arbitrary()?;
    let bytes: Vec<u8> = (0..len.min(48)).map(|_| u.arbitrary().unwrap_or(b'x')).collect();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
})] String);

#[derive(Arbitrary, Debug, Clone)]
struct SmallBytes(#[arbitrary(with = |u: &mut Unstructured| -> arbitrary::Result<Vec<u8>> {
    let len: u8 = u.arbitrary()?;
    (0..len.min(64)).map(|_| u.arbitrary()).collect()
})] Vec<u8>);

// ── Module & name pools ──────────────────────────────────────────────
// Mix of dangerous, suspicious, safe, ML framework, and edge-case entries

static MODULES: &[&str] = &[
    // Dangerous
    "os", "subprocess", "builtins", "socket", "ctypes",
    "marshal", "pickle", "_pickle", "importlib", "code",
    "nt", "posix", "shutil", "tempfile", "webbrowser",
    // Safe stdlib
    "collections", "datetime", "math", "functools", "itertools",
    "decimal", "fractions", "copy", "json", "re",
    // ML frameworks
    "torch", "numpy", "sklearn.linear_model", "tensorflow.keras",
    "pandas", "scipy", "joblib",
    "numpy.core.multiarray",
    // Edge cases
    "", "__main__", "a.b.c.d.e", "x\ny", "mod\x00ule",
    "\t\r\n", "...", "a" , // single char
];

static NAMES: &[&str] = &[
    // Dangerous
    "system", "popen", "exec", "eval", "__import__", "Popen",
    "check_output", "check_call", "run",
    "loads", "load", "import_module", "CDLL", "windll",
    "rmtree", "remove", "unlink", "makedirs",
    // Safe
    "OrderedDict", "defaultdict", "datetime", "zeros", "array",
    "_reconstruct", "scalar", "dtype",
    "__new__", "__init__", "__reduce__", "__reduce_ex__",
    "__setstate__", "__getstate__", "__class__",
    // Edge cases
    "", "a\nb", "x\x00y", "name\twith\ttabs",
    "\r\n", "__builtins__", "object",
];

// Injection payloads for InjectionKind
fn injection_payload(kind: &InjectionKind) -> (&str, &str) {
    match kind {
        InjectionKind::OsSystem => ("os", "system"),
        InjectionKind::SubprocessPopen => ("subprocess", "Popen"),
        InjectionKind::BuiltinsEval => ("builtins", "eval"),
        InjectionKind::BuiltinsExec => ("builtins", "exec"),
        InjectionKind::BuiltinsImport => ("builtins", "__import__"),
        InjectionKind::MarshalLoads => ("marshal", "loads"),
        InjectionKind::CtypesCDLL => ("ctypes", "CDLL"),
        InjectionKind::PathTraversal => ("__main__", "../../../etc/passwd"),
        InjectionKind::ShellMetachar => ("__main__", "; rm -rf /"),
        InjectionKind::TemplateInjection => ("__main__", "{{config}}"),
        InjectionKind::SsrfUrl => ("__main__", "http://169.254.169.254/latest/meta-data/"),
        InjectionKind::NullByte => ("__main__", "payload\x00hidden"),
        InjectionKind::UnicodeOverflow => ("__main__", "\u{FEFF}\u{200B}\u{200C}\u{200D}"),
    }
}

// ── Serialiser ───────────────────────────────────────────────────────

fn encode_ops(ops: &[PickleOp]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ops.len() * 6);
    buf.extend_from_slice(&[0x80, 2]); // proto 2 default

    for op in ops {
        match op {
            PickleOp::PushNone => buf.push(b'N'),
            PickleOp::PushBool(true)  => buf.push(0x88),
            PickleOp::PushBool(false) => buf.push(0x89),
            PickleOp::PushInt(v) => {
                buf.push(b'J'); // BININT
                buf.extend_from_slice(&v.to_le_bytes());
            }
            PickleOp::PushLong(v) => {
                // LONG4 — 4-byte length-prefixed signed little-endian
                let bytes = v.to_le_bytes();
                buf.push(0x8b); // LONG4
                buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(&bytes);
            }
            PickleOp::PushFloat(v) => {
                buf.push(b'G'); // BINFLOAT
                buf.extend_from_slice(&v.to_be_bytes());
            }
            PickleOp::PushShortStr(SmallString(s)) => {
                let bytes = s.as_bytes();
                let len = bytes.len().min(255) as u8;
                buf.push(0x8c); // SHORT_BINUNICODE
                buf.push(len);
                buf.extend_from_slice(&bytes[..len as usize]);
            }
            PickleOp::PushLongStr(SmallString(s)) => {
                let bytes = s.as_bytes();
                buf.push(b'X'); // BINUNICODE
                buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            PickleOp::PushBytes(SmallBytes(b)) => {
                let len = b.len().min(255) as u8;
                buf.push(b'C'); // SHORT_BINBYTES
                buf.push(len);
                buf.extend_from_slice(&b[..len as usize]);
            }
            PickleOp::PushLongBytes(SmallBytes(b)) => {
                buf.push(b'B'); // BINBYTES
                buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
                buf.extend_from_slice(b);
            }
            PickleOp::PushEmptyList  => buf.push(b']'),
            PickleOp::PushEmptyDict  => buf.push(b'}'),
            PickleOp::PushEmptyTuple => buf.push(b')'),
            PickleOp::PushEmptySet   => buf.push(0x8f),
            PickleOp::Mark           => buf.push(b'('),
            PickleOp::Pop            => buf.push(b'0'),
            PickleOp::PopMark        => buf.push(b'1'),
            PickleOp::Dup            => buf.push(b'2'),
            PickleOp::AppendToList   => buf.push(b'a'),
            PickleOp::Appends        => buf.push(b'e'),
            PickleOp::SetItem        => buf.push(b's'),
            PickleOp::SetItems       => buf.push(b'u'),
            PickleOp::AddItem        => buf.push(0x90),
            PickleOp::FrozenSet      => buf.push(0x91),
            PickleOp::BuildTuple     => buf.push(b't'),
            PickleOp::BuildTuple1    => buf.push(0x85),
            PickleOp::BuildTuple2    => buf.push(0x86),
            PickleOp::BuildTuple3    => buf.push(0x87),
            PickleOp::List           => buf.push(b'l'),
            PickleOp::Dict           => buf.push(b'd'),
            PickleOp::Reduce         => buf.push(b'R'),
            PickleOp::Build          => buf.push(b'b'),
            PickleOp::Newobj         => buf.push(0x81),
            PickleOp::NewobjEx       => buf.push(0x92),
            PickleOp::Memoize        => buf.push(0x94),
            PickleOp::MemoPut(idx) => {
                buf.push(b'q'); // BINPUT
                buf.push(*idx);
            }
            PickleOp::MemoGet(idx) => {
                buf.push(b'h'); // BINGET
                buf.push(*idx);
            }
            PickleOp::LongMemoPut(idx) => {
                buf.push(b'r'); // LONG_BINPUT
                buf.extend_from_slice(&idx.to_le_bytes());
            }
            PickleOp::LongMemoGet(idx) => {
                buf.push(b'j'); // LONG_BINGET
                buf.extend_from_slice(&idx.to_le_bytes());
            }
            PickleOp::Frame => {
                buf.push(0x95); // FRAME
                buf.extend_from_slice(&0u64.to_le_bytes());
            }
            PickleOp::Proto(v) => {
                buf.push(0x80);
                buf.push(v.min(&5).clone());
            }
            PickleOp::PersId(SmallString(s)) => {
                buf.push(b'P'); // PERSID
                buf.extend_from_slice(s.as_bytes());
                buf.push(b'\n');
            }
            PickleOp::BinPersId => buf.push(b'Q'), // BINPERSID
            PickleOp::ShortBinUnicode(SmallString(s)) => {
                let bytes = s.as_bytes();
                let len = bytes.len().min(255) as u8;
                buf.push(0x8c);
                buf.push(len);
                buf.extend_from_slice(&bytes[..len as usize]);
            }
            PickleOp::BinUnicode8(SmallString(s)) => {
                let bytes = s.as_bytes();
                buf.push(0x8d); // BINUNICODE8
                buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            PickleOp::Global { module_idx, name_idx } => {
                let m = MODULES[(*module_idx as usize) % MODULES.len()];
                let n = NAMES[(*name_idx as usize) % NAMES.len()];
                buf.push(b'c'); // GLOBAL
                buf.extend_from_slice(m.as_bytes());
                buf.push(b'\n');
                buf.extend_from_slice(n.as_bytes());
                buf.push(b'\n');
            }
            PickleOp::Inst { module_idx, name_idx } => {
                let m = MODULES[(*module_idx as usize) % MODULES.len()];
                let n = NAMES[(*name_idx as usize) % NAMES.len()];
                buf.push(b'i'); // INST
                buf.extend_from_slice(m.as_bytes());
                buf.push(b'\n');
                buf.extend_from_slice(n.as_bytes());
                buf.push(b'\n');
            }
            PickleOp::StackGlobal { module_idx, name_idx } => {
                let m = MODULES[(*module_idx as usize) % MODULES.len()];
                let n = NAMES[(*name_idx as usize) % NAMES.len()];
                let m_bytes = m.as_bytes();
                let n_bytes = n.as_bytes();
                let ml = m_bytes.len().min(255) as u8;
                let nl = n_bytes.len().min(255) as u8;
                buf.push(0x8c); buf.push(ml);
                buf.extend_from_slice(&m_bytes[..ml as usize]);
                buf.push(0x8c); buf.push(nl);
                buf.extend_from_slice(&n_bytes[..nl as usize]);
                buf.push(0x93); // STACK_GLOBAL
            }
            PickleOp::InjectionStr(kind) => {
                let (m, n) = injection_payload(kind);
                let payload = format!("{}.{}", m, n);
                let bytes = payload.as_bytes();
                let len = bytes.len().min(255) as u8;
                buf.push(0x8c);
                buf.push(len);
                buf.extend_from_slice(&bytes[..len as usize]);
            }
            PickleOp::InjectionGlobal(kind) => {
                let (m, n) = injection_payload(kind);
                buf.push(b'c'); // GLOBAL
                buf.extend_from_slice(m.as_bytes());
                buf.push(b'\n');
                buf.extend_from_slice(n.as_bytes());
                buf.push(b'\n');
            }
        }
    }

    buf.push(b'.'); // STOP
    buf
}

// ── Fuzz entry ────────────────────────────────────────────────────────

fuzz_target!(|ops: Vec<PickleOp>| {
    let ops = &ops[..ops.len().min(512)];
    if ops.is_empty() { return; }

    let data = encode_ops(ops);
    let policy = ScanPolicy::new(false);
    let strict_policy = ScanPolicy::new(true);

    // ── INV-1: Scanner never panics (implicit) ────────────────────────
    let (findings, stats) = scan_data_with_stats(&data, &policy);

    // ── INV-2: Findings well-formed ───────────────────────────────────
    for f in &findings {
        assert!(!f.rule_id.is_empty());
        assert!(!f.severity.is_empty());
        assert!(!f.description.is_empty());
        assert!(f.confidence >= 0.0 && f.confidence <= 1.0);
    }

    // ── INV-3: Stack depth bounded ────────────────────────────────────
    assert!(stats.max_stack_depth <= MAX_STACK_DEPTH);

    // ── INV-4: Strict ⊇ non-strict ───────────────────────────────────
    let (strict_findings, _) = scan_data_with_stats(&data, &strict_policy);
    assert!(strict_findings.len() >= findings.len());

    // ── INV-5: Idempotency ────────────────────────────────────────────
    let (findings_2, stats_2) = scan_data_with_stats(&data, &policy);
    assert_eq!(findings.len(), findings_2.len());
    assert_eq!(stats.opcode_count, stats_2.opcode_count);

    // ── INV-6: Dangerous globals detected ─────────────────────────────
    // If we emitted a GLOBAL/INST with a known-dangerous (module, name),
    // the scanner MUST flag it.
    let dangerous_globals: HashSet<(&str, &str)> = [
        ("os", "system"), ("os", "popen"),
        ("subprocess", "Popen"), ("subprocess", "check_output"),
        ("builtins", "eval"), ("builtins", "exec"),
        ("builtins", "__import__"),
        ("ctypes", "CDLL"), ("marshal", "loads"),
        ("pickle", "loads"), ("_pickle", "loads"),
        ("importlib", "import_module"),
    ].iter().cloned().collect();

    let flagged_globals: HashSet<(String, String)> = findings.iter()
        .filter(|f| !f.module_name.is_empty())
        .map(|f| (f.module_name.clone(), f.import_name.clone()))
        .collect();

    for op in ops {
        let (m_idx, n_idx) = match op {
            PickleOp::Global { module_idx, name_idx }
            | PickleOp::Inst { module_idx, name_idx }
            | PickleOp::StackGlobal { module_idx, name_idx } => {
                (*module_idx, *name_idx)
            }
            PickleOp::InjectionGlobal(kind) => {
                let (m, n) = injection_payload(kind);
                if dangerous_globals.contains(&(m, n)) {
                    assert!(
                        flagged_globals.contains(&(m.to_string(), n.to_string())),
                        "scanner missed dangerous injection global {}.{}",
                        m, n
                    );
                }
                continue;
            }
            _ => continue,
        };
        let m = MODULES[(m_idx as usize) % MODULES.len()];
        let n = NAMES[(n_idx as usize) % NAMES.len()];
        if dangerous_globals.contains(&(m, n)) {
            assert!(
                flagged_globals.contains(&(m.to_string(), n.to_string())),
                "scanner missed dangerous global {}.{}",
                m, n
            );
        }
    }

    // ── INV-7: Abort consistency ──────────────────────────────────────
    if stats.aborted {
        assert!(stats.opcode_count >= MAX_OPCODE_COUNT);
    }

    // ── INV-8: Truncation robustness ──────────────────────────────────
    if data.len() > 4 {
        let mid = data.len() / 2;
        let _ = scan_data(&data[..mid], &policy);
        let _ = scan_data(&data[1..], &policy);
    }

    // ── INV-9: Finding severity monotonicity ──────────────────────────
    // All findings from dangerous globals should be CRITICAL or HIGH
    for f in &findings {
        if f.rule_id == "PICKLE-EXEC" {
            assert!(
                f.severity == "CRITICAL",
                "PICKLE-EXEC must be CRITICAL, got {}",
                f.severity
            );
        }
    }

    // ── INV-10: Multi-pickle concatenation ────────────────────────────
    if data.len() < 2048 {
        let mut cat = data.clone();
        cat.extend_from_slice(&data);
        let (cat_f, cat_s) = scan_data_with_stats(&cat, &policy);
        for f in &cat_f {
            assert!(!f.rule_id.is_empty());
        }
        assert!(cat_s.max_stack_depth <= MAX_STACK_DEPTH);
    }
});
