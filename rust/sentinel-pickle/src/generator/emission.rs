// generator/emission.rs — Opcode emission with argument encoding
//
// Writes pickle opcodes and their arguments to the output buffer,
// then updates the simulated stack.

use std::sync::LazyLock;

use super::Generator;
use super::source::{EntropySource, GenerationSource};
use super::state::GenStackValue;
use crate::opcode::Opcode;

// Module/name pools loaded from stdlib_complete.txt at compile time.
// Each line is "module.attribute" — we split into separate vecs.
static STDLIB_RAW: &str = include_str!("../../data/stdlib_complete.txt");

struct StdlibPools {
    modules: Vec<String>,
    names: Vec<String>,
}

static POOLS: LazyLock<StdlibPools> = LazyLock::new(|| {
    let mut modules = Vec::new();
    let mut names = Vec::new();
    for line in STDLIB_RAW.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        // Split on last '.' to get module and name
        if let Some(dot) = line.rfind('.') {
            let m = &line[..dot];
            let n = &line[dot + 1..];
            if !m.is_empty() && !n.is_empty() {
                modules.push(m.to_string());
                names.push(n.to_string());
            }
        }
    }
    // Ensure we always have fallback entries
    if modules.is_empty() {
        modules.push("__main__".to_string());
        names.push("__new__".to_string());
    }
    StdlibPools { modules, names }
});

impl Generator {
    /// Emit a single opcode with random arguments, update stack.
    pub(super) fn emit_and_process(
        &mut self,
        op: Opcode,
        source: &mut GenerationSource,
    ) {
        match op {
            // ── Value producers ──────────────────────────────────────
            Opcode::NoneOp => {
                self.output.push(b'N');
                self.push(GenStackValue::None);
            }
            Opcode::NewTrue => {
                self.output.push(0x88);
                self.push(GenStackValue::Bool(true));
            }
            Opcode::NewFalse => {
                self.output.push(0x89);
                self.push(GenStackValue::Bool(false));
            }
            Opcode::BinInt => {
                let v = self.mutate_int(source.gen_i32());
                let pre = self.output.len();
                self.output.push(b'J');
                self.output.extend_from_slice(&v.to_le_bytes());
                self.push(GenStackValue::Int(v as i64));
                self.post_process_emission(pre);
            }
            Opcode::BinInt1 => {
                let v = self.mutate_int(source.gen_u8() as i32) as u8;
                let pre = self.output.len();
                self.output.push(b'K');
                self.output.push(v);
                self.push(GenStackValue::Int(v as i64));
                self.post_process_emission(pre);
            }
            Opcode::BinInt2 => {
                let v = self.mutate_int(source.gen_u16() as i32) as u16;
                let pre = self.output.len();
                self.output.push(b'M');
                self.output.extend_from_slice(&v.to_le_bytes());
                self.push(GenStackValue::Int(v as i64));
                self.post_process_emission(pre);
            }
            Opcode::Int => {
                let v = self.mutate_int(source.gen_i32());
                let pre = self.output.len();
                self.output.push(b'I');
                self.output.extend_from_slice(v.to_string().as_bytes());
                self.output.push(b'\n');
                self.push(GenStackValue::Int(v as i64));
                self.post_process_emission(pre);
            }
            Opcode::Long | Opcode::Long1 => {
                let v = self.mutate_long(source.gen_i64());
                let pre = self.output.len();
                self.output.push(0x8a);
                let bytes = v.to_le_bytes();
                let len = if v == 0 { 0 } else { 8 };
                self.output.push(len as u8);
                if len > 0 { self.output.extend_from_slice(&bytes[..len]); }
                self.push(GenStackValue::Int(v));
                self.post_process_emission(pre);
            }
            Opcode::Long4 => {
                let v = self.mutate_long(source.gen_i64());
                let pre = self.output.len();
                self.output.push(0x8b);
                let bytes = v.to_le_bytes();
                let len = if v == 0 { 0u32 } else { 8 };
                self.output.extend_from_slice(&len.to_le_bytes());
                if len > 0 { self.output.extend_from_slice(&bytes[..len as usize]); }
                self.push(GenStackValue::Int(v));
                self.post_process_emission(pre);
            }
            Opcode::BinFloat => {
                let v = self.mutate_float(source.gen_f64());
                let pre = self.output.len();
                self.output.push(b'G');
                self.output.extend_from_slice(&v.to_be_bytes());
                self.push(GenStackValue::Float);
                self.post_process_emission(pre);
            }
            Opcode::Float => {
                let v = self.mutate_float(source.gen_f64());
                let pre = self.output.len();
                self.output.push(b'F');
                self.output.extend_from_slice(format!("{v}").as_bytes());
                self.output.push(b'\n');
                self.push(GenStackValue::Float);
                self.post_process_emission(pre);
            }
            Opcode::ShortBinUnicode => {
                let len = source.gen_range(0, 33).min(255);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let bytes = s.as_bytes();
                let pre = self.output.len();
                self.output.push(0x8c);
                self.output.push(bytes.len().min(255) as u8);
                self.output.extend_from_slice(&bytes[..bytes.len().min(255)]);
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::BinUnicode => {
                let len = source.gen_range(0, 65);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let bytes = s.as_bytes();
                let pre = self.output.len();
                self.output.push(b'X');
                self.output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                self.output.extend_from_slice(bytes);
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::BinUnicode8 => {
                let len = source.gen_range(0, 65);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let bytes = s.as_bytes();
                let pre = self.output.len();
                self.output.push(0x8d);
                self.output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                self.output.extend_from_slice(bytes);
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::String => {
                let len = source.gen_range(0, 33);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let pre = self.output.len();
                self.output.push(b'S');
                self.output.push(b'\'');
                self.output.extend_from_slice(s.as_bytes());
                self.output.push(b'\'');
                self.output.push(b'\n');
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::BinString => {
                let len = source.gen_range(0, 65);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let bytes = s.as_bytes();
                let pre = self.output.len();
                self.output.push(b'T');
                self.output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                self.output.extend_from_slice(bytes);
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::ShortBinString => {
                let len = source.gen_range(0, 33).min(255);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let bytes = s.as_bytes();
                let pre = self.output.len();
                self.output.push(b'U');
                self.output.push(bytes.len().min(255) as u8);
                self.output.extend_from_slice(&bytes[..bytes.len().min(255)]);
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::Unicode => {
                let len = source.gen_range(0, 33);
                let raw: String = (0..len).map(|_| source.gen_ascii_char()).collect();
                let s = self.mutate_string(raw);
                let pre = self.output.len();
                self.output.push(b'V');
                self.output.extend_from_slice(s.as_bytes());
                self.output.push(b'\n');
                self.push(GenStackValue::String(s));
                self.post_process_emission(pre);
            }
            Opcode::ShortBinBytes => {
                let len = source.gen_range(0, 65).min(255);
                let raw = source.gen_bytes(len);
                let data = self.mutate_bytes(raw);
                let pre = self.output.len();
                self.output.push(b'C');
                self.output.push(data.len().min(255) as u8);
                self.output.extend_from_slice(&data[..data.len().min(255)]);
                self.push(GenStackValue::Bytes);
                self.post_process_emission(pre);
            }
            Opcode::BinBytes => {
                let len = source.gen_range(0, 65);
                let raw = source.gen_bytes(len);
                let data = self.mutate_bytes(raw);
                let pre = self.output.len();
                self.output.push(b'B');
                self.output.extend_from_slice(&(data.len() as u32).to_le_bytes());
                self.output.extend_from_slice(&data);
                self.push(GenStackValue::Bytes);
                self.post_process_emission(pre);
            }
            Opcode::BinBytes8 => {
                let len = source.gen_range(0, 65);
                let raw = source.gen_bytes(len);
                let data = self.mutate_bytes(raw);
                let pre = self.output.len();
                self.output.push(0x8e);
                self.output.extend_from_slice(&(data.len() as u64).to_le_bytes());
                self.output.extend_from_slice(&data);
                self.push(GenStackValue::Bytes);
                self.post_process_emission(pre);
            }
            Opcode::Bytearray8 => {
                let len = source.gen_range(0, 65);
                let raw = source.gen_bytes(len);
                let data = self.mutate_bytes(raw);
                let pre = self.output.len();
                self.output.push(0x96);
                self.output.extend_from_slice(&(data.len() as u64).to_le_bytes());
                self.output.extend_from_slice(&data);
                self.push(GenStackValue::Bytes);
                self.post_process_emission(pre);
            }

            // ── Containers ──────────────────────────────────────────
            Opcode::EmptyList => {
                self.output.push(b']');
                self.push(GenStackValue::List);
            }
            Opcode::EmptyDict => {
                self.output.push(b'}');
                self.push(GenStackValue::Dict);
            }
            Opcode::EmptyTuple => {
                self.output.push(b')');
                self.push(GenStackValue::Tuple);
            }
            Opcode::EmptySet => {
                self.output.push(0x8f);
                self.push(GenStackValue::Set);
            }

            // ── Stack operations ────────────────────────────────────
            Opcode::Mark => {
                self.output.push(b'(');
                self.push(GenStackValue::Mark);
            }
            Opcode::Pop => {
                self.output.push(b'0');
                self.pop();
            }
            Opcode::PopMark => {
                self.output.push(b'1');
                self.pop_to_mark();
            }
            Opcode::Dup => {
                self.output.push(b'2');
                if let Some(val) = self.peek().cloned() {
                    self.push(val);
                }
            }

            // ── Tuple builders ──────────────────────────────────────
            Opcode::Tuple1 => {
                self.output.push(0x85);
                self.pop();
                self.push(GenStackValue::Tuple);
            }
            Opcode::Tuple2 => {
                self.output.push(0x86);
                self.pop(); self.pop();
                self.push(GenStackValue::Tuple);
            }
            Opcode::Tuple3 => {
                self.output.push(0x87);
                self.pop(); self.pop(); self.pop();
                self.push(GenStackValue::Tuple);
            }
            Opcode::Tuple => {
                self.output.push(b't');
                self.pop_to_mark();
                self.push(GenStackValue::Tuple);
            }
            Opcode::List => {
                self.output.push(b'l');
                self.pop_to_mark();
                self.push(GenStackValue::List);
            }
            Opcode::Dict => {
                self.output.push(b'd');
                self.pop_to_mark();
                self.push(GenStackValue::Dict);
            }
            Opcode::Frozenset => {
                self.output.push(0x91);
                self.pop_to_mark();
                self.push(GenStackValue::FrozenSet);
            }

            // ── List/Dict/Set operations ────────────────────────────
            Opcode::Append => {
                self.output.push(b'a');
                self.pop(); // item
            }
            Opcode::Appends => {
                self.output.push(b'e');
                self.pop_to_mark();
            }
            Opcode::Setitem => {
                self.output.push(b's');
                self.pop(); self.pop(); // value, key
            }
            Opcode::Setitems => {
                self.output.push(b'u');
                self.pop_to_mark();
            }
            Opcode::Additems => {
                self.output.push(0x90);
                self.pop_to_mark();
            }

            // ── Memo operations ─────────────────────────────────────
            Opcode::BinPut => {
                let raw = self.next_memo_idx();
                let idx = self.mutate_memo_index(raw as usize) as u32;
                self.output.push(b'q');
                self.output.push((idx & 0xFF) as u8);
                self.memo_put();
            }
            Opcode::LongBinPut => {
                let raw = self.next_memo_idx();
                let idx = self.mutate_memo_index(raw as usize) as u32;
                self.output.push(b'r');
                self.output.extend_from_slice(&idx.to_le_bytes());
                self.memo_put();
            }
            Opcode::Put => {
                let raw = self.next_memo_idx();
                let idx = self.mutate_memo_index(raw as usize) as u32;
                self.output.push(b'p');
                self.output.extend_from_slice(idx.to_string().as_bytes());
                self.output.push(b'\n');
                self.memo_put();
            }
            Opcode::Memoize => {
                self.output.push(0x94);
                self.memo_put();
            }
            Opcode::BinGet => {
                if self.next_memo > 0 {
                    let raw = source.gen_range(0, self.next_memo as usize);
                    let idx = self.mutate_memo_index(raw);
                    self.output.push(b'h');
                    self.output.push((idx & 0xFF) as u8);
                    self.push(GenStackValue::Unknown);
                }
            }
            Opcode::LongBinGet => {
                if self.next_memo > 0 {
                    let raw = source.gen_range(0, self.next_memo as usize);
                    let idx = self.mutate_memo_index(raw) as u32;
                    self.output.push(b'j');
                    self.output.extend_from_slice(&idx.to_le_bytes());
                    self.push(GenStackValue::Unknown);
                }
            }
            Opcode::Get => {
                if self.next_memo > 0 {
                    let raw = source.gen_range(0, self.next_memo as usize);
                    let idx = self.mutate_memo_index(raw);
                    self.output.push(b'g');
                    self.output.extend_from_slice(idx.to_string().as_bytes());
                    self.output.push(b'\n');
                    self.push(GenStackValue::Unknown);
                }
            }

            // ── Object operations ───────────────────────────────────
            Opcode::Global => {
                let pools = &*POOLS;
                let m = &pools.modules[source.choose_index(pools.modules.len())];
                let n = &pools.names[source.choose_index(pools.names.len())];
                let ms = self.mutate_string(m.clone());
                let ns = self.mutate_string(n.clone());
                self.output.push(b'c');
                self.output.extend_from_slice(ms.as_bytes());
                self.output.push(b'\n');
                self.output.extend_from_slice(ns.as_bytes());
                self.output.push(b'\n');
                self.push(GenStackValue::Global {
                    module: ms,
                    name: ns,
                });
            }
            Opcode::Inst => {
                // INST: like GLOBAL but also pops args from the mark
                let pools = &*POOLS;
                let m = &pools.modules[source.choose_index(pools.modules.len())];
                let n = &pools.names[source.choose_index(pools.names.len())];
                let ms = self.mutate_string(m.clone());
                let ns = self.mutate_string(n.clone());
                self.output.push(b'i');
                self.output.extend_from_slice(ms.as_bytes());
                self.output.push(b'\n');
                self.output.extend_from_slice(ns.as_bytes());
                self.output.push(b'\n');
                self.pop_to_mark();
                self.push(GenStackValue::Reduced {
                    callable: Box::new(GenStackValue::Global { module: ms, name: ns }),
                });
            }
            Opcode::Persid => {
                let id_str = source.gen_range(0, 9999).to_string();
                self.output.push(b'P');
                self.output.extend_from_slice(id_str.as_bytes());
                self.output.push(b'\n');
                self.push(GenStackValue::Unknown);
            }
            Opcode::BinPersid => {
                self.output.push(b'Q');
                self.pop(); // pid from TOS
                self.push(GenStackValue::Unknown);
            }
            Opcode::StackGlobal => {
                self.output.push(0x93);
                let name = self.pop();
                let module = self.pop();
                let (m, n) = match (&module, &name) {
                    (Some(GenStackValue::String(m)), Some(GenStackValue::String(n))) =>
                        (m.clone(), n.clone()),
                    _ => ("__main__".to_string(), "__new__".to_string()),
                };
                self.push(GenStackValue::Global { module: m, name: n });
            }
            Opcode::Reduce => {
                self.output.push(b'R');
                self.pop(); // args
                let callable = self.pop();
                self.push(GenStackValue::Reduced {
                    callable: Box::new(callable.unwrap_or(GenStackValue::Unknown)),
                });
            }
            Opcode::Newobj => {
                self.output.push(0x81);
                self.pop(); // args
                let cls = self.pop();
                self.push(GenStackValue::Reduced {
                    callable: Box::new(cls.unwrap_or(GenStackValue::Unknown)),
                });
            }
            Opcode::NewobjEx => {
                self.output.push(0x92);
                self.pop(); // kwargs
                self.pop(); // args
                let cls = self.pop();
                self.push(GenStackValue::Reduced {
                    callable: Box::new(cls.unwrap_or(GenStackValue::Unknown)),
                });
            }
            Opcode::Build => {
                self.output.push(b'b');
                self.pop(); // state
                // TOS stays (the built object)
            }

            // ── Catch-all ───────────────────────────────────────────
            _ => {}
        }

        self.opcode_count += 1;
    }

    /// Pop everything down to and including the topmost mark.
    pub(super) fn pop_to_mark(&mut self) {
        while let Some(val) = self.stack.pop() {
            if matches!(val, GenStackValue::Mark) {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdlib_pools_loaded() {
        let pools = &*POOLS;
        // stdlib_complete.txt has 130+ entries
        assert!(pools.modules.len() >= 100,
            "expected 100+ modules, got {}", pools.modules.len());
        assert_eq!(pools.modules.len(), pools.names.len());
    }

    #[test]
    fn test_stdlib_pools_contain_dangerous() {
        let pools = &*POOLS;
        assert!(pools.modules.contains(&"os".to_string()));
        assert!(pools.names.contains(&"system".to_string()));
        assert!(pools.modules.contains(&"subprocess".to_string()));
        assert!(pools.names.contains(&"Popen".to_string()));
    }

    #[test]
    fn test_stdlib_pools_contain_safe() {
        let pools = &*POOLS;
        assert!(pools.modules.contains(&"collections".to_string()));
        assert!(pools.names.contains(&"OrderedDict".to_string()));
    }

    #[test]
    fn test_stdlib_pools_contain_ml() {
        let pools = &*POOLS;
        assert!(pools.modules.iter().any(|m| m.starts_with("torch")));
        assert!(pools.modules.iter().any(|m| m.starts_with("numpy")));
    }

    #[test]
    fn test_generate_with_new_opcodes() {
        // Generate with all protocols to exercise new opcodes (Long4, Inst, etc.)
        for proto in 0..=5u8 {
            let mut gen = Generator::new(proto)
                .with_opcode_range(16, 128);
            let pickle = gen.generate(proto as u64 * 1000 + 42).unwrap();
            assert!(!pickle.is_empty());
            assert_eq!(*pickle.last().unwrap(), b'.');
        }
    }

    #[test]
    fn test_generate_exercises_dangerous_ops() {
        // With weighted selection, dangerous ops should appear more often.
        // Generate many pickles and check for GLOBAL opcode (0x63 = b'c')
        let mut found_global = false;
        for seed in 0..20u64 {
            let mut gen = Generator::new(4).with_opcode_range(8, 64);
            let pickle = gen.generate(seed).unwrap();
            if pickle.windows(1).any(|w| w[0] == b'c') {
                found_global = true;
                break;
            }
        }
        assert!(found_global, "weighted selection should produce GLOBAL in 20 tries");
    }
}
