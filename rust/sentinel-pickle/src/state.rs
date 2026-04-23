// state.rs — Pickle Virtual Machine state tracking
// Tracks stack, memo, mark stack, and global references through
// the opcode stream so the policy engine can evaluate what would
// happen on unpickle without actually executing anything.

use crate::opcode::Opcode;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StackValue {
    None,
    Bool(bool),
    Int(i64),
    Float(String),
    Bytes(Vec<u8>),
    String(String),
    List,
    Dict,
    Tuple,
    Set,
    FrozenSet,
    Mark,
    Global { module: String, name: String },
    Reduced { callable: Box<StackValue> },
    Built { base: Box<StackValue> },
    Unknown,
}

impl StackValue {
    pub fn as_global(&self) -> Option<(&str, &str)> {
        match self {
            StackValue::Global { module, name } => Some((module, name)),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            StackValue::String(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalRef {
    pub module: String,
    pub name: String,
    pub offset: usize,
    pub opcode: Opcode,
}

#[derive(Debug, Clone)]
pub struct ReduceCall {
    pub callable: GlobalRef,
    pub offset: usize,
}

#[derive(Debug)]
pub struct PVMState {
    pub stack: Vec<StackValue>,
    pub memo: HashMap<u32, StackValue>,
    pub mark_stack: Vec<usize>,
    pub global_refs: Vec<GlobalRef>,
    pub reduce_calls: Vec<ReduceCall>,
    pub protocol: u8,
    pub offset: usize,
    pub opcode_count: usize,
    pub errors: Vec<String>,
}

impl PVMState {
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(256),
            memo: HashMap::new(),
            mark_stack: Vec::new(),
            global_refs: Vec::new(),
            reduce_calls: Vec::new(),
            protocol: 0,
            offset: 0,
            opcode_count: 0,
            errors: Vec::new(),
        }
    }

    pub fn push(&mut self, val: StackValue) {
        self.stack.push(val);
    }

    pub fn pop(&mut self) -> StackValue {
        self.stack.pop().unwrap_or(StackValue::Unknown)
    }

    pub fn peek(&self) -> &StackValue {
        self.stack.last().unwrap_or(&StackValue::Unknown)
    }

    pub fn pop_mark(&mut self) -> Vec<StackValue> {
        if let Some(mark_pos) = self.mark_stack.pop() {
            if mark_pos <= self.stack.len() {
                return self.stack.split_off(mark_pos);
            }
        }
        Vec::new()
    }

    pub fn memo_get(&self, idx: u32) -> StackValue {
        self.memo.get(&idx).cloned().unwrap_or(StackValue::Unknown)
    }

    pub fn memo_put(&mut self, idx: u32, val: StackValue) {
        self.memo.insert(idx, val);
    }

    pub fn memoize(&mut self) {
        let idx = self.memo.len() as u32;
        let val = self.peek().clone();
        self.memo.insert(idx, val);
    }

    pub fn record_global(&mut self, module: String, name: String, opcode: Opcode) {
        let gref = GlobalRef {
            module: module.clone(),
            name: name.clone(),
            offset: self.offset,
            opcode,
        };
        self.global_refs.push(gref);
        self.push(StackValue::Global { module, name });
    }

    pub fn record_reduce(&mut self) {
        let args = self.pop();
        let callable = self.pop();
        if let StackValue::Global { module, name } = &callable {
            self.reduce_calls.push(ReduceCall {
                callable: GlobalRef {
                    module: module.clone(),
                    name: name.clone(),
                    offset: self.offset,
                    opcode: Opcode::Reduce,
                },
                offset: self.offset,
            });
        }
        self.push(StackValue::Reduced {
            callable: Box::new(callable),
        });
    }

    pub fn record_build(&mut self) {
        let state = self.pop();
        let base = self.pop();
        self.push(StackValue::Built {
            base: Box::new(base),
        });
    }

    pub fn execute(&mut self, data: &[u8]) {
        self.offset = 0;
        while self.offset < data.len() {
            let byte = data[self.offset];
            let op = Opcode::from_byte(byte);
            self.opcode_count += 1;
            self.offset += 1;

            match op {
                Opcode::Proto => {
                    if self.offset < data.len() {
                        self.protocol = data[self.offset];
                        self.offset += 1;
                    }
                }
                Opcode::Frame => {
                    // 8-byte frame length — skip
                    self.offset += 8;
                }
                Opcode::Stop => break,
                Opcode::NoneOp | Opcode::BinNone => self.push(StackValue::None),
                Opcode::NewTrue => self.push(StackValue::Bool(true)),
                Opcode::NewFalse => self.push(StackValue::Bool(false)),
                Opcode::EmptyList => self.push(StackValue::List),
                Opcode::EmptyDict => self.push(StackValue::Dict),
                Opcode::EmptyTuple => self.push(StackValue::Tuple),
                Opcode::EmptySet => self.push(StackValue::Set),
                Opcode::Mark => {
                    self.mark_stack.push(self.stack.len());
                }
                Opcode::Pop => { self.pop(); }
                Opcode::PopMark => { self.pop_mark(); }
                Opcode::Dup => {
                    let val = self.peek().clone();
                    self.push(val);
                }
                Opcode::Memoize => self.memoize(),

                // ── Integer opcodes ──
                Opcode::BinInt => {
                    if self.offset + 4 <= data.len() {
                        let v = i32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]);
                        self.push(StackValue::Int(v as i64));
                        self.offset += 4;
                    }
                }
                Opcode::BinInt1 => {
                    if self.offset < data.len() {
                        self.push(StackValue::Int(data[self.offset] as i64));
                        self.offset += 1;
                    }
                }
                Opcode::BinInt2 => {
                    if self.offset + 2 <= data.len() {
                        let v = u16::from_le_bytes([data[self.offset], data[self.offset+1]]);
                        self.push(StackValue::Int(v as i64));
                        self.offset += 2;
                    }
                }
                Opcode::BinFloat => {
                    if self.offset + 8 <= data.len() {
                        let v = f64::from_be_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                            data[self.offset+4], data[self.offset+5],
                            data[self.offset+6], data[self.offset+7],
                        ]);
                        self.push(StackValue::Float(v.to_string()));
                        self.offset += 8;
                    }
                }

                // ── String opcodes ──
                Opcode::ShortBinUnicode => {
                    if self.offset < data.len() {
                        let len = data[self.offset] as usize;
                        self.offset += 1;
                        if self.offset + len <= data.len() {
                            let s = String::from_utf8_lossy(&data[self.offset..self.offset+len]).into_owned();
                            self.push(StackValue::String(s));
                            self.offset += len;
                        }
                    }
                }
                Opcode::BinUnicode => {
                    if self.offset + 4 <= data.len() {
                        let len = u32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]) as usize;
                        self.offset += 4;
                        if self.offset + len <= data.len() {
                            let s = String::from_utf8_lossy(&data[self.offset..self.offset+len]).into_owned();
                            self.push(StackValue::String(s));
                            self.offset += len;
                        }
                    }
                }
                Opcode::BinUnicode8 => {
                    if self.offset + 8 <= data.len() {
                        let len = u64::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                            data[self.offset+4], data[self.offset+5],
                            data[self.offset+6], data[self.offset+7],
                        ]) as usize;
                        self.offset += 8;
                        if self.offset + len <= data.len() {
                            let s = String::from_utf8_lossy(&data[self.offset..self.offset+len]).into_owned();
                            self.push(StackValue::String(s));
                            self.offset += len;
                        }
                    }
                }

                // ── Bytes opcodes ──
                Opcode::ShortBinBytes | Opcode::ShortBinBytes3 => {
                    if self.offset < data.len() {
                        let len = data[self.offset] as usize;
                        self.offset += 1;
                        if self.offset + len <= data.len() {
                            self.push(StackValue::Bytes(data[self.offset..self.offset+len].to_vec()));
                            self.offset += len;
                        }
                    }
                }
                Opcode::BinBytes | Opcode::BinBytes3 => {
                    if self.offset + 4 <= data.len() {
                        let len = u32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]) as usize;
                        self.offset += 4;
                        if self.offset + len <= data.len() {
                            self.push(StackValue::Bytes(data[self.offset..self.offset+len].to_vec()));
                            self.offset += len;
                        }
                    }
                }
                Opcode::BinBytes8 => {
                    if self.offset + 8 <= data.len() {
                        let len = u64::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                            data[self.offset+4], data[self.offset+5],
                            data[self.offset+6], data[self.offset+7],
                        ]) as usize;
                        self.offset += 8;
                        if self.offset + len <= data.len() {
                            self.push(StackValue::Bytes(data[self.offset..self.offset+len].to_vec()));
                            self.offset += len;
                        }
                    }
                }
                Opcode::Bytearray8 => {
                    if self.offset + 8 <= data.len() {
                        let len = u64::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                            data[self.offset+4], data[self.offset+5],
                            data[self.offset+6], data[self.offset+7],
                        ]) as usize;
                        self.offset += 8;
                        if self.offset + len <= data.len() {
                            self.push(StackValue::Bytes(data[self.offset..self.offset+len].to_vec()));
                            self.offset += len;
                        }
                    }
                }

                // ── Memo get/put ──
                Opcode::BinGet => {
                    if self.offset < data.len() {
                        let idx = data[self.offset] as u32;
                        self.offset += 1;
                        let val = self.memo_get(idx);
                        self.push(val);
                    }
                }
                Opcode::LongBinGet => {
                    if self.offset + 4 <= data.len() {
                        let idx = u32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]);
                        self.offset += 4;
                        let val = self.memo_get(idx);
                        self.push(val);
                    }
                }
                Opcode::BinPut => {
                    if self.offset < data.len() {
                        let idx = data[self.offset] as u32;
                        self.offset += 1;
                        let val = self.peek().clone();
                        self.memo_put(idx, val);
                    }
                }
                Opcode::LongBinPut => {
                    if self.offset + 4 <= data.len() {
                        let idx = u32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]);
                        self.offset += 4;
                        let val = self.peek().clone();
                        self.memo_put(idx, val);
                    }
                }

                // ── Protocol 0 text opcodes ──
                Opcode::Int => {
                    let line = self.read_line(data);
                    if line == "01" {
                        self.push(StackValue::Bool(true));
                    } else if line == "00" {
                        self.push(StackValue::Bool(false));
                    } else {
                        let v = line.parse::<i64>().unwrap_or(0);
                        self.push(StackValue::Int(v));
                    }
                }
                Opcode::Long => {
                    let line = self.read_line(data);
                    let v = line.trim_end_matches('L').parse::<i64>().unwrap_or(0);
                    self.push(StackValue::Int(v));
                }
                Opcode::Float => {
                    let line = self.read_line(data);
                    self.push(StackValue::Float(line));
                }
                Opcode::String => {
                    let line = self.read_line(data);
                    let s = line.trim_matches('\'').trim_matches('"').to_string();
                    self.push(StackValue::String(s));
                }
                Opcode::Unicode => {
                    let line = self.read_line(data);
                    self.push(StackValue::String(line));
                }
                Opcode::Get => {
                    let line = self.read_line(data);
                    let idx = line.parse::<u32>().unwrap_or(0);
                    let val = self.memo_get(idx);
                    self.push(val);
                }
                Opcode::Put => {
                    let line = self.read_line(data);
                    let idx = line.parse::<u32>().unwrap_or(0);
                    let val = self.peek().clone();
                    self.memo_put(idx, val);
                }

                // ── DANGEROUS: Global/Inst/StackGlobal ──
                Opcode::Global => {
                    let module = self.read_line(data);
                    let name = self.read_line(data);
                    self.record_global(module, name, Opcode::Global);
                }
                Opcode::Inst => {
                    let module = self.read_line(data);
                    let name = self.read_line(data);
                    self.pop_mark();
                    self.record_global(module, name, Opcode::Inst);
                }
                Opcode::StackGlobal => {
                    let name_val = self.pop();
                    let module_val = self.pop();
                    let module = match &module_val {
                        StackValue::String(s) => s.clone(),
                        _ => "<unknown>".to_string(),
                    };
                    let name = match &name_val {
                        StackValue::String(s) => s.clone(),
                        _ => "<unknown>".to_string(),
                    };
                    self.record_global(module, name, Opcode::StackGlobal);
                }

                // ── DANGEROUS: Reduce/Newobj/NewobjEx/Build ──
                Opcode::Reduce => self.record_reduce(),
                Opcode::Newobj => {
                    let args = self.pop();
                    let cls = self.pop();
                    if let StackValue::Global { module, name } = &cls {
                        self.reduce_calls.push(ReduceCall {
                            callable: GlobalRef {
                                module: module.clone(),
                                name: name.clone(),
                                offset: self.offset,
                                opcode: Opcode::Newobj,
                            },
                            offset: self.offset,
                        });
                    }
                    self.push(StackValue::Reduced { callable: Box::new(cls) });
                }
                Opcode::NewobjEx => {
                    let kwargs = self.pop();
                    let args = self.pop();
                    let cls = self.pop();
                    if let StackValue::Global { module, name } = &cls {
                        self.reduce_calls.push(ReduceCall {
                            callable: GlobalRef {
                                module: module.clone(),
                                name: name.clone(),
                                offset: self.offset,
                                opcode: Opcode::NewobjEx,
                            },
                            offset: self.offset,
                        });
                    }
                    self.push(StackValue::Reduced { callable: Box::new(cls) });
                }
                Opcode::Build => self.record_build(),

                // ── Collection builders ──
                Opcode::Tuple => {
                    let items = self.pop_mark();
                    self.push(StackValue::Tuple);
                }
                Opcode::Tuple1 => { self.pop(); self.push(StackValue::Tuple); }
                Opcode::Tuple2 => { self.pop(); self.pop(); self.push(StackValue::Tuple); }
                Opcode::Tuple3 => { self.pop(); self.pop(); self.pop(); self.push(StackValue::Tuple); }
                Opcode::List => {
                    self.pop_mark();
                    self.push(StackValue::List);
                }
                Opcode::Dict => {
                    self.pop_mark();
                    self.push(StackValue::Dict);
                }
                Opcode::Frozenset => {
                    self.pop_mark();
                    self.push(StackValue::FrozenSet);
                }

                Opcode::Append | Opcode::Setitem => { self.pop(); }
                Opcode::Appends | Opcode::Setitems | Opcode::Additems => {
                    self.pop_mark();
                }

                // ── Binary string (proto 0-1) ──
                Opcode::BinString => {
                    if self.offset + 4 <= data.len() {
                        let len = i32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]) as usize;
                        self.offset += 4;
                        if self.offset + len <= data.len() {
                            let s = String::from_utf8_lossy(&data[self.offset..self.offset+len]).into_owned();
                            self.push(StackValue::String(s));
                            self.offset += len;
                        }
                    }
                }
                Opcode::ShortBinString => {
                    if self.offset < data.len() {
                        let len = data[self.offset] as usize;
                        self.offset += 1;
                        if self.offset + len <= data.len() {
                            let s = String::from_utf8_lossy(&data[self.offset..self.offset+len]).into_owned();
                            self.push(StackValue::String(s));
                            self.offset += len;
                        }
                    }
                }

                Opcode::Long1 => {
                    if self.offset < data.len() {
                        let len = data[self.offset] as usize;
                        self.offset += 1;
                        self.offset += len;
                        self.push(StackValue::Int(0));
                    }
                }
                Opcode::Long4 => {
                    if self.offset + 4 <= data.len() {
                        let len = i32::from_le_bytes([
                            data[self.offset], data[self.offset+1],
                            data[self.offset+2], data[self.offset+3],
                        ]) as usize;
                        self.offset += 4;
                        self.offset += len;
                        self.push(StackValue::Int(0));
                    }
                }

                Opcode::Persid => {
                    let _line = self.read_line(data);
                    self.push(StackValue::Unknown);
                }
                Opcode::BinPersid => {
                    self.pop();
                    self.push(StackValue::Unknown);
                }
                Opcode::NextBuffer | Opcode::ReadonlyBuffer => {
                    self.push(StackValue::Unknown);
                }

                _ => {
                    self.errors.push(format!(
                        "Unhandled opcode {:?} (0x{:02x}) at offset {}",
                        op, byte, self.offset - 1
                    ));
                }
            }
        }
    }

    fn read_line(&mut self, data: &[u8]) -> String {
        let start = self.offset;
        while self.offset < data.len() && data[self.offset] != b'\n' {
            self.offset += 1;
        }
        let line = String::from_utf8_lossy(&data[start..self.offset]).into_owned();
        if self.offset < data.len() {
            self.offset += 1; // skip newline
        }
        line.trim_end_matches('\r').to_string()
    }
}

impl Default for PVMState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pickle() {
        let mut state = PVMState::new();
        state.execute(&[b'.']); // just STOP
        assert_eq!(state.opcode_count, 1);
        assert!(state.global_refs.is_empty());
    }

    #[test]
    fn test_global_detection() {
        // Protocol 0: c<module>\n<name>\n
        let data = b"cos\nsystem\nR.";
        let mut state = PVMState::new();
        state.execute(data);
        assert_eq!(state.global_refs.len(), 1);
        assert_eq!(state.global_refs[0].module, "os");
        assert_eq!(state.global_refs[0].name, "system");
    }

    #[test]
    fn test_protocol2_header() {
        let data = &[0x80, 0x02, b'.'];
        let mut state = PVMState::new();
        state.execute(data);
        assert_eq!(state.protocol, 2);
    }

    #[test]
    fn test_stack_global() {
        // SHORT_BINUNICODE "os", SHORT_BINUNICODE "system", STACK_GLOBAL
        let mut data = vec![0x80, 0x04]; // proto 4
        data.push(0x95); // FRAME
        data.extend_from_slice(&[20u8, 0, 0, 0, 0, 0, 0, 0]); // frame len
        data.push(0x8c); data.push(2); data.extend_from_slice(b"os"); // SHORT_BINUNICODE "os"
        data.push(0x8c); data.push(6); data.extend_from_slice(b"system"); // SHORT_BINUNICODE "system"
        data.push(0x93); // STACK_GLOBAL
        data.push(b'.'); // STOP

        let mut state = PVMState::new();
        state.execute(&data);
        assert_eq!(state.global_refs.len(), 1);
        assert_eq!(state.global_refs[0].module, "os");
        assert_eq!(state.global_refs[0].name, "system");
    }

    #[test]
    fn test_memo_round_trip() {
        let mut state = PVMState::new();
        state.push(StackValue::String("hello".to_string()));
        state.memo_put(0, StackValue::String("hello".to_string()));
        let val = state.memo_get(0);
        assert_eq!(val, StackValue::String("hello".to_string()));
    }
}
