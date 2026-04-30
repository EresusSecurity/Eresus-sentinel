// generator/state.rs — Generator stack value types
//
// Lightweight enum tracking what the generator has pushed onto
// its simulated stack. Used for opcode validation (e.g., can we
// emit STACK_GLOBAL? Only if TOS and TOS-1 are strings).

/// Value types tracked on the generator's simulated stack.
#[derive(Debug, Clone, PartialEq)]
pub enum GenStackValue {
    None,
    Bool(bool),
    Int(i64),
    Float,
    String(String),
    Bytes,
    List,
    Dict,
    Tuple,
    Set,
    FrozenSet,
    Mark,
    Global { module: String, name: String },
    Reduced { callable: Box<GenStackValue> },
    Unknown,
}
