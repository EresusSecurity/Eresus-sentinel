// mutators/mod.rs — Mutation strategies for pickle byte-stream fuzzing
//
// Two levels of mutation:
// 1. Byte-level: `mutate(&mut buf, offset)` — raw byte perturbation
// 2. Value-level: `mutate_int()`, `mutate_string()`, etc. — semantic mutations
//
// Mutators are used by fuzz targets and the structure-aware generator
// to create deviant pickle streams that exercise edge cases in the
// scanner.

mod bitflip;
mod boundary;
mod character;
pub mod injection;
mod memoindex;
mod offbyone;
mod stringlen;
mod typeconfusion;

pub use bitflip::BitFlipMutator;
pub use boundary::BoundaryMutator;
pub use character::CharacterMutator;
pub use injection::InjectionMutator;
pub use memoindex::MemoIndexMutator;
pub use offbyone::OffByOneMutator;
pub use stringlen::StringLengthMutator;
pub use typeconfusion::TypeConfusionMutator;

/// All available mutator variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutatorKind {
    BitFlip,
    Boundary,
    Character,
    Injection,
    MemoIndex,
    OffByOne,
    StringLength,
    TypeConfusion,
}

impl MutatorKind {
    /// All safe mutators (excludes MemoIndex and TypeConfusion).
    pub fn safe_mutators() -> Vec<MutatorKind> {
        vec![
            MutatorKind::BitFlip,
            MutatorKind::Boundary,
            MutatorKind::Character,
            MutatorKind::Injection,
            MutatorKind::OffByOne,
            MutatorKind::StringLength,
        ]
    }

    /// All mutators including unsafe ones.
    pub fn all_mutators() -> Vec<MutatorKind> {
        vec![
            MutatorKind::BitFlip,
            MutatorKind::Boundary,
            MutatorKind::Character,
            MutatorKind::Injection,
            MutatorKind::MemoIndex,
            MutatorKind::OffByOne,
            MutatorKind::StringLength,
            MutatorKind::TypeConfusion,
        ]
    }

    /// Create a boxed mutator from this kind.
    pub fn create(&self) -> Box<dyn Mutator> {
        match self {
            MutatorKind::BitFlip => Box::new(BitFlipMutator),
            MutatorKind::Boundary => Box::new(BoundaryMutator),
            MutatorKind::Character => Box::new(CharacterMutator),
            MutatorKind::Injection => Box::new(InjectionMutator),
            MutatorKind::MemoIndex => Box::new(MemoIndexMutator),
            MutatorKind::OffByOne => Box::new(OffByOneMutator),
            MutatorKind::StringLength => Box::new(StringLengthMutator),
            MutatorKind::TypeConfusion => Box::new(TypeConfusionMutator),
        }
    }

    /// Whether this mutator can produce invalid/unsafe mutations.
    pub fn is_unsafe(&self) -> bool {
        matches!(self, MutatorKind::MemoIndex | MutatorKind::TypeConfusion)
    }
}

/// Common interface every mutator must implement.
pub trait Mutator: Send + Sync {
    /// Apply byte-level mutation to `buf` at `offset`.
    fn mutate(&self, buf: &mut Vec<u8>, offset: usize) -> bool;

    /// Human-readable name.
    fn name(&self) -> &'static str;

    // ── Value-aware hooks (default = no-op) ─────────────────────
    fn mutate_int(&self, _value: i32, _rate: f64) -> Option<i32> { None }
    fn mutate_long(&self, _value: i64, _rate: f64) -> Option<i64> { None }
    fn mutate_float(&self, _value: f64, _rate: f64) -> Option<f64> { None }
    fn mutate_string(&self, _value: String, _rate: f64) -> Option<String> { None }
    fn mutate_bytes(&self, _value: Vec<u8>, _rate: f64) -> Option<Vec<u8>> { None }
    fn mutate_memo_index(&self, _idx: usize, _rate: f64) -> Option<usize> { None }

    /// Whether this mutator can produce invalid pickles.
    fn is_unsafe_mutator(&self) -> bool { false }
}

/// Apply all mutators in sequence (byte-level); returns count that fired.
pub fn apply_all(buf: &mut Vec<u8>, offset: usize) -> usize {
    let mutators: &[&dyn Mutator] = &[
        &BitFlipMutator,
        &BoundaryMutator,
        &CharacterMutator,
        &InjectionMutator,
        &MemoIndexMutator,
        &OffByOneMutator,
        &StringLengthMutator,
        &TypeConfusionMutator,
    ];
    mutators.iter().filter(|m| m.mutate(buf, offset)).count()
}

/// Apply first matching value-level mutation on an i32.
pub fn apply_int_mutation(value: i32, rate: f64) -> i32 {
    let mutators: &[&dyn Mutator] = &[
        &BitFlipMutator,
        &BoundaryMutator,
        &OffByOneMutator,
    ];
    for m in mutators {
        if let Some(v) = m.mutate_int(value, rate) {
            return v;
        }
    }
    value
}

/// Apply first matching value-level mutation on a string.
pub fn apply_string_mutation(value: String, rate: f64) -> String {
    let mutators: &[&dyn Mutator] = &[
        &InjectionMutator,
        &CharacterMutator,
        &StringLengthMutator,
    ];
    for m in mutators {
        if let Some(v) = m.mutate_string(value.clone(), rate) {
            return v;
        }
    }
    value
}
