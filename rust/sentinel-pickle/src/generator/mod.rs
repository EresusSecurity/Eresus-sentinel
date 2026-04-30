// generator/mod.rs — Structure-aware pickle bytecode generator
//
// Ports the Cisco pickle-fuzzer architecture into sentinel-pickle.
// Produces syntactically valid pickle streams across protocols 0-5
// using either seeded PRNG or coverage-guided fuzzer bytes.
//
// Usage (Rust):
//   let mut gen = Generator::new(4).min_opcodes(8).max_opcodes(128);
//   let pickle = gen.generate(42)?;
//
// Usage (fuzz target):
//   let pickle = Generator::new(4).generate_from_arbitrary(data)?;

pub mod source;
mod core;
mod emission;
mod mutation;
mod stack_ops;
mod utils;
mod validation;

pub(crate) mod state;

pub use source::{EntropySource, GenerationSource};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use arbitrary::Unstructured;

use crate::mutators::Mutator;
use state::GenStackValue;

/// Structure-aware pickle bytecode generator.
///
/// Maintains a simulated stack + memo to ensure only valid opcode
/// sequences are produced.  Supports protocols 0-5.
pub struct Generator {
    /// Target protocol version (0-5).
    pub(crate) version: u8,
    /// Simulated pickle stack.
    pub(crate) stack: Vec<GenStackValue>,
    /// Output bytecode buffer.
    pub(crate) output: Vec<u8>,
    /// Next available memo index.
    pub(crate) next_memo: u32,
    /// Total opcodes emitted.
    pub(crate) opcode_count: usize,
    /// Minimum body opcodes to emit.
    min_opcodes: usize,
    /// Maximum body opcodes to emit.
    max_opcodes: usize,
    /// Active mutators for argument mutation.
    pub(crate) mutators: Vec<Box<dyn Mutator>>,
    /// Mutation rate (0.0-1.0).
    pub(crate) mutation_rate: f64,
    /// Allow unsafe mutations that may violate pickle validity.
    pub(crate) unsafe_mutations: bool,
    /// Maximum output size (None = unlimited).
    pub(crate) bufsize: Option<usize>,
}

impl Generator {
    /// Create a new generator for the given protocol version.
    pub fn new(version: u8) -> Self {
        Self {
            version: version.min(5),
            stack: Vec::with_capacity(256),
            output: Vec::with_capacity(4096),
            next_memo: 0,
            opcode_count: 0,
            min_opcodes: 4,
            max_opcodes: 64,
            mutators: Vec::new(),
            mutation_rate: 0.1,
            unsafe_mutations: false,
            bufsize: None,
        }
    }

    /// Set minimum number of body opcodes.
    pub fn min_opcodes(mut self, n: usize) -> Self {
        self.min_opcodes = n;
        self
    }

    /// Set maximum number of body opcodes.
    pub fn max_opcodes(mut self, n: usize) -> Self {
        self.max_opcodes = n;
        self
    }

    /// Set both min and max opcodes.
    pub fn with_opcode_range(mut self, min: usize, max: usize) -> Self {
        self.min_opcodes = min;
        self.max_opcodes = max.max(min);
        self
    }

    /// Set maximum output size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.bufsize = Some(size);
        self
    }

    /// Add a mutator.
    pub fn with_mutator(mut self, mutator: Box<dyn Mutator>) -> Self {
        self.mutators.push(mutator);
        self
    }

    /// Set mutation rate (0.0-1.0).
    pub fn with_mutation_rate(mut self, rate: f64) -> Self {
        self.mutation_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Allow unsafe mutations.
    pub fn with_unsafe_mutations(mut self, allow: bool) -> Self {
        self.unsafe_mutations = allow;
        self
    }

    /// Get normalized opcode range (min, max).
    pub(crate) fn normalized_opcode_range(&self) -> (usize, usize) {
        let min = self.min_opcodes.max(2); // at least PROTO + STOP
        let max = self.max_opcodes.max(min);
        (min, max)
    }

    /// Reset internal state for a fresh generation.
    fn reset(&mut self) {
        self.stack.clear();
        self.output.clear();
        self.next_memo = 0;
        self.opcode_count = 0;
    }

    /// Generate a pickle stream using a seed for deterministic output.
    pub fn generate(&mut self, seed: u64) -> Result<Vec<u8>, String> {
        self.reset();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut source = GenerationSource::Rand(&mut rng);
        self.generate_internal(&mut source)
    }

    /// Generate a pickle stream from fuzzer-provided arbitrary bytes.
    pub fn generate_from_arbitrary(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("empty input".to_string());
        }
        self.reset();
        // Use first byte for protocol selection (optional)
        let version_byte = data[0] % 6;
        self.version = version_byte;
        let mut u = Unstructured::new(&data[1..]);
        let mut source = GenerationSource::Arbitrary(&mut u);
        self.generate_internal(&mut source)
    }
}

impl Default for Generator {
    fn default() -> Self {
        Self::new(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_deterministic() {
        let mut gen = Generator::new(4).min_opcodes(4).max_opcodes(32);
        let a = gen.generate(42).unwrap();
        let mut gen2 = Generator::new(4).min_opcodes(4).max_opcodes(32);
        let b = gen2.generate(42).unwrap();
        assert_eq!(a, b, "same seed must produce identical output");
    }

    #[test]
    fn test_generate_ends_with_stop() {
        let mut gen = Generator::new(2).min_opcodes(4).max_opcodes(32);
        let pickle = gen.generate(123).unwrap();
        assert!(!pickle.is_empty());
        assert_eq!(*pickle.last().unwrap(), b'.', "pickle must end with STOP");
    }

    #[test]
    fn test_generate_starts_with_proto() {
        let mut gen = Generator::new(4).min_opcodes(4).max_opcodes(32);
        let pickle = gen.generate(99).unwrap();
        assert!(pickle.len() >= 2);
        assert_eq!(pickle[0], 0x80, "v4 pickle must start with PROTO");
        assert_eq!(pickle[1], 4, "PROTO version must be 4");
    }

    #[test]
    fn test_generate_v0_no_proto() {
        let mut gen = Generator::new(0).min_opcodes(4).max_opcodes(32);
        let pickle = gen.generate(77).unwrap();
        assert!(!pickle.is_empty());
        // V0 should NOT start with PROTO
        assert_ne!(pickle[0], 0x80, "v0 pickle must not start with PROTO");
    }

    #[test]
    fn test_generate_from_arbitrary() {
        let data = [4u8, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04,
                     0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let mut gen = Generator::default();
        let result = gen.generate_from_arbitrary(&data);
        assert!(result.is_ok());
        let pickle = result.unwrap();
        assert!(!pickle.is_empty());
        assert_eq!(*pickle.last().unwrap(), b'.');
    }

    #[test]
    fn test_generate_from_arbitrary_empty() {
        let mut gen = Generator::default();
        let result = gen.generate_from_arbitrary(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_seeds_different_output() {
        let mut gen = Generator::new(4).min_opcodes(8).max_opcodes(64);
        let a = gen.generate(1).unwrap();
        let b = gen.generate(2).unwrap();
        // Very unlikely to produce identical output with different seeds
        assert_ne!(a, b, "different seeds should produce different output");
    }

    #[test]
    fn test_all_protocols() {
        for version in 0..=5 {
            let mut gen = Generator::new(version).min_opcodes(4).max_opcodes(16);
            let pickle = gen.generate(version as u64 * 100).unwrap();
            assert!(!pickle.is_empty());
            assert_eq!(*pickle.last().unwrap(), b'.');
            if version >= 2 {
                assert_eq!(pickle[0], 0x80);
                assert_eq!(pickle[1], version);
            }
        }
    }

    #[test]
    fn test_large_generation() {
        let mut gen = Generator::new(4).min_opcodes(100).max_opcodes(512);
        let pickle = gen.generate(999).unwrap();
        assert!(pickle.len() > 50, "large generation should produce substantial output");
        assert_eq!(*pickle.last().unwrap(), b'.');
    }

    #[test]
    fn test_generate_roundtrip_with_scanner() {
        // Generate a pickle and scan it — should not panic
        let mut gen = Generator::new(4).min_opcodes(8).max_opcodes(64);
        let pickle = gen.generate(42).unwrap();

        let policy = crate::policy::ScanPolicy::new(false);
        let findings = crate::scanner::scan_data(&pickle, &policy);
        // Findings should be well-formed
        for f in &findings {
            assert!(!f.rule_id.is_empty());
            assert!(f.confidence >= 0.0 && f.confidence <= 1.0);
        }
    }
}
