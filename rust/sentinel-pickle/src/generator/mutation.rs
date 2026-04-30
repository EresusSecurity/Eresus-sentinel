// generator/mutation.rs — Mutation integration during generation
//
// Applies registered mutators to values as they are generated.
// Mutations are applied at value-level: mutate_int/float/string/bytes/memo_index
// and post-emission byte-level via mutate() on the output buffer.

use super::Generator;

impl Generator {
    /// Apply mutations to an integer value.
    pub(super) fn mutate_int(&self, value: i32) -> i32 {
        if self.mutators.is_empty() { return value; }
        let mut result = value;
        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            if let Some(mutated) = mutator.mutate_int(result, self.mutation_rate) {
                result = mutated;
                break;
            }
        }
        result
    }

    /// Apply mutations to a long integer value.
    pub(super) fn mutate_long(&self, value: i64) -> i64 {
        if self.mutators.is_empty() { return value; }
        let mut result = value;
        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            if let Some(mutated) = mutator.mutate_long(result, self.mutation_rate) {
                result = mutated;
                break;
            }
        }
        result
    }

    /// Apply mutations to a float value.
    pub(super) fn mutate_float(&self, value: f64) -> f64 {
        if self.mutators.is_empty() { return value; }
        let mut result = value;
        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            if let Some(mutated) = mutator.mutate_float(result, self.mutation_rate) {
                result = mutated;
                break;
            }
        }
        result
    }

    /// Apply mutations to a string value.
    pub(super) fn mutate_string(&self, value: String) -> String {
        if self.mutators.is_empty() { return value; }
        let mut result = value;
        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            if let Some(mutated) = mutator.mutate_string(result.clone(), self.mutation_rate) {
                result = mutated;
                break;
            }
        }
        result
    }

    /// Apply mutations to a bytes value.
    pub(super) fn mutate_bytes(&self, value: Vec<u8>) -> Vec<u8> {
        if self.mutators.is_empty() { return value; }
        let mut result = value;
        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            if let Some(mutated) = mutator.mutate_bytes(result.clone(), self.mutation_rate) {
                result = mutated;
                break;
            }
        }
        result
    }

    /// Apply mutations to a memo index.
    pub(super) fn mutate_memo_index(&self, index: usize) -> usize {
        if self.mutators.is_empty() { return index; }
        let mut result = index;
        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            if let Some(mutated) = mutator.mutate_memo_index(result, self.mutation_rate) {
                result = mutated;
                break;
            }
        }
        result
    }

    /// Apply post-emission byte-level mutations to the output buffer.
    pub(super) fn post_process_emission(
        &mut self,
        pre_output_len: usize,
    ) {
        if self.mutators.is_empty() { return; }
        if self.output.len() <= pre_output_len { return; }

        let original = self.output[pre_output_len..].to_vec();

        for mutator in &self.mutators {
            if !self.unsafe_mutations && mutator.is_unsafe_mutator() { continue; }
            mutator.mutate(&mut self.output, pre_output_len);
        }

        // If mutation changed the output but we can't resynchronize the stack,
        // revert to keep the generator state consistent when not in unsafe mode
        let mutated = &self.output[pre_output_len..];
        if mutated != original.as_slice() && !self.unsafe_mutations {
            self.output.truncate(pre_output_len);
            self.output.extend_from_slice(&original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutators::MutatorKind;

    #[test]
    fn test_mutate_int_no_mutators() {
        let gen = Generator::new(4);
        assert_eq!(gen.mutate_int(42), 42);
    }

    #[test]
    fn test_mutate_string_no_mutators() {
        let gen = Generator::new(4);
        assert_eq!(gen.mutate_string("hello".into()), "hello");
    }

    #[test]
    fn test_mutate_int_with_boundary() {
        let gen = Generator::new(4)
            .with_mutator(MutatorKind::Boundary.create())
            .with_mutation_rate(1.0);
        let result = gen.mutate_int(42);
        let boundary_vals = [0i32, 1, -1, i32::MAX, i32::MIN, 127, -128, 255, 256, 65535, 65536];
        assert!(boundary_vals.contains(&result), "expected boundary value, got {result}");
    }

    #[test]
    fn test_mutate_string_with_injection() {
        let gen = Generator::new(4)
            .with_mutator(MutatorKind::Injection.create())
            .with_mutation_rate(1.0);
        let result = gen.mutate_string("hello".into());
        assert_ne!(result, "hello");
    }

    #[test]
    fn test_unsafe_mutators_skipped() {
        let gen = Generator::new(4)
            .with_mutator(MutatorKind::MemoIndex.create())
            .with_mutation_rate(1.0);
        let result = gen.mutate_memo_index(5);
        assert_eq!(result, 5, "unsafe mutator should be skipped");
    }

    #[test]
    fn test_unsafe_mutators_allowed() {
        let gen = Generator::new(4)
            .with_mutator(MutatorKind::MemoIndex.create())
            .with_mutation_rate(1.0)
            .with_unsafe_mutations(true);
        let result = gen.mutate_memo_index(5);
        assert_ne!(result, 5, "unsafe mutator should apply when allowed");
    }

    #[test]
    fn test_generate_with_mutators() {
        let mut gen = Generator::new(4)
            .min_opcodes(8)
            .max_opcodes(64)
            .with_mutator(MutatorKind::Boundary.create())
            .with_mutator(MutatorKind::Injection.create())
            .with_mutation_rate(0.5);
        let pickle = gen.generate(42).unwrap();
        assert!(!pickle.is_empty());
        assert_eq!(*pickle.last().unwrap(), b'.');
    }

    #[test]
    fn test_generate_with_unsafe_mutators() {
        let mut gen = Generator::new(4)
            .min_opcodes(4)
            .max_opcodes(32)
            .with_mutator(MutatorKind::MemoIndex.create())
            .with_mutator(MutatorKind::TypeConfusion.create())
            .with_mutation_rate(0.3)
            .with_unsafe_mutations(true);
        let pickle = gen.generate(42).unwrap();
        assert!(!pickle.is_empty());
        assert_eq!(*pickle.last().unwrap(), b'.');
    }
}
