// generator/source.rs — Entropy source abstraction for pickle generation
//
// Provides a unified interface for generating random values from either:
// - Rand (ChaCha8Rng) for deterministic CLI/standalone use
// - Arbitrary (Unstructured) for coverage-guided fuzzing

use arbitrary::Unstructured;
use rand::{Rng, TryRngCore};
use rand_chacha::ChaCha8Rng;

/// Source of entropy for pickle generation.
pub enum GenerationSource<'a> {
    Rand(&'a mut ChaCha8Rng),
    Arbitrary(&'a mut Unstructured<'a>),
}

/// Trait abstracting entropy generation.
pub trait EntropySource {
    fn choose_index(&mut self, max: usize) -> usize;
    fn gen_bool(&mut self) -> bool;
    fn gen_u8(&mut self) -> u8;
    fn gen_u16(&mut self) -> u16;
    fn gen_u32(&mut self) -> u32;
    fn gen_i32(&mut self) -> i32;
    fn gen_i64(&mut self) -> i64;
    fn gen_f64(&mut self) -> f64;
    fn gen_range(&mut self, min: usize, max: usize) -> usize;
    fn gen_bytes(&mut self, len: usize) -> Vec<u8>;
    fn gen_ascii_char(&mut self) -> char;
}

const ASCII_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

impl<'a> EntropySource for GenerationSource<'a> {
    fn choose_index(&mut self, max: usize) -> usize {
        if max == 0 { return 0; }
        match self {
            GenerationSource::Rand(rng) => rng.random_range(0..max),
            GenerationSource::Arbitrary(u) => u.choose_index(max).unwrap_or(0),
        }
    }

    fn gen_bool(&mut self) -> bool {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(false),
        }
    }

    fn gen_u8(&mut self) -> u8 {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(0),
        }
    }

    fn gen_u16(&mut self) -> u16 {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(0),
        }
    }

    fn gen_u32(&mut self) -> u32 {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(0),
        }
    }

    fn gen_i32(&mut self) -> i32 {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(0),
        }
    }

    fn gen_i64(&mut self) -> i64 {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(0),
        }
    }

    fn gen_f64(&mut self) -> f64 {
        match self {
            GenerationSource::Rand(rng) => rng.random(),
            GenerationSource::Arbitrary(u) => u.arbitrary().unwrap_or(0.0),
        }
    }

    fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max { return min; }
        match self {
            GenerationSource::Rand(rng) => rng.random_range(min..max),
            GenerationSource::Arbitrary(u) => {
                u.int_in_range(min..=max.saturating_sub(1)).unwrap_or(min)
            }
        }
    }

    fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        match self {
            GenerationSource::Rand(rng) => {
                let mut bytes = vec![0u8; len];
                rng.try_fill_bytes(&mut bytes).unwrap_or(());
                bytes
            }
            GenerationSource::Arbitrary(u) => {
                u.bytes(len).map(|b| b.to_vec()).unwrap_or_else(|_| vec![0u8; len])
            }
        }
    }

    fn gen_ascii_char(&mut self) -> char {
        let idx = self.choose_index(ASCII_CHARS.len());
        ASCII_CHARS[idx] as char
    }
}
