// fuzz/src/lib.rs — Shared fuzz helper crate
//
// Provides invariant checks, format builders, and corpus seeds
// shared across all fuzz targets.

pub mod invariants;
pub mod builders;
pub mod corpus;
