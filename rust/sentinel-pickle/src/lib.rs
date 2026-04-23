// sentinel-pickle: High-performance pickle opcode scanner
// -------------------------------------------------------
// This crate provides a Rust-native pickle virtual machine (PVM) that
// reads pickle streams byte-by-byte, tracks the stack / memo state,
// and evaluates every GLOBAL / STACK_GLOBAL / INST opcode against a
// configurable policy (allowlist + blocklist).  The result is exposed
// to Python via PyO3 so Eresus Sentinel can fall back to this engine
// for 10-100× faster scanning of large .pkl / .pt files.

pub mod opcode;
pub mod state;
pub mod policy;
pub mod scanner;
pub mod strings;
pub mod report;

use pyo3::prelude::*;

/// Python module entry-point — `import sentinel_pickle`
#[pymodule]
fn sentinel_pickle(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<scanner::PickleScanner>()?;
    m.add_class::<policy::ScanPolicy>()?;
    m.add_class::<report::Finding>()?;
    m.add_function(wrap_pyfunction!(scanner::scan_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(scanner::scan_file, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
