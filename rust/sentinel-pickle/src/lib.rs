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
pub mod mutators;
pub mod generator;

use pyo3::prelude::*;

/// Python module entry-point — `import sentinel_pickle`
#[pymodule]
fn sentinel_pickle(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<scanner::PickleScanner>()?;
    m.add_class::<policy::ScanPolicy>()?;
    m.add_class::<report::Finding>()?;
    m.add_class::<PyGenerator>()?;
    m.add_function(wrap_pyfunction!(scanner::scan_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(scanner::scan_file, m)?)?;
    m.add_function(wrap_pyfunction!(py_generate_pickle, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}

/// Python-callable: generate a pickle stream with given version and seed.
#[pyfunction]
#[pyo3(name = "generate_pickle")]
fn py_generate_pickle(version: u8, seed: u64, min_ops: usize, max_ops: usize) -> PyResult<Vec<u8>> {
    let mut gen = generator::Generator::new(version)
        .min_opcodes(min_ops)
        .max_opcodes(max_ops);
    gen.generate(seed).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// Full-featured Python generator class with builder-pattern configuration.
#[pyclass(name = "PickleGenerator")]
struct PyGenerator {
    version: u8,
    seed: Option<u64>,
    min_opcodes: usize,
    max_opcodes: usize,
    mutation_rate: f64,
    bufsize: Option<usize>,
}

#[pymethods]
impl PyGenerator {
    #[new]
    #[pyo3(signature = (protocol=4, seed=None, min_opcodes=8, max_opcodes=64))]
    fn new(protocol: u8, seed: Option<u64>, min_opcodes: usize, max_opcodes: usize) -> PyResult<Self> {
        if protocol > 5 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Invalid protocol: {}. Must be 0-5.", protocol),
            ));
        }
        Ok(PyGenerator {
            version: protocol,
            seed,
            min_opcodes,
            max_opcodes,
            mutation_rate: 0.1,
            bufsize: None,
        })
    }

    /// Generate pickle bytes using a seed (defaults to constructor seed or 0).
    #[pyo3(signature = (seed=None))]
    fn generate(&mut self, seed: Option<u64>) -> PyResult<Vec<u8>> {
        let s = seed.or(self.seed).unwrap_or(0);
        let mut gen = generator::Generator::new(self.version)
            .min_opcodes(self.min_opcodes)
            .max_opcodes(self.max_opcodes)
            .with_mutation_rate(self.mutation_rate);
        if let Some(bs) = self.bufsize {
            gen = gen.with_buffer_size(bs);
        }
        gen.generate(s).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
    }

    /// Generate pickle bytes from fuzzer-provided arbitrary bytes.
    fn generate_from_bytes(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        let mut gen = generator::Generator::new(self.version)
            .min_opcodes(self.min_opcodes)
            .max_opcodes(self.max_opcodes)
            .with_mutation_rate(self.mutation_rate);
        if let Some(bs) = self.bufsize {
            gen = gen.with_buffer_size(bs);
        }
        gen.generate_from_arbitrary(data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
    }

    /// Set opcode range.
    fn set_opcode_range(&mut self, min_opcodes: usize, max_opcodes: usize) {
        self.min_opcodes = min_opcodes;
        self.max_opcodes = max_opcodes.max(min_opcodes);
    }

    /// Set mutation rate (0.0-1.0).
    fn set_mutation_rate(&mut self, rate: f64) {
        self.mutation_rate = rate.clamp(0.0, 1.0);
    }

    /// Set maximum output size.
    fn set_buffer_size(&mut self, size: usize) {
        self.bufsize = Some(size);
    }

    /// Get protocol version.
    #[getter]
    fn protocol(&self) -> u8 { self.version }

    /// Get min opcodes.
    #[getter]
    fn min_opcodes(&self) -> usize { self.min_opcodes }

    /// Get max opcodes.
    #[getter]
    fn max_opcodes(&self) -> usize { self.max_opcodes }
}
