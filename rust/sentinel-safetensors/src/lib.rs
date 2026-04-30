// sentinel-safetensors: fast safetensors header security scanner
// Parses the 8-byte length prefix + JSON header and runs checks.

pub mod header;
pub mod checks;
pub mod report;

use pyo3::prelude::*;

#[pymodule]
fn sentinel_safetensors(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<report::SafetensorsFinding>()?;
    m.add_function(wrap_pyfunction!(scan_bytes_py, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}

/// Python-callable: scan raw safetensors bytes → list of findings.
#[pyfunction]
#[pyo3(name = "scan_bytes")]
fn scan_bytes_py(data: &[u8]) -> PyResult<Vec<report::SafetensorsFinding>> {
    match header::parse(data) {
        Ok(hdr) => Ok(checks::run(&hdr)),
        Err(e)  => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
    }
}
