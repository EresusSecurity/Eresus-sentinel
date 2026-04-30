// sentinel-gguf: fast GGUF model file security scanner
// ---------------------------------------------------
// Parses the GGUF binary header (magic, version, tensor count, KV pairs)
// and runs security checks for injection, overflow, and anomalous values.

pub mod header;
pub mod checks;
pub mod report;

use pyo3::prelude::*;

/// Rust-native scan — call this from fuzz targets or other Rust code.
pub fn scan(data: &[u8]) -> Vec<report::GgufFinding> {
    match header::parse(data) {
        Ok(hdr) => checks::run(&hdr, data),
        Err(e)  => vec![report::GgufFinding {
            rule_id:     "GGUF-000".into(),
            severity:    report::Severity::Medium,
            title:       "GGUF parse error".into(),
            evidence:    e.to_string(),
            description: format!("Failed to parse GGUF header: {e}"),
            confidence:  0.9,
        }],
    }
}

/// Python module entry-point — `import sentinel_gguf`
#[pymodule]
fn sentinel_gguf(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<report::GgufFinding>()?;
    m.add_function(wrap_pyfunction!(scan_bytes_py, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}

/// Python-callable: scan raw GGUF bytes → list of findings.
#[pyfunction]
#[pyo3(name = "scan_bytes")]
fn scan_bytes_py(data: &[u8]) -> Vec<report::GgufFinding> {
    scan(data)
}
