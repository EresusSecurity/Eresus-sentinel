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

/// Python-exposed GGUF metadata extracted from the file header.
#[pyclass]
#[derive(Debug, Clone)]
pub struct GgufMetadata {
    #[pyo3(get)]
    pub version: u32,
    #[pyo3(get)]
    pub tensor_count: u64,
    #[pyo3(get)]
    pub kv_count: u64,
    #[pyo3(get)]
    pub data_len: usize,
}

#[pymethods]
impl GgufMetadata {
    fn kv_entries_dict<'py>(&self, py: pyo3::Python<'py>) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::types::PyDict>> {
        let dict = pyo3::types::PyDict::new(py);
        Ok(dict)
    }

    fn __repr__(&self) -> String {
        format!(
            "GgufMetadata(version={}, tensor_count={}, kv_count={})",
            self.version, self.tensor_count, self.kv_count
        )
    }
}

/// Python-exposed scan report bundling findings + metadata.
#[pyclass]
#[derive(Debug, Clone)]
pub struct GgufScanReport {
    #[pyo3(get)]
    pub findings: Vec<report::GgufFinding>,
    #[pyo3(get)]
    pub metadata: GgufMetadata,
    #[pyo3(get)]
    pub ok: bool,
}

#[pymethods]
impl GgufScanReport {
    fn finding_count(&self) -> usize {
        self.findings.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "GgufScanReport(findings={}, ok={})",
            self.findings.len(), self.ok
        )
    }
}

/// Internal helper: build a GgufScanReport from raw bytes.
fn scan_to_report_internal(data: &[u8]) -> GgufScanReport {
    let findings = scan(data);
    let metadata = match header::parse(data) {
        Ok(hdr) => GgufMetadata {
            version: hdr.version,
            tensor_count: hdr.tensor_count,
            kv_count: hdr.kv_count,
            data_len: hdr.data_len,
        },
        Err(_) => GgufMetadata {
            version: 0,
            tensor_count: 0,
            kv_count: 0,
            data_len: data.len(),
        },
    };
    let ok = findings.is_empty();
    GgufScanReport { findings, metadata, ok }
}

/// Python module entry-point — `import sentinel_gguf`
#[pymodule]
fn sentinel_gguf(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<report::GgufFinding>()?;
    m.add_class::<GgufMetadata>()?;
    m.add_class::<GgufScanReport>()?;
    m.add_function(wrap_pyfunction!(scan_bytes_py, m)?)?;
    m.add_function(wrap_pyfunction!(scan_file_py, m)?)?;
    m.add_function(wrap_pyfunction!(scan_bytes_report_py, m)?)?;
    m.add_function(wrap_pyfunction!(extract_metadata_py, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}

/// Python-callable: scan raw GGUF bytes → list of findings.
#[pyfunction]
#[pyo3(name = "scan_bytes")]
fn scan_bytes_py(data: &[u8]) -> Vec<report::GgufFinding> {
    scan(data)
}

/// Python-callable: scan a GGUF file on disk → list of findings.
#[pyfunction]
#[pyo3(name = "scan_file")]
fn scan_file_py(path: &str) -> PyResult<Vec<report::GgufFinding>> {
    let data = std::fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to read {}: {}", path, e))
    })?;
    Ok(scan(&data))
}

/// Python-callable: scan raw GGUF bytes → GgufScanReport (findings + metadata).
#[pyfunction]
#[pyo3(name = "scan_bytes_report")]
fn scan_bytes_report_py(data: &[u8]) -> GgufScanReport {
    scan_to_report_internal(data)
}

/// Python-callable: extract GGUF header metadata without running security checks.
#[pyfunction]
#[pyo3(name = "extract_metadata")]
fn extract_metadata_py(data: &[u8]) -> PyResult<GgufMetadata> {
    header::parse(data)
        .map(|hdr| GgufMetadata {
            version: hdr.version,
            tensor_count: hdr.tensor_count,
            kv_count: hdr.kv_count,
            data_len: hdr.data_len,
        })
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
