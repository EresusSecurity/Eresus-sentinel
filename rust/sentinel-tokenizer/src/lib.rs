// sentinel-tokenizer: fast HuggingFace tokenizer.json security scanner
// --------------------------------------------------------------------
// Parses tokenizer.json and checks added_tokens, normalizer, pre_tokenizer,
// and model fields for injection, overflow, and anomalous values.

pub mod checks;
pub mod report;

use pyo3::prelude::*;
use serde_json::Value;

/// Rust-native scan — call this from fuzz targets or other Rust code.
pub fn scan(data: &[u8]) -> Vec<report::TokenizerFinding> {
    let json_str = match std::str::from_utf8(data) {
        Ok(s)  => s,
        Err(_) => return vec![report::TokenizerFinding {
            rule_id:     "TOK-000".into(),
            severity:    report::Severity::Medium,
            title:       "Invalid UTF-8 in tokenizer file".into(),
            evidence:    format!("data_len={}", data.len()),
            description: "tokenizer.json contains invalid UTF-8 bytes".into(),
            confidence:  0.9,
        }],
    };

    let parsed: Value = match serde_json::from_str(json_str) {
        Ok(v)  => v,
        Err(e) => return vec![report::TokenizerFinding {
            rule_id:     "TOK-000".into(),
            severity:    report::Severity::Medium,
            title:       "Invalid JSON in tokenizer file".into(),
            evidence:    e.to_string(),
            description: format!("Failed to parse tokenizer.json: {e}"),
            confidence:  0.9,
        }],
    };

    checks::run(&parsed)
}

/// Python module entry-point — `import sentinel_tokenizer`
#[pymodule]
fn sentinel_tokenizer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<report::TokenizerFinding>()?;
    m.add_function(wrap_pyfunction!(scan_bytes_py, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}

/// Python-callable: scan raw tokenizer.json bytes → list of findings.
#[pyfunction]
#[pyo3(name = "scan_bytes")]
fn scan_bytes_py(data: &[u8]) -> Vec<report::TokenizerFinding> {
    scan(data)
}
