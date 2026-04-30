// report.rs — Finding type for tokenizer scanner

use pyo3::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Info     => write!(f, "INFO"),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct TokenizerFinding {
    #[pyo3(get)]
    pub rule_id: String,

    pub severity: Severity,

    #[pyo3(get)]
    pub title: String,

    #[pyo3(get)]
    pub evidence: String,

    #[pyo3(get)]
    pub description: String,

    #[pyo3(get)]
    pub confidence: f64,
}

#[pymethods]
impl TokenizerFinding {
    #[getter]
    fn severity_str(&self) -> String {
        self.severity.to_string()
    }

    fn __repr__(&self) -> String {
        format!(
            "TokenizerFinding(rule_id='{}', severity='{}', title='{}')",
            self.rule_id, self.severity, self.title
        )
    }
}
