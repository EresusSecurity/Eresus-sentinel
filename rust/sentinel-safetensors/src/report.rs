// Finding struct exposed to Python via PyO3.

use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, Clone)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[pymethods]
impl Severity {
    fn __str__(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct SafetensorsFinding {
    #[pyo3(get)] pub rule_id:     String,
    #[pyo3(get)] pub severity:    Severity,
    #[pyo3(get)] pub title:       String,
    #[pyo3(get)] pub evidence:    String,
    #[pyo3(get)] pub description: String,
}

#[pymethods]
impl SafetensorsFinding {
    fn __repr__(&self) -> String {
        format!("SafetensorsFinding(rule_id={:?}, title={:?})", self.rule_id, self.title)
    }
}
