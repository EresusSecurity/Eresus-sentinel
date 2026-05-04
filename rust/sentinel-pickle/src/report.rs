// report.rs — Finding generation exposed to Python via PyO3

use crate::opcode::Severity;
use crate::policy::PolicyVerdict;
use pyo3::prelude::*;

/// Indicates whether the scanner consumed the entire pickle stream.
#[pyclass(eq, eq_int)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    /// All opcodes were processed within the budget.
    Complete,
    /// The opcode budget or recursion limit was hit; analysis is partial.
    Inconclusive,
    /// A hard error prevented scanning (I/O failure, malformed framing).
    Error,
}

#[pymethods]
impl ScanStatus {
    pub fn __str__(&self) -> &'static str {
        match self {
            ScanStatus::Complete => "complete",
            ScanStatus::Inconclusive => "inconclusive",
            ScanStatus::Error => "error",
        }
    }
}

/// The safety verdict produced by policy evaluation.
///
/// **Invariant**: if `ScanStatus` is `Inconclusive` or `Error`,
/// the verdict MUST be `Unknown` — never `Clean`.
#[pyclass(eq, eq_int)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    /// No dangerous or suspicious globals found in a complete scan.
    Clean,
    /// One or more suspicious (but not definitively dangerous) globals found.
    Suspicious,
    /// One or more definitively dangerous globals (e.g. os.system) found.
    Malicious,
    /// Scan was incomplete (budget/error); cleanliness cannot be asserted.
    Unknown,
}

#[pymethods]
impl SafetyVerdict {
    pub fn __str__(&self) -> &'static str {
        match self {
            SafetyVerdict::Clean => "clean",
            SafetyVerdict::Suspicious => "suspicious",
            SafetyVerdict::Malicious => "malicious",
            SafetyVerdict::Unknown => "unknown",
        }
    }
}

/// Top-level result returned by the scanner to Python callers.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PickleReport {
    #[pyo3(get)]
    pub status: ScanStatus,
    #[pyo3(get)]
    pub verdict: SafetyVerdict,
    #[pyo3(get)]
    pub findings: Vec<Finding>,
    #[pyo3(get)]
    pub opcode_count: usize,
    #[pyo3(get)]
    pub aborted: bool,
    #[pyo3(get)]
    pub errors: Vec<String>,
}

#[pymethods]
impl PickleReport {
    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("status", self.status.__str__())?;
        dict.set_item("verdict", self.verdict.__str__())?;
        dict.set_item("aborted", self.aborted)?;
        dict.set_item("opcode_count", self.opcode_count)?;
        dict.set_item("errors", &self.errors)?;
        let findings_list: Vec<PyObject> = self
            .findings
            .iter()
            .map(|f| f.to_dict(py))
            .collect::<PyResult<Vec<_>>>()?;
        dict.set_item("findings", findings_list)?;
        Ok(dict.into())
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct Finding {
    #[pyo3(get)]
    pub rule_id: String,
    #[pyo3(get)]
    pub title: String,
    #[pyo3(get)]
    pub description: String,
    #[pyo3(get)]
    pub severity: String,
    #[pyo3(get)]
    pub module_name: String,
    #[pyo3(get)]
    pub import_name: String,
    #[pyo3(get)]
    pub offset: usize,
    #[pyo3(get)]
    pub opcode: String,
    #[pyo3(get)]
    pub evidence: String,
    #[pyo3(get)]
    pub confidence: f64,
}

#[pymethods]
impl Finding {
    #[new]
    #[pyo3(signature = (rule_id, title, description, severity, module_name, import_name, offset, opcode, evidence, confidence=0.95))]
    pub fn new(
        rule_id: String,
        title: String,
        description: String,
        severity: String,
        module_name: String,
        import_name: String,
        offset: usize,
        opcode: String,
        evidence: String,
        confidence: f64,
    ) -> Self {
        Self {
            rule_id,
            title,
            description,
            severity,
            module_name,
            import_name,
            offset,
            opcode,
            evidence,
            confidence,
        }
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("rule_id", &self.rule_id)?;
        dict.set_item("title", &self.title)?;
        dict.set_item("description", &self.description)?;
        dict.set_item("severity", &self.severity)?;
        dict.set_item("module_name", &self.module_name)?;
        dict.set_item("import_name", &self.import_name)?;
        dict.set_item("offset", self.offset)?;
        dict.set_item("opcode", &self.opcode)?;
        dict.set_item("evidence", &self.evidence)?;
        dict.set_item("confidence", self.confidence)?;
        Ok(dict.into())
    }
}

impl Finding {
    pub fn from_global_ref(
        module: &str,
        name: &str,
        offset: usize,
        opcode_name: &str,
        verdict: &PolicyVerdict,
    ) -> Self {
        let (rule_id, severity, confidence) = match verdict {
            PolicyVerdict::Dangerous => ("PICKLE-EXEC", Severity::Critical, 0.99),
            PolicyVerdict::Suspicious => ("PICKLE-SUS", Severity::High, 0.85),
            PolicyVerdict::Unknown => ("PICKLE-UNK", Severity::Medium, 0.7),
            PolicyVerdict::Safe => ("PICKLE-SAFE", Severity::Info, 1.0),
        };

        Self {
            rule_id: rule_id.to_string(),
            title: format!("Pickle {} import: {}.{}", verdict, module, name),
            description: format!(
                "Pickle opcode {} at offset 0x{:x} resolves {}.{} — classified as {}",
                opcode_name, offset, module, name, verdict
            ),
            severity: severity.to_string(),
            module_name: module.to_string(),
            import_name: name.to_string(),
            offset,
            opcode: opcode_name.to_string(),
            evidence: format!("{}\\n{}.{}", opcode_name, module, name),
            confidence,
        }
    }

    pub fn from_url(url: &str, offset: usize) -> Self {
        Self {
            rule_id: "PICKLE-URL".to_string(),
            title: format!(
                "URL embedded in pickle stream: {}",
                &url[..url.len().min(60)]
            ),
            description: format!("Embedded URL found in pickle data: {}", url),
            severity: Severity::High.to_string(),
            module_name: String::new(),
            import_name: String::new(),
            offset,
            opcode: "STRING".to_string(),
            evidence: url.to_string(),
            confidence: 0.9,
        }
    }

    pub fn from_suspicious_string(s: &str, offset: usize) -> Self {
        Self {
            rule_id: "PICKLE-SUS-STR".to_string(),
            title: format!("Suspicious string in pickle: {}", &s[..s.len().min(40)]),
            description: format!(
                "Potentially malicious string literal found: {}",
                &s[..s.len().min(120)]
            ),
            severity: Severity::Medium.to_string(),
            module_name: String::new(),
            import_name: String::new(),
            offset,
            opcode: "STRING".to_string(),
            evidence: s[..s.len().min(256)].to_string(),
            confidence: 0.75,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_finding() {
        let f = Finding::from_global_ref("os", "system", 42, "GLOBAL", &PolicyVerdict::Dangerous);
        assert_eq!(f.rule_id, "PICKLE-EXEC");
        assert!(f.severity.contains("CRITICAL"));
        assert!(f.confidence > 0.95);
    }

    #[test]
    fn test_url_finding() {
        let f = Finding::from_url("https://evil.com/backdoor.py", 100);
        assert_eq!(f.rule_id, "PICKLE-URL");
    }
}
