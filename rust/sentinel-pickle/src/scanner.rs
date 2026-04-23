// scanner.rs — High-level scan API exposed to Python via PyO3

use pyo3::prelude::*;
use std::fs;

use crate::policy::{ScanPolicy, PolicyVerdict};
use crate::report::Finding;
use crate::state::PVMState;
use crate::strings::{extract_strings, find_urls, find_ips, find_suspicious_strings};

#[pyclass]
pub struct PickleScanner {
    policy: ScanPolicy,
}

#[pymethods]
impl PickleScanner {
    #[new]
    #[pyo3(signature = (strict_mode=false))]
    pub fn new(strict_mode: bool) -> Self {
        Self {
            policy: ScanPolicy::new(strict_mode),
        }
    }

    pub fn allow(&mut self, module: &str, name: &str) {
        self.policy.allow(module, name);
    }

    pub fn block(&mut self, module: &str, name: &str) {
        self.policy.block(module, name);
    }

    pub fn allow_module(&mut self, module: &str) {
        self.policy.allow_module(module);
    }

    pub fn block_module(&mut self, module: &str) {
        self.policy.block_module(module);
    }

    pub fn scan_bytes_py(&self, data: &[u8]) -> Vec<Finding> {
        scan_data(data, &self.policy)
    }

    pub fn scan_file_py(&self, path: &str) -> PyResult<Vec<Finding>> {
        let data = fs::read(path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Failed to read {}: {}", path, e))
        })?;
        Ok(scan_data(&data, &self.policy))
    }
}

pub fn scan_data(data: &[u8], policy: &ScanPolicy) -> Vec<Finding> {
    let mut findings = Vec::new();

    let streams = locate_pickle_streams(data);
    if streams.is_empty() {
        let mut state = PVMState::new();
        state.execute(data);
        findings.extend(evaluate_state(&state, policy));
        return findings;
    }

    for (start, end) in streams {
        let mut state = PVMState::new();
        state.execute(&data[start..end]);
        findings.extend(evaluate_state(&state, policy));
    }

    findings
}

fn evaluate_state(state: &PVMState, policy: &ScanPolicy) -> Vec<Finding> {
    let mut findings = Vec::new();

    for gref in &state.global_refs {
        let verdict = policy.evaluate_internal(&gref.module, &gref.name);
        match verdict {
            PolicyVerdict::Safe => {}
            _ => {
                findings.push(Finding::from_global_ref(
                    &gref.module,
                    &gref.name,
                    gref.offset,
                    gref.opcode.name(),
                    &verdict,
                ));
            }
        }
    }

    let strings = extract_strings(state);

    for url_str in find_urls(&strings) {
        findings.push(Finding::from_url(&url_str.value, url_str.offset));
    }

    for sus in find_suspicious_strings(&strings) {
        findings.push(Finding::from_suspicious_string(&sus.value, sus.offset));
    }

    findings
}

fn locate_pickle_streams(data: &[u8]) -> Vec<(usize, usize)> {
    let mut streams = Vec::new();

    // Look for protocol markers (0x80 followed by version 1-5)
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0x80 && i + 1 < data.len() && data[i + 1] <= 5 {
            let start = i;
            // Scan for STOP opcode
            let mut j = i + 2;
            while j < data.len() {
                if data[j] == b'.' {
                    streams.push((start, j + 1));
                    i = j + 1;
                    break;
                }
                j += 1;
            }
            if j >= data.len() {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    streams
}

#[pyfunction]
pub fn scan_bytes(data: &[u8], strict: bool) -> Vec<Finding> {
    let policy = ScanPolicy::new(strict);
    scan_data(data, &policy)
}

#[pyfunction]
pub fn scan_file(path: &str, strict: bool) -> PyResult<Vec<Finding>> {
    let data = fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to read {}: {}", path, e))
    })?;
    Ok(scan_data(&data, &ScanPolicy::new(strict)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_dangerous_pickle() {
        // cos\nsystem\n(S'echo hello'\ntR.
        let data = b"cos\nsystem\n(S'echo hello'\ntR.";
        let findings = scan_bytes(data, false);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "PICKLE-EXEC"));
    }

    #[test]
    fn test_scan_safe_pickle() {
        // Protocol 4 with numpy array reconstruction
        let mut data = vec![0x80, 0x04]; // proto 4
        data.push(0x95); // FRAME
        data.extend_from_slice(&[30u8, 0, 0, 0, 0, 0, 0, 0]);
        data.push(0x8c); data.push(11); data.extend_from_slice(b"numpy.core");
        data.push(0x8c); data.push(12); data.extend_from_slice(b"_reconstruct");
        data.push(0x93); // STACK_GLOBAL
        data.push(b'.'); // STOP

        let findings = scan_bytes(&data, false);
        // numpy should be safe in non-strict mode
        assert!(findings.iter().all(|f| f.rule_id != "PICKLE-EXEC"));
    }

    #[test]
    fn test_locate_pickle_streams() {
        let mut data = vec![0x00; 100];
        // Insert a pickle stream at offset 20
        data[20] = 0x80;
        data[21] = 0x04;
        data[22] = b'N'; // NONE
        data[23] = b'.'; // STOP
        let streams = locate_pickle_streams(&data);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0], (20, 24));
    }
}
