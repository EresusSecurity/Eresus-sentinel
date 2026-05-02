// scanner.rs — High-level scan API exposed to Python via PyO3

use pyo3::prelude::*;
use std::fs;

use crate::policy::{PolicyVerdict, ScanPolicy};
use crate::report::{Finding, PickleReport, SafetyVerdict, ScanStatus};
use crate::state::PVMState;
use crate::strings::{
    extract_strings, find_nested_pickle_b64, find_nested_pickle_hex, find_nested_pickle_raw_bytes,
    find_suspicious_strings, find_urls,
};

/// Maximum ratio of SETITEMS/APPENDS/SETITEM opcodes vs total opcodes
/// that is considered indicative of a pickle-expansion (zip-bomb) attack.
const EXPANSION_OPCODE_RATIO: f64 = 0.60;
/// Minimum total opcodes before triggering expansion heuristic.
const EXPANSION_MIN_OPCODES: usize = 500;
/// Maximum post-budget tail bytes to inspect for conservative GLOBAL surfacing.
const POST_BUDGET_TAIL_LIMIT: usize = 128 * 1024;

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

    /// Preferred API: returns a `PickleReport` with status + verdict + findings.
    /// Fail-closed: aborted or budget-exceeded scans yield `verdict=Unknown`.
    pub fn scan_bytes_report(&self, data: &[u8]) -> PickleReport {
        scan_to_report(data, &self.policy)
    }

    /// Preferred API (file): returns a `PickleReport`.
    pub fn scan_file_report(&self, path: &str) -> PyResult<PickleReport> {
        let data = fs::read(path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Failed to read {}: {}", path, e))
        })?;
        Ok(scan_to_report(&data, &self.policy))
    }

    /// Return execution stats for the last scan as a Python dict.
    /// Useful for fuzzing dashboards and CI budget enforcement.
    pub fn scan_bytes_with_stats<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyDict>> {
        let (findings, stats) = scan_data_with_stats(data, &self.policy);
        let dict = pyo3::types::PyDict::new(py);
        let findings_list = pyo3::types::PyList::new(py, findings.iter().map(|f| f.clone()))?;
        dict.set_item("findings", findings_list)?;
        dict.set_item("opcode_count", stats.opcode_count)?;
        dict.set_item("max_stack_depth", stats.max_stack_depth)?;
        dict.set_item("depth_limit_hits", stats.depth_limit_hits)?;
        dict.set_item("tainted_on_stack", stats.tainted_on_stack)?;
        dict.set_item("memo_entries", stats.memo_entries)?;
        dict.set_item("aborted", stats.aborted)?;
        dict.set_item("analyzed_bytes", stats.analyzed_bytes)?;
        dict.set_item("errors", stats.errors)?;
        Ok(dict)
    }
}

pub struct ScanStats {
    pub opcode_count: usize,
    pub max_stack_depth: usize,
    pub depth_limit_hits: usize,
    pub tainted_on_stack: usize,
    pub memo_entries: usize,
    pub aborted: bool,
    pub analyzed_bytes: usize,
    pub errors: Vec<String>,
}

/// Build a `PickleReport` with fail-closed safety semantics.
///
/// Safety invariant: `aborted == true` ⟹ `verdict == Unknown`.
/// This prevents truncation attacks where a budget-exceeded scan
/// falsely appears clean.
pub fn scan_to_report(data: &[u8], policy: &ScanPolicy) -> PickleReport {
    let (mut findings, stats) = scan_data_with_stats(data, policy);

    // Detect expansion (zip-bomb-style amplification) across all states
    if let Some(f) = detect_expansion_raw(data, &stats) {
        findings.push(f);
    }
    findings.extend(detect_post_budget_globals(data, &stats, policy));

    let status = if stats.aborted {
        ScanStatus::Inconclusive
    } else if !stats.errors.is_empty() {
        ScanStatus::Error
    } else {
        ScanStatus::Complete
    };

    // Fail-closed: incomplete scan can never be declared Clean.
    let verdict = if stats.aborted || !stats.errors.is_empty() {
        SafetyVerdict::Unknown
    } else if findings
        .iter()
        .any(|f| f.severity.contains("CRITICAL") || f.rule_id == "PICKLE-EXEC")
    {
        SafetyVerdict::Malicious
    } else if !findings.is_empty() {
        SafetyVerdict::Suspicious
    } else {
        SafetyVerdict::Clean
    };

    PickleReport {
        status,
        verdict,
        findings,
        opcode_count: stats.opcode_count,
        aborted: stats.aborted,
        errors: stats.errors,
    }
}

/// Conservatively surface dangerous GLOBAL opcodes after the scan budget.
///
/// A hostile pickle can spend the opcode budget on benign filler and place the
/// dangerous import just past the scanned prefix. The report is still Unknown,
/// but this finding gives callers concrete evidence to block on.
fn detect_post_budget_globals(data: &[u8], stats: &ScanStats, policy: &ScanPolicy) -> Vec<Finding> {
    if !stats.aborted || stats.analyzed_bytes >= data.len() {
        return Vec::new();
    }

    let tail_end = data
        .len()
        .min(stats.analyzed_bytes + POST_BUDGET_TAIL_LIMIT);
    let tail = &data[stats.analyzed_bytes..tail_end];
    let mut findings = Vec::new();
    let mut i = 0;

    while i < tail.len() {
        if tail[i] != b'c' {
            i += 1;
            continue;
        }

        let module_start = i + 1;
        let Some(module_end_rel) = tail[module_start..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let module_end = module_start + module_end_rel;
        let name_start = module_end + 1;
        let Some(name_end_rel) = tail[name_start..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let name_end = name_start + name_end_rel;

        let module = String::from_utf8_lossy(&tail[module_start..module_end]).to_string();
        let name = String::from_utf8_lossy(&tail[name_start..name_end]).to_string();
        match policy.evaluate_internal(&module, &name) {
            PolicyVerdict::Safe => {}
            verdict => findings.push(Finding {
                rule_id: "POST-BUDGET-GLOBAL".to_string(),
                title: format!("Dangerous GLOBAL after opcode budget: {module}.{name}"),
                description: format!(
                    "A {verdict} GLOBAL opcode was found after the Rust scanner hit its \
                     opcode budget. This is a conservative fail-closed signal."
                ),
                severity: if verdict == PolicyVerdict::Dangerous {
                    "CRITICAL".to_string()
                } else {
                    "HIGH".to_string()
                },
                module_name: module.clone(),
                import_name: name.clone(),
                offset: stats.analyzed_bytes + i,
                opcode: "GLOBAL".to_string(),
                evidence: format!("{module}.{name}"),
                confidence: 0.91,
            }),
        }
        i = name_end + 1;
    }

    findings
}

/// Detect pickle expansion (zip-bomb) attacks by examining raw opcode density.
/// Returns a finding if the ratio of repetitive fill opcodes is above threshold.
fn detect_expansion_raw(data: &[u8], stats: &ScanStats) -> Option<Finding> {
    if stats.opcode_count < EXPANSION_MIN_OPCODES {
        return None;
    }
    // Count SETITEMS (u), APPENDS (e), SETITEM (s), APPEND (a) opcodes
    let fill_count = data
        .iter()
        .filter(|&&b| matches!(b, b'u' | b'e' | b's' | b'a'))
        .count();
    let ratio = fill_count as f64 / stats.opcode_count as f64;
    if ratio >= EXPANSION_OPCODE_RATIO {
        Some(Finding {
            rule_id: "PICKLE-EXPANSION".to_string(),
            title: format!(
                "Pickle expansion attack: {:.0}% fill opcodes ({} / {})",
                ratio * 100.0,
                fill_count,
                stats.opcode_count
            ),
            description: format!(
                "Unusually high ratio of SETITEMS/APPENDS opcodes ({:.1}%) suggests a \
                 zip-bomb-style amplification attack. Deserializing this pickle may \
                 exhaust memory.",
                ratio * 100.0
            ),
            severity: "HIGH".to_string(),
            module_name: String::new(),
            import_name: String::new(),
            offset: 0,
            opcode: "SETITEMS/APPENDS".to_string(),
            evidence: format!(
                "fill_ratio={:.3} fill_opcodes={} total_opcodes={}",
                ratio, fill_count, stats.opcode_count
            ),
            confidence: 0.88,
        })
    } else {
        None
    }
}

/// Convert nested pickle hits from strings module into `Finding` objects.
fn nested_hits_to_findings(
    b64_hits: Vec<crate::strings::NestedPickleHit>,
    hex_hits: Vec<crate::strings::NestedPickleHit>,
    raw_hits: Vec<crate::strings::NestedPickleHit>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for hit in b64_hits.into_iter().chain(hex_hits).chain(raw_hits) {
        out.push(Finding {
            rule_id: hit.rule_id.clone(),
            title: format!("Nested pickle ({}) inside outer stream", hit.encoding),
            description: format!(
                "A {}-encoded pickle payload ({} bytes decoded) was found embedded inside \
                 a string/bytes value in the outer pickle stream. This technique is used to \
                 evade static scanners that only inspect the top-level stream.",
                hit.encoding, hit.decoded_len
            ),
            severity: "CRITICAL".to_string(),
            module_name: String::new(),
            import_name: String::new(),
            offset: hit.offset,
            opcode: "STRING/BYTES".to_string(),
            evidence: hit.value_preview,
            confidence: 0.97,
        });
    }
    out
}

pub fn scan_data(data: &[u8], policy: &ScanPolicy) -> Vec<Finding> {
    scan_data_with_stats(data, policy).0
}

pub fn scan_data_with_stats(data: &[u8], policy: &ScanPolicy) -> (Vec<Finding>, ScanStats) {
    let mut findings = Vec::new();
    let mut agg = ScanStats {
        opcode_count: 0,
        max_stack_depth: 0,
        depth_limit_hits: 0,
        tainted_on_stack: 0,
        memo_entries: 0,
        aborted: false,
        analyzed_bytes: 0,
        errors: Vec::new(),
    };

    let streams = locate_pickle_streams(data);
    if streams.is_empty() {
        let mut state = PVMState::new();
        state.execute(data);
        findings.extend(evaluate_state(&state, policy));
        agg.opcode_count += state.opcode_count;
        agg.max_stack_depth = agg.max_stack_depth.max(state.max_stack_depth);
        agg.depth_limit_hits += state.depth_limit_hits;
        agg.tainted_on_stack = state.tainted_on_stack;
        agg.memo_entries = state.memo.len();
        agg.aborted = agg.aborted || state.aborted;
        agg.analyzed_bytes = agg.analyzed_bytes.max(state.offset);
        agg.errors.extend(state.errors);
        return (findings, agg);
    }

    for (start, end) in streams {
        let mut state = PVMState::new();
        state.execute(&data[start..end]);
        findings.extend(evaluate_state(&state, policy));
        agg.opcode_count += state.opcode_count;
        agg.max_stack_depth = agg.max_stack_depth.max(state.max_stack_depth);
        agg.depth_limit_hits += state.depth_limit_hits;
        agg.tainted_on_stack = state.tainted_on_stack;
        agg.memo_entries = agg.memo_entries.max(state.memo.len());
        agg.aborted = agg.aborted || state.aborted;
        agg.analyzed_bytes = agg.analyzed_bytes.max(start + state.offset);
        agg.errors.extend(state.errors);
    }

    (findings, agg)
}

fn evaluate_state(state: &PVMState, policy: &ScanPolicy) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(finding) = structural_tamper_finding(state) {
        findings.push(finding);
    }

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

    // Nested pickle detection: S601 (base64), S602 (hex), S213 (raw bytes)
    let b64_hits = find_nested_pickle_b64(&strings);
    let hex_hits = find_nested_pickle_hex(&strings);
    let raw_hits = find_nested_pickle_raw_bytes(state);
    findings.extend(nested_hits_to_findings(b64_hits, hex_hits, raw_hits));

    findings
}

fn structural_tamper_finding(state: &PVMState) -> Option<Finding> {
    if state.errors.is_empty() && state.depth_limit_hits == 0 && state.mark_stack.is_empty() {
        return None;
    }

    let evidence = if let Some(first_error) = state.errors.first() {
        first_error.clone()
    } else if state.depth_limit_hits > 0 {
        format!("stack_depth_limit_hits={}", state.depth_limit_hits)
    } else {
        format!("unclosed_mark_count={}", state.mark_stack.len())
    };

    Some(Finding {
        rule_id: "STRUCTURAL-TAMPER".to_string(),
        title: "Structurally suspicious pickle opcode stream".to_string(),
        description: "The opcode stream contains malformed, unbalanced, or producer-unusual structure that a normal pickle writer should not emit.".to_string(),
        severity: "HIGH".to_string(),
        module_name: String::new(),
        import_name: String::new(),
        offset: state.offset,
        opcode: "STRUCTURAL".to_string(),
        evidence,
        confidence: 0.82,
    })
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
        data.push(0x8c);
        data.push(11);
        data.extend_from_slice(b"numpy.core");
        data.push(0x8c);
        data.push(12);
        data.extend_from_slice(b"_reconstruct");
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

    #[test]
    fn test_report_clean_for_complete_safe_pickle() {
        let policy = ScanPolicy::new(false);
        let report = scan_to_report(b"\x80\x04N.", &policy);

        assert_eq!(report.status, ScanStatus::Complete);
        assert_eq!(report.verdict, SafetyVerdict::Clean);
        assert!(!report.aborted);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_fail_closed_on_opcode_budget_exhaustion() {
        let policy = ScanPolicy::new(false);
        let data = vec![b'0'; crate::state::MAX_OPCODE_COUNT + 16];

        let report = scan_to_report(&data, &policy);

        assert!(report.aborted);
        assert_eq!(report.status, ScanStatus::Inconclusive);
        assert_eq!(report.verdict, SafetyVerdict::Unknown);
        assert_ne!(report.verdict, SafetyVerdict::Clean);
    }

    #[test]
    fn test_post_budget_global_is_surfaced() {
        let policy = ScanPolicy::new(false);
        let mut data = vec![b'0'; crate::state::MAX_OPCODE_COUNT];
        data.extend_from_slice(b"cos\nsystem\n.");

        let report = scan_to_report(&data, &policy);

        assert_eq!(report.verdict, SafetyVerdict::Unknown);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "POST-BUDGET-GLOBAL"));
    }

    #[test]
    fn test_expansion_opcode_density_is_reported() {
        let policy = ScanPolicy::new(false);
        let data = vec![b'a'; 600];

        let report = scan_to_report(&data, &policy);

        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "PICKLE-EXPANSION"));
    }

    #[test]
    fn test_nested_pickle_payloads_are_reported() {
        let policy = ScanPolicy::new(false);
        let b64 = b"\x80\x04\x8c\x08gAROLg==.";
        let hex = b"\x80\x04\x8c\x0880044e2e.";
        let raw = b"\x80\x04C\x04\x80\x04N..";

        let b64_report = scan_to_report(b64, &policy);
        let hex_report = scan_to_report(hex, &policy);
        let raw_report = scan_to_report(raw, &policy);

        assert!(b64_report.findings.iter().any(|f| f.rule_id == "S601"));
        assert!(hex_report.findings.iter().any(|f| f.rule_id == "S602"));
        assert!(raw_report.findings.iter().any(|f| f.rule_id == "S213"));
    }

    #[test]
    fn test_structural_tamper_is_reported() {
        let policy = ScanPolicy::new(false);
        let report = scan_to_report(b"\xff.", &policy);

        assert_eq!(report.status, ScanStatus::Error);
        assert_eq!(report.verdict, SafetyVerdict::Unknown);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "STRUCTURAL-TAMPER"));
    }
}
