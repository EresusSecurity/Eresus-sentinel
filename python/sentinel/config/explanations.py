"""
Human-readable finding explanations — maps rule IDs to description, remediation, and references.
"""

from __future__ import annotations

from typing import Optional

_EXPLANATIONS: dict[str, dict] = {
    # Artifact scanner
    "ARTIFACT-001": {"desc": "Pickle contains a dangerous GLOBAL opcode importing a known-malicious module.", "fix": "Use SafeTensors or scan with --strict mode. Do not load untrusted pickles.", "refs": ["https://blog.trailofbits.com/2021/03/15/never-a-dull-moment-when-you-pickle/"]},
    "ARTIFACT-002": {"desc": "Pickle REDUCE opcode executes arbitrary callable after GLOBAL import.", "fix": "Reject pickles with REDUCE+GLOBAL from untrusted sources.", "refs": ["CVE-2022-45907"]},
    # Opcode sequence
    "OPSEQ-001": {"desc": "Dangerous standalone opcode (e.g., INST) found — can import+call in one step.", "fix": "Avoid using pickle protocol 0/1 INST opcode from untrusted sources."},
    "OPSEQ-002": {"desc": "Dangerous opcode sequence detected (e.g., GLOBAL+REDUCE) indicating code execution.", "fix": "Use SafeTensors. If pickle is required, scan with Sentinel before loading."},
    # Entropy
    "ENTROPY-001": {"desc": "File has near-maximum entropy (>7.9/8.0), suggesting encrypted or compressed payload.", "fix": "Investigate contents — encrypted payloads may hide malicious code."},
    "ENTROPY-002": {"desc": "File has very low entropy (<0.5), suggesting zeroed/corrupted data.", "fix": "Verify file integrity — may indicate tampering."},
    # Pattern
    "PATTERN-001": {"desc": "Dangerous code pattern found in model file (eval, exec, subprocess, etc.).", "fix": "Remove or isolate the file. Model files should not contain executable code."},
    # Anomaly
    "ANOMALY-001": {"desc": "Execution opcodes (GLOBAL, REDUCE, INST, NEWOBJ) make up an unusually high fraction of the file.", "fix": "This is a strong indicator of a weaponized pickle. Do not load."},
    "ANOMALY-002": {"desc": "Opcode distribution differs significantly from known-good ML model baselines.", "fix": "Inspect manually. This may be a non-standard or hand-crafted pickle."},
    "ANOMALY-003": {"desc": "Near-maximum byte entropy suggests encrypted or random data in pickle.", "fix": "Encrypted payloads may hide malware. Investigate before loading."},
    "ANOMALY-004": {"desc": "REDUCE/NEWOBJ count greatly exceeds GLOBAL references, unusual for ML models.", "fix": "Likely a code-execution pickle, not a model. Do not load."},
    # Symbol
    "SYMBOL-001": {"desc": "Blocked dangerous function (e.g., os.system, subprocess.Popen) in pickle GLOBAL.", "fix": "Reject this file immediately. This is a confirmed malicious pickle."},
    "SYMBOL-002": {"desc": "Blocked module imported in pickle GLOBAL.", "fix": "Reject the file. Dangerous module should never appear in model pickles."},
    "SYMBOL-003": {"desc": "Unknown module in pickle GLOBAL — not in any ML framework safe list.", "fix": "Manually verify the module is safe before loading."},
    # Deception
    "DECEPTION-JAIL-001": {"desc": "Jailbreak attempt: instruction override pattern detected.", "fix": "Query was flagged by the deception guardrail. DECEIVE or BLOCK action taken."},
    # Network
    "NET-001": {"desc": "URL found in model file that is not a known-safe ML domain.", "fix": "Verify the URL is expected. Unexpected URLs may indicate C2 or exfiltration."},
    "NET-002": {"desc": "IP address found in model file.", "fix": "Model files should not contain hardcoded IPs."},
    "NET-003": {"desc": "Network communication API (socket, urllib, http) found in model.", "fix": "Model files should never contain network code. Reject the file."},
    # JIT
    "JIT-001": {"desc": "Dangerous TorchScript/JIT operation found that may execute arbitrary code.", "fix": "Review JIT ops carefully. PythonOp and CallFunction can run arbitrary code."},
    # GGUF
    "GGUF-001": {"desc": "GGUF header tensor count overflow — possibly crafted to trigger buffer overflow.", "fix": "Reject malformed GGUF files."},
    # Firewall
    "FIREWALL-INPUT-001": {"desc": "Prompt injection detected in user input.", "fix": "Block or sanitize the input before forwarding to the LLM."},
    "FIREWALL-OUTPUT-001": {"desc": "Sensitive data detected in LLM output.", "fix": "Redact sensitive content before returning to the user."},
}


def explain(rule_id: str) -> Optional[dict]:
    """Get human-readable explanation for a rule ID.

    Returns dict with keys: desc, fix, refs (optional), or None if unknown.
    """
    return _EXPLANATIONS.get(rule_id)


def explain_finding(finding) -> str:
    """Return a formatted explanation string for a Finding object."""
    rule_id = getattr(finding, "rule_id", "")
    info = _EXPLANATIONS.get(rule_id)
    if not info:
        return f"[{rule_id}] No additional explanation available."
    parts = [f"[{rule_id}] {info['desc']}"]
    if "fix" in info:
        parts.append(f"  Remediation: {info['fix']}")
    if "refs" in info:
        parts.append(f"  References: {', '.join(info['refs'])}")
    return "\n".join(parts)


def all_rule_ids() -> list[str]:
    """Return all known rule IDs."""
    return sorted(_EXPLANATIONS.keys())
