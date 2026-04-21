"""
Eresus Sentinel — Production-grade AI/LLM Security Platform
Part of the Eresus Security Ecosystem

Modules:
    artifact          — 24 model artifact scanners (pickle/torch/safetensors/GGUF/ONNX/TFLite...)
    firewall.input    — 22 input guardrails + 4 layered defense (injection, secrets, PII, encoding, prompt leak...)
    firewall.output   — 24 output guardrails (toxicity, bias, compliance, copyright, watermark...)
    redteam           — 48 attack probes + 13 detectors + 14 generators + evaluator + orchestrator
    agent             — Agent/MCP security validation (trust map, permissions)
    supply_chain      — ML supply chain auditing (provenance, dependency, HF scanner)
    notebook_scanner  — Jupyter notebook security scanning (14 plugins)
    diff_scanner      — Git diff/PR ML security anti-pattern detection
    ai                — AI-assisted reasoning layer
    policy            — YAML-driven policy engine with auto-discovery
    audit             — Structured JSONL audit logger with query/export
    metrics           — Prometheus/OpenTelemetry metrics collector with alerts
    cost_guard        — LLM cost tracking, budget enforcement, anomaly detection
    vault             — Secure PII redaction & restoration vault (Fernet encryption)
    evaluator         — Scanner effectiveness measurement (precision/recall/F1)
    hf_guard          — HuggingFace pre-download security guard
    _plugins          — Auto-discovery engine for scanner plugins
    sdk               — Python SDK (one-liner integration, SARIF export)
    server            — FastAPI REST API (batch scan, k8s probes)
    middleware        — LangChain/OpenAI/Generic LLM middleware (async support)
    data              — 8 externalized YAML pattern databases
    data_loader       — YAML loader with schema validation & integrity checks
    finding           — Universal finding model with dedup fingerprints
    mcp_proxy         — Live MCP intercepting proxy (stdio/HTTP, behavioral+OPA inspection)
    sast.secrets      — Enterprise secrets scanner (120+ patterns, entropy, git history)
    redteam.playbook  — YAML-driven attack playbook engine (SARIF/HTML reports)
    supply_chain.live — Live dependency scanner (OSV.dev, typosquatting, confusion)

Quick Start:
    from sentinel import Sentinel
    s = Sentinel()
    result = s.scan_input("user prompt here")
    result = s.scan_output("prompt", "llm response")
"""

__version__ = "0.1.0"
__author__ = "Eresus Security"
__license__ = "Proprietary"

__all__ = [
    # Core SDK
    "Sentinel",
    # Data models
    "Finding",
    "Severity",
    "ScanResult",
    "ScanAction",
    # Modules
    "AuditLogger",
    "MetricsCollector",
    "CostGuard",
    "Vault",
    "HFGuard",
    "ScannerEvaluator",
    # Enterprise Hardening
    "MCPProxy",
    "SecretsScanner",
    "PlaybookEngine",
    "LiveDependencyScanner",
    # Middleware
    "SentinelMiddleware",
    "SentinelOpenAIWrapper",
    "SentinelLangChainHandler",
    "sentinel_guard",
    # Utilities
    "merge_findings",
]


def __getattr__(name: str):
    """Lazy imports for convenience — avoids loading everything at import time."""
    _lazy_map = {
        "Sentinel": "sentinel.sdk",
        "Finding": "sentinel.finding",
        "Severity": "sentinel.finding",
        "merge_findings": "sentinel.finding",
        "ScanResult": "sentinel.firewall.base",
        "ScanAction": "sentinel.firewall.base",
        "AuditLogger": "sentinel.audit",
        "MetricsCollector": "sentinel.metrics",
        "CostGuard": "sentinel.cost_guard",
        "Vault": "sentinel.vault",
        "HFGuard": "sentinel.hf_guard",
        "ScannerEvaluator": "sentinel.evaluator",
        "MCPProxy": "sentinel.mcp_proxy",
        "SecretsScanner": "sentinel.sast.secrets_scanner",
        "PlaybookEngine": "sentinel.redteam.playbook_engine",
        "LiveDependencyScanner": "sentinel.supply_chain.live_scanner",
        "SentinelMiddleware": "sentinel.middleware",
        "SentinelOpenAIWrapper": "sentinel.middleware",
        "SentinelLangChainHandler": "sentinel.middleware",
        "sentinel_guard": "sentinel.middleware",
    }
    if name in _lazy_map:
        import importlib
        module = importlib.import_module(_lazy_map[name])
        return getattr(module, name)
    raise AttributeError(f"module 'sentinel' has no attribute {name!r}")


