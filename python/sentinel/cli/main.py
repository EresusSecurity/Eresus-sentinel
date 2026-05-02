"""
Eresus Sentinel CLI — main entry point.

Usage:
    sentinel scan ./project/
    sentinel firewall "prompt text"
    sentinel firewall -d output "response"
    sentinel dashboard
    sentinel shell
    sentinel scanners
    sentinel version
"""

from __future__ import annotations

import argparse
import sys
from contextlib import redirect_stdout

from sentinel.cli._helpers import console, err, set_machine_stdout


def main():
    from sentinel import __version__ as ver

    _BANNER = f"""\
[red]╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸[/red]
[bold white]  ERESUS SENTINEL[/bold white]  [dim]v{ver}[/dim]
[dim]  AI/LLM Security Platform[/dim]
[red]╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸[/red]"""

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"sentinel — AI/LLM security scanner v{ver}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sentinel scan ./project/\n"
            "  sentinel firewall 'ignore all previous instructions'\n"
            "  sentinel firewall -d output 'some response'\n"
            "  sentinel dashboard\n"
            "  sentinel artifact ./models/ --show-skipped\n"
            "  sentinel hf-artifact org/model-name\n"
            "  sentinel hf-scan org/model-name\n"
            "  sentinel shell\n"
            "  sentinel scanners\n"
            "  sentinel benchmark -n 5\n"
            "  sentinel scan ./p -f sarif -o report.sarif\n"
            "  sentinel scan ./p -f html -o report.html\n"
            "  echo 'test' | sentinel firewall -\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"sentinel {ver}")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    output_formats = ["table", "json", "sarif", "csv", "markdown", "html", "junit"]
    parser.add_argument("-f", "--format", choices=output_formats, default="table")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("--show-skipped", action="store_true", help="show files skipped due to unsupported format")
    parser.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="minimum severity to report")

    sub = parser.add_subparsers(dest="command")

    def _add_output_args(p, *, formats=None, severity=True):
        """Register -f/--format, -o/--output, --min-severity on a subparser."""
        fmts = formats or output_formats
        p.add_argument("-f", "--format", choices=fmts, default=argparse.SUPPRESS)
        p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
        if severity:
            p.add_argument(
                "--min-severity",
                choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                default=argparse.SUPPRESS,
            )

    # ── Scan commands ──────────────────────────────────────────────
    from sentinel.cli.cmd_scan import (
        cmd_artifact_entry,
        cmd_artifact_scan,
        cmd_firewall,
        cmd_hf_artifact,
        cmd_hf_bulk_scan,
        cmd_hf_guard,
        cmd_hf_scan,
        cmd_scan,
    )

    p = sub.add_parser("scan", help="full scan")
    p.add_argument("path")
    p.add_argument("-f", "--format", choices=output_formats, default=argparse.SUPPRESS)
    p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    p.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=argparse.SUPPRESS,
    )
    p.add_argument(
        "--fail-on",
        choices=[
            "info", "low", "medium", "high", "critical",
            "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
        ],
    )
    p.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: keep output machine-compatible and use --fail-on for exit policy",
    )
    p.add_argument(
        "--fast",
        action="store_true",
        help="Skip slow modules (artifact, supply-chain, redteam); run only SAST + secrets",
    )
    p.add_argument(
        "--stdin-files",
        action="store_true",
        help="Read additional file paths from stdin (one per line) — for pre-commit use",
    )
    p.add_argument(
        "--plan",
        dest="explain_plan",
        action="store_true",
        help="Alias for --explain-plan; show scanner plan without running",
    )
    p.add_argument(
        "--explain-plan",
        action="store_true",
        help="Show which scanners will run without actually scanning",
    )
    p.add_argument(
        "--profile",
        choices=["fast", "balanced", "deep", "paranoid"],
        help="Scan depth profile: fast=SAST+secrets, balanced=default, deep=+redteam, paranoid=+fuzz",
    )
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("firewall", aliases=["fw"], help="firewall scan")
    p.add_argument("input", help="text or - for stdin")
    p.add_argument("-d", "--direction", choices=["input", "output"], default="input")
    _add_output_args(p)
    p.set_defaults(func=cmd_firewall)

    p = sub.add_parser(
        "artifact",
        help="model artifact scan",
        description=(
            "model artifact scan\n\n"
            "examples:\n"
            "  sentinel artifact ./models\n"
            "  sentinel artifact scan ./models --dry-run -f json\n"
            "  sentinel artifact scan --list-scanners -f json\n"
            "  sentinel artifact metadata model.pt -f json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("artifact_args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_artifact_entry)

    # ── Pre-commit hook: artifact-scan (accepts multiple staged files) ──
    p = sub.add_parser(
        "artifact-scan",
        help="scan staged model files — for pre-commit pass_filenames: true",
    )
    p.add_argument("files", nargs="+", metavar="FILE", help="staged file paths")
    p.add_argument(
        "--fail-on",
        default="critical",
        choices=["info", "low", "medium", "high", "critical"],
        help="minimum severity that causes exit 1 (default: critical)",
    )
    p.set_defaults(func=cmd_artifact_scan)

    p = sub.add_parser("hf-artifact", help="scan model artifacts from HuggingFace repo")
    p.add_argument("hf_repo", help="HuggingFace repo (e.g. org/model-name)")
    _add_output_args(p)
    p.set_defaults(func=cmd_hf_artifact)

    p = sub.add_parser("hf-scan", help="scan HuggingFace model repo")
    p.add_argument("repo", help="HuggingFace repo (e.g. org/model)")
    _add_output_args(p)
    p.set_defaults(func=cmd_hf_scan)

    p = sub.add_parser("hf-guard", help="pre-download HF repo assessment")
    p.add_argument("repo", help="HuggingFace repo (e.g. org/model)")
    p.add_argument("--deep", action="store_true", help="download and deep-scan files")
    p.add_argument("--block-pickle", action="store_true", help="block repos with pickle files")
    p.add_argument("--require-safetensors", action="store_true", help="require safetensors format")
    p.add_argument("--offline", action="store_true", help="skip HuggingFace Hub network calls")
    _add_output_args(p)
    p.set_defaults(func=cmd_hf_guard)

    p = sub.add_parser("hf-bulk-scan", help="bulk scan HuggingFace Hub repositories")
    p.add_argument("--owner", help="filter by HF username/organisation")
    p.add_argument("--task", help="filter by pipeline task (e.g. text-generation)")
    p.add_argument("--tags", nargs="+", metavar="TAG", help="filter by model tags")
    p.add_argument("--limit", type=int, default=1000, help="max repos to scan (default: 1000)")
    p.add_argument("--min-downloads", type=int, default=0, dest="min_downloads",
                   help="minimum download count filter")
    p.add_argument("--mode", choices=["guard", "full"], default="guard",
                   help="scan mode: guard (no download) or full (default: guard)")
    p.add_argument("--concurrency", type=int, default=4, help="parallel scans (default: 4)")
    p.add_argument("--output", "-o", help="JSONL output file for results")
    p.add_argument("--resume", action="store_true", help="skip repos already in output file")
    p.set_defaults(func=cmd_hf_bulk_scan)

    # ── Analysis commands ──────────────────────────────────────────
    from sentinel.cli.cmd_analysis import (
        cmd_a2a,
        cmd_agent,
        cmd_diff,
        cmd_mcp,
        cmd_mcp_fingerprint,
        cmd_mcp_validate,
        cmd_multi_agent_scan,
        cmd_notebook,
        cmd_redteam,
        cmd_sast,
        cmd_secrets_scan,
        cmd_skill_scan,
        cmd_supply_chain,
    )

    p = sub.add_parser("sast", help="static analysis")
    p.add_argument("path")
    _add_output_args(p)
    p.set_defaults(func=cmd_sast)

    p = sub.add_parser("agent", help="agent/mcp validation")
    p.add_argument("path")
    _add_output_args(p)
    p.set_defaults(func=cmd_agent)

    # ── Pre-commit hook: skill-scan ────────────────────────────────────
    p = sub.add_parser(
        "skill-scan",
        help="audit SKILL.md / plugin manifests — for pre-commit pass_filenames: true",
    )
    p.add_argument("files", nargs="*", metavar="FILE")
    p.add_argument(
        "--fail-on",
        default="critical",
        choices=["info", "low", "medium", "high", "critical"],
    )
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="return clean when pre-commit passes no matching files",
    )
    _add_output_args(p)
    p.set_defaults(func=cmd_skill_scan)

    # ── Pre-commit hook: mcp-validate ──────────────────────────────────
    p = sub.add_parser(
        "mcp-validate",
        help="validate MCP tool manifests — for pre-commit pass_filenames: true",
    )
    p.add_argument("files", nargs="*", metavar="FILE")
    p.add_argument(
        "--fail-on",
        default="high",
        choices=["info", "low", "medium", "high", "critical"],
    )
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="return clean when pre-commit passes no matching files",
    )
    _add_output_args(p)
    p.set_defaults(func=cmd_mcp_validate)

    mcp_p = sub.add_parser("mcp", help="MCP live and manifest scanning")
    mcp_sub = mcp_p.add_subparsers(dest="mcp_action")
    mcp_p.set_defaults(func=cmd_mcp)
    ms = mcp_sub.add_parser("scan", help="scan an MCP manifest or live endpoint")
    ms.add_argument("target", nargs="?", help="manifest path or HTTP endpoint")
    ms.add_argument("--manifest", help="MCP JSON/YAML manifest path")
    ms.add_argument("--url", help="MCP HTTP JSON-RPC endpoint")
    ms.add_argument("--stdio-command", nargs=argparse.REMAINDER, help="MCP stdio server command")
    ms.add_argument("--timeout", type=float, default=5.0)
    ms.add_argument("-f", "--format", choices=output_formats, default=argparse.SUPPRESS)
    ms.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    ms.set_defaults(func=cmd_mcp, mcp_action="scan")

    mt = mcp_sub.add_parser("transports", help="show MCP transport coverage matrix")
    mt.add_argument("-f", "--format", choices=["table", "json"], default="table")
    mt.add_argument("-o", "--output", help="output file")
    mt.set_defaults(func=cmd_mcp, mcp_action="transports")

    mf = mcp_sub.add_parser("fingerprint", help="enumerate and fingerprint MCP server capabilities")
    mf.add_argument("target", nargs="?", help="manifest path or HTTP endpoint")
    mf.add_argument("--url", help="MCP HTTP JSON-RPC endpoint")
    mf.add_argument("--timeout", type=float, default=5.0)
    mf.add_argument("-f", "--format", choices=["table", "json"], default="table")
    mf.add_argument("-o", "--output", help="write JSON fingerprint to file")
    mf.set_defaults(func=cmd_mcp_fingerprint, mcp_action="fingerprint")

    a2a_p = sub.add_parser("a2a", help="A2A agent-card and source scanning")
    a2a_sub = a2a_p.add_subparsers(dest="a2a_action")
    a2a_p.set_defaults(func=cmd_a2a)
    a2a_scan = a2a_sub.add_parser("scan", help="scan an A2A agent card or project")
    a2a_scan.add_argument("path")
    a2a_scan.add_argument("-f", "--format", choices=output_formats, default=argparse.SUPPRESS)
    a2a_scan.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    a2a_scan.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=argparse.SUPPRESS,
    )
    a2a_scan.set_defaults(func=cmd_a2a, a2a_action="scan")

    p = sub.add_parser("supply-chain", help="supply chain audit")
    p.add_argument("path")
    _add_output_args(p)
    p.set_defaults(func=cmd_supply_chain)

    p = sub.add_parser("multi-agent-scan", aliases=["multi-agent"], help="multi-agent cross-contamination and hallucination scan")
    p.add_argument(
        "agents",
        nargs="+",
        metavar="MANIFEST",
        help="2+ agent manifest files (JSON or YAML)",
    )
    p.add_argument(
        "--scenarios",
        nargs="+",
        choices=["hallucination", "contamination", "memory_poisoning"],
        default=None,
        help="scenarios to run (default: all)",
    )
    p.add_argument("-f", "--format", choices=output_formats, default=argparse.SUPPRESS)
    p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    p.set_defaults(func=cmd_multi_agent_scan)

    p = sub.add_parser("diff", help="git diff scan")
    p.add_argument("target", nargs="?", default=None)
    p.add_argument("--staged", action="store_true", help="scan staged git changes")
    p.add_argument("--unstaged", action="store_true", help="scan unstaged git changes")
    p.add_argument("--all", action="store_true", help="scan all git changes")
    _add_output_args(p)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("notebook", aliases=["nb"], help="notebook scan")
    p.add_argument("path")
    _add_output_args(p)
    p.set_defaults(func=cmd_notebook)

    p = sub.add_parser("red-team", aliases=["redteam"], help="red team probes")
    p.add_argument("target", nargs="?")
    p.add_argument("--target", dest="target_flag")
    _add_output_args(p)
    p.add_argument(
        "--vertical",
        choices=[
            "financial", "healthcare", "telecom", "ecommerce", "insurance",
            "realestate", "medical", "pharmacy", "policy", "agentic",
            "teenSafety", "codingAgent", "compliance", "all",
        ],
        default=None,
        help="run industry-specific probe suite (use 'all' for every vertical)",
    )
    p.add_argument(
        "--strategy",
        default=None,
        metavar="STRATEGY",
        help="attack strategy name (e.g. autodan, meta_agent, adaptive)",
    )
    p.set_defaults(func=cmd_redteam)

    p = sub.add_parser("secrets-scan", aliases=["secrets"], help="enterprise secrets scanner (120+ patterns)")
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--git-history", action="store_true", help="scan git history for leaked secrets")
    p.add_argument("--no-entropy", action="store_true", help="disable entropy detection")
    p.add_argument("--max-git-commits", type=int, default=500, help="max git commits to scan")
    _add_output_args(p)
    p.set_defaults(func=cmd_secrets_scan)

    # ── Tool commands ──────────────────────────────────────────────
    from sentinel.cli.cmd_tools import (
        cmd_aibom,
        cmd_audit,
        cmd_benchmark,
        cmd_cache,
        cmd_config,
        cmd_debug,
        cmd_doctor,
        cmd_evaluate,
        cmd_findings_explain,
        cmd_plugins,
        cmd_refs,
        cmd_reverse,
        cmd_rules,
        cmd_scanners,
        cmd_shell,
        cmd_setup,
        cmd_stats,
        cmd_tui,
        cmd_version,
        cmd_watch,
    )
    from sentinel.cli.cmd_provenance import cmd_provenance

    p = sub.add_parser("evaluate", aliases=["eval"], help="evaluate scanners or LLM targets")
    p.add_argument("config", nargs="?", help="YAML/JSON eval config")
    p.add_argument("--fail-on-threshold", type=float, help="fail if pass rate is below threshold")
    p.add_argument("--concurrency", "-j", type=int, default=1, help="max parallel eval workers (default: 1)")
    p.add_argument("--summary-only", action="store_true", help="hide per-case eval rows")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("aibom", help="generate AI bill of materials")
    p.add_argument("path", nargs="?", default=".", help="repository or directory to scan")
    p.add_argument("extra_paths", nargs="*", help=argparse.SUPPRESS)
    p.add_argument(
        "--format",
        "-f",
        dest="aibom_format",
        default="cyclonedx",
        choices=["cyclonedx", "json", "spdx", "sarif", "html", "csv", "junit", "markdown"],
    )
    p.add_argument("--output", "-o", default=argparse.SUPPRESS, help="output file")
    p.add_argument(
        "--ci",
        action="store_true",
        help="CI-compatible no-op flag for GitHub Action parity",
    )
    p.add_argument("--list-scanners", action="store_true", help="list AIBOM scanner registry")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="compare two AIBOM JSON files")
    p.add_argument("--container-extraction-tier", default="auto", choices=["auto", "runtime", "tarball", "metadata"])
    p.add_argument("--discover-repos", help="scan immediate child repositories under this directory")
    p.add_argument("--skip-unchanged", action="store_true", help="skip repos whose HEAD cannot be resolved as changed")
    p.add_argument("--parallel-repos", type=int, default=1, help="reserved compatibility knob for org scans")
    p.add_argument("--once", action="store_true", help="run a single watch-mode scan and exit")
    p.set_defaults(func=cmd_aibom)

    refs_p = sub.add_parser("refs", help="inspect `.refs` inventory and parity")
    refs_sub = refs_p.add_subparsers(dest="refs_action")
    refs_p.add_argument("--refs-dir", default=".refs", help="reference clone directory")
    refs_p.add_argument("-f", "--format", dest="refs_format", choices=["markdown", "json"], default="markdown")
    refs_p.add_argument("-o", "--output", help="output file")
    refs_p.set_defaults(func=cmd_refs, refs_action="inventory")
    refs_inventory = refs_sub.add_parser("inventory", help="show cloned reference inventory")
    refs_inventory.add_argument("--refs-dir", default=argparse.SUPPRESS, help="reference clone directory")
    refs_inventory.add_argument("-f", "--format", dest="refs_format", choices=["markdown", "json"], default=argparse.SUPPRESS)
    refs_inventory.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    refs_inventory.set_defaults(func=cmd_refs, refs_action="inventory")
    refs_plan = refs_sub.add_parser("plan", help="show P1/P2 execution plan")
    refs_plan.add_argument("--refs-dir", default=argparse.SUPPRESS, help="reference clone directory")
    refs_plan.add_argument("-f", "--format", dest="refs_format", choices=["markdown", "json"], default=argparse.SUPPRESS)
    refs_plan.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    refs_plan.set_defaults(func=cmd_refs, refs_action="plan")
    refs_parity = refs_sub.add_parser("parity", help="show reference parity manifest")
    refs_parity.add_argument("-f", "--format", dest="refs_format", choices=["markdown", "json"], default=argparse.SUPPRESS)
    refs_parity.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    refs_parity.set_defaults(func=cmd_refs, refs_action="parity")

    p = sub.add_parser("plugins", help="list discovered scanner plugins")
    _add_output_args(p, severity=False)
    p.set_defaults(func=cmd_plugins)

    p = sub.add_parser("shell", aliases=["repl"], help="interactive REPL")
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("watch", help="watch & auto-scan")
    p.add_argument("path")
    p.add_argument("-i", "--interval", type=float, default=3.0)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("benchmark", aliases=["bench"], help="performance benchmark")
    p.add_argument("-n", "--iterations", type=int, default=3)
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("scanners", aliases=["ls"], help="list scanners")
    _add_output_args(p, severity=False)
    p.set_defaults(func=cmd_scanners)

    p = sub.add_parser("reverse", aliases=["rev"], help="deep format reverse engineering")
    p.add_argument("path", help="model file to reverse-engineer")
    p.set_defaults(func=cmd_reverse)

    p = sub.add_parser("stats", help="scan statistics and file distribution")
    p.add_argument("path", help="directory or file to analyze")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("doctor", help="system health check")
    p.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    p.add_argument("--show-failed", action="store_true", help="show failed/degraded checks only")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("debug", help="environment and configuration diagnostics")
    p.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    p.set_defaults(func=cmd_debug)

    cache_p = sub.add_parser("cache", help="scan cache management")
    cache_sub = cache_p.add_subparsers(dest="cache_action")
    cache_stats = cache_sub.add_parser("stats", help="show cache statistics")
    cache_stats.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    cache_stats.set_defaults(func=cmd_cache, cache_action="stats")
    cache_clear = cache_sub.add_parser("clear", help="clear in-memory scan caches")
    cache_clear.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    cache_clear.set_defaults(func=cmd_cache, cache_action="clear")
    cache_cleanup = cache_sub.add_parser("cleanup", help="remove stale cache entries")
    cache_cleanup.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    cache_cleanup.set_defaults(func=cmd_cache, cache_action="cleanup")
    cache_p.set_defaults(func=cmd_cache, cache_action="stats")

    audit_p = sub.add_parser("audit", help="query durable SQLite audit history")
    audit_sub = audit_p.add_subparsers(dest="audit_action")
    audit_query = audit_sub.add_parser("query", help="query audit events")
    audit_query.add_argument("--since", help="relative duration (1h, 7d) or ISO timestamp")
    audit_query.add_argument("--type", help="event type filter")
    audit_query.add_argument("--verdict", help="verdict filter")
    audit_query.add_argument("--limit", type=int, default=100)
    audit_query.add_argument("--db", help="audit.db path")
    audit_query.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    _add_output_args(audit_query, severity=False)
    audit_query.set_defaults(func=cmd_audit, audit_action="query")
    audit_export = audit_sub.add_parser("export", help="export audit events")
    audit_export.add_argument("--since", help="relative duration (1h, 7d) or ISO timestamp")
    audit_export.add_argument("--format", choices=["jsonl", "json"], default="jsonl")
    audit_export.add_argument("--output-path", required=True)
    audit_export.add_argument("--db", help="audit.db path")
    audit_export.add_argument("--json", dest="json_output", action="store_true", help="output command summary as JSON")
    audit_export.set_defaults(func=cmd_audit, audit_action="export")
    audit_p.set_defaults(func=cmd_audit, audit_action="query")

    setup_p = sub.add_parser("setup", help="configure local integrations")
    setup_sub = setup_p.add_subparsers(dest="setup_action")
    setup_webhook = setup_sub.add_parser("webhook", help="configure webhook notifier")
    setup_webhook.add_argument("--url", required=True)
    setup_webhook.add_argument("--events", default="block,critical")
    setup_webhook.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    setup_webhook.set_defaults(func=cmd_setup, setup_action="webhook")
    setup_splunk = setup_sub.add_parser("splunk", help="configure Splunk HEC")
    setup_splunk.add_argument("--url", required=True)
    setup_splunk.add_argument("--token", required=True)
    setup_splunk.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    setup_splunk.set_defaults(func=cmd_setup, setup_action="splunk")
    setup_guardrail = setup_sub.add_parser("guardrail", help="configure proxy guardrail mode")
    setup_guardrail.add_argument("--mode", choices=["observe", "action"], required=True)
    setup_guardrail.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    setup_guardrail.set_defaults(func=cmd_setup, setup_action="guardrail")

    p = sub.add_parser("tui", help="operator terminal dashboard")
    p.add_argument("--db", help="audit.db path")
    p.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    _add_output_args(p, severity=False)
    p.set_defaults(func=cmd_tui)

    prov_p = sub.add_parser("provenance", help="model lineage fingerprinting")
    prov_sub = prov_p.add_subparsers(dest="provenance_action")
    prov_scan = prov_sub.add_parser("scan", help="scan a local model against the reference DB")
    prov_scan.add_argument("model")
    prov_scan.add_argument("--top-k", type=int, default=5)
    prov_scan.add_argument("--threshold", type=float, default=0.5)
    prov_scan.add_argument("--db", help="reference fingerprint DB JSON")
    prov_scan.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    _add_output_args(prov_scan, severity=False)
    prov_scan.set_defaults(func=cmd_provenance, provenance_action="scan")

    prov_compare = prov_sub.add_parser("compare", help="compare two local models head-to-head")
    prov_compare.add_argument("model_a")
    prov_compare.add_argument("model_b")
    prov_compare.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    _add_output_args(prov_compare, severity=False)
    prov_compare.set_defaults(func=cmd_provenance, provenance_action="compare")

    prov_info = prov_sub.add_parser("db-info", help="show installed reference DB status")
    prov_info.add_argument("--db", help="reference fingerprint DB JSON")
    prov_info.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    _add_output_args(prov_info, severity=False)
    prov_info.set_defaults(func=cmd_provenance, provenance_action="db-info")

    prov_download = prov_sub.add_parser("download-fingerprints", help="install the bundled seed fingerprint DB")
    prov_download.add_argument("--output-path", help="where to write the fingerprint DB JSON")
    prov_download.add_argument("--json", dest="json_output", action="store_true", help="output as JSON")
    _add_output_args(prov_download, severity=False)
    prov_download.set_defaults(func=cmd_provenance, provenance_action="download-fingerprints")
    prov_p.set_defaults(func=cmd_provenance, provenance_action="db-info")

    config_p = sub.add_parser("config", help="inspect effective Sentinel configuration")
    config_p.add_argument("--explain", action="store_true", help="explain where each config value comes from")
    config_p.set_defaults(func=cmd_config, config_action="show")
    config_sub = config_p.add_subparsers(dest="config_action")
    config_explain = config_sub.add_parser("explain", help="explain config precedence and discovered sources")
    config_explain.add_argument("-f", "--format", choices=["table", "json"], default=argparse.SUPPRESS)
    config_explain.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    config_explain.set_defaults(func=cmd_config, config_action="explain", explain=True)

    p = sub.add_parser("version", help="version info")
    p.set_defaults(func=cmd_version)

    # ── Rules management ───────────────────────────────────────────
    rules_p = sub.add_parser("rules", help="rule management: list, test, explain")
    rules_sub = rules_p.add_subparsers(dest="rules_action")
    rules_list_p = rules_sub.add_parser("list", help="list all loaded rules")
    rules_list_p.add_argument("--domain", help="filter by domain")
    rules_list_p.add_argument("--format", "-f", default="table", choices=["table", "json"])
    rules_list_p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    rules_list_p.set_defaults(func=cmd_rules)
    rules_test_p = rules_sub.add_parser("test", help="test a rule against a smoke fixture")
    rules_test_p.add_argument("rule_id", help="rule ID to test")
    rules_test_p.add_argument("-f", "--format", choices=["table", "json"], default=argparse.SUPPRESS)
    rules_test_p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    rules_test_p.set_defaults(func=cmd_rules)
    rules_explain_p = rules_sub.add_parser("explain", help="explain a loaded rule ID")
    rules_explain_p.add_argument("rule_id", help="rule ID to explain")
    rules_explain_p.add_argument("-f", "--format", choices=["table", "json"], default=argparse.SUPPRESS)
    rules_explain_p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    rules_explain_p.set_defaults(func=cmd_rules)
    rules_audit_p = rules_sub.add_parser("audit", help="audit loaded rule IDs and regexes")
    rules_audit_p.add_argument("-f", "--format", choices=["table", "json"], default=argparse.SUPPRESS)
    rules_audit_p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    rules_audit_p.set_defaults(func=cmd_rules)
    rules_p.set_defaults(func=cmd_rules)

    # ── Findings explain ───────────────────────────────────────────
    findings_p = sub.add_parser("finding", aliases=["findings"], help="finding inspection and explanation")
    findings_sub = findings_p.add_subparsers(dest="findings_action")
    explain_p = findings_sub.add_parser("explain", help="explain a rule ID")
    explain_p.add_argument("rule_id", help="rule ID to explain (e.g. ARTIFACT-031)")
    explain_p.add_argument("-f", "--format", choices=["table", "json"], default=argparse.SUPPRESS)
    explain_p.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    explain_p.set_defaults(func=cmd_findings_explain)
    findings_p.set_defaults(func=cmd_findings_explain)

    # ── Service commands ───────────────────────────────────────────
    from sentinel.cli.cmd_serve import (
        cmd_dep_scan,
        cmd_playbook,
        cmd_policy,
        cmd_proxy,
        cmd_serve,
        cmd_validate,
    )

    p = sub.add_parser("policy", help="policy management")
    p.add_argument("action", choices=["init", "show", "validate"], default="show", nargs="?")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("dashboard", help="web dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--policy", default="")
    p.add_argument(
        "--open",
        dest="open_browser",
        action="store_true",
        help="open dashboard in browser",
    )
    p.set_defaults(func=cmd_serve, ui=True)

    p = sub.add_parser("serve", help="REST API server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--policy", default="")
    p.add_argument(
        "--ui",
        action="store_true",
        help="serve web dashboard (React SPA + hardened API)",
    )
    p.add_argument(
        "--open",
        dest="open_browser",
        action="store_true",
        help="open dashboard in browser when --ui is set",
    )
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("validate", help="validate YAML rules")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("proxy", help="live MCP intercepting proxy")
    p.add_argument("--mode", choices=["enforce", "audit", "passthrough", "observe", "action"], default="action")
    p.add_argument("--transport", choices=["stdio", "http"], default="http")
    p.add_argument("--upstream", default="http://localhost:3000", help="upstream MCP server URL")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--server-cmd", nargs=argparse.REMAINDER, help="MCP server command (for stdio mode)")
    p.set_defaults(func=cmd_proxy)

    p = sub.add_parser("playbook", aliases=["pb"], help="attack playbook runner")
    p.add_argument("path", help="playbook YAML file or directory")
    p.add_argument("--report-format", choices=["json", "html", "sarif", "text"], default="text")
    p.add_argument("--report-output", help="report output file")
    p.add_argument("--fail-fast", action="store_true", help="stop on first failure")
    p.add_argument("--fail-on-critical", action="store_true", help="exit 1 if any CRITICAL probe fails")
    p.add_argument("--fail-on-failed-probes", action="store_true", help="exit 1 if any probe fails")
    p.add_argument("--fail-on-grade", choices=["A", "B", "C", "D", "F"], help="exit 1 when grade is this or worse")
    p.set_defaults(func=cmd_playbook)

    p = sub.add_parser("dep-scan", aliases=["deps"], help="live dependency vulnerability scanner")
    p.add_argument("path", help="project directory to scan")
    p.add_argument("--no-osv", action="store_true", help="disable OSV.dev queries")
    p.add_argument("--no-pip-audit", action="store_true", help="disable pip-audit")
    p.add_argument("--offline", action="store_true", help="disable live vulnerability lookups")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    _add_output_args(p)
    p.set_defaults(func=cmd_dep_scan)

    # ── Fuzz commands ──────────────────────────────────────────────
    from sentinel.cli.cmd_fuzz import cmd_fuzz

    fuzz_p = sub.add_parser("fuzz", help="AI offensive security fuzzing")
    fuzz_sub = fuzz_p.add_subparsers(dest="fuzz_action")
    fuzz_p.set_defaults(func=cmd_fuzz)

    fg = fuzz_sub.add_parser("generate", help="generate random pickle samples")
    fg.add_argument("-n", "--count", type=int, default=100, help="number of samples")
    fg.add_argument("-p", "--protocol", type=int, default=4, choices=range(6), help="pickle protocol (0-5)")
    fg.add_argument("-s", "--seed", type=int, help="random seed for reproducibility")
    fg.add_argument("--min-opcodes", type=int, default=10)
    fg.add_argument("--max-opcodes", type=int, default=200)
    fg.add_argument("--dir", help="output directory for batch generation")
    fg.add_argument("--file", help="output file for single sample")
    fg.set_defaults(func=cmd_fuzz, fuzz_action="generate")

    fm = fuzz_sub.add_parser("mutate", help="mutate existing pickle files")
    fm.add_argument("input_file", help="pickle file to mutate")
    fm.add_argument("-n", "--count", type=int, default=10, help="number of variants")
    fm.add_argument("-s", "--seed", type=int)
    fm.add_argument("--dir", help="output directory")
    fm.set_defaults(func=cmd_fuzz, fuzz_action="mutate")

    fv = fuzz_sub.add_parser("validate", help="validate pickle samples with pickletools")
    fv.add_argument("dir", help="directory or file to validate")
    fv.set_defaults(func=cmd_fuzz, fuzz_action="validate")

    fs = fuzz_sub.add_parser("selftest", help="Sentinel Eats Itself — self-test pipeline")
    fs.add_argument("-n", "--samples", type=int, default=500, help="total samples to generate")
    fs.add_argument("-s", "--seed", type=int, help="random seed")
    fs.add_argument("--dir", help="output directory for reports and bypasses")
    fs.add_argument("--allow-bypass", action="store_true", help="exit 0 even when bypassed payloads are found")
    fs.add_argument("--min-tpr", type=float, default=0.95, help="minimum true-positive rate required to pass")
    fs.add_argument("--max-fpr", type=float, default=0.03, help="maximum false-positive rate allowed to pass")
    fs.set_defaults(func=cmd_fuzz, fuzz_action="selftest")

    fp = fuzz_sub.add_parser("payloads", help="list adversarial payload templates")

    fmin = fuzz_sub.add_parser("minimize", help="minimize fuzz corpus (remove redundant samples)")
    fmin.add_argument("corpus_dir", help="directory containing pickle corpus files")
    fmin.add_argument("-o", "--output", help="output directory for minimized corpus")
    fmin.add_argument("--dry-run", action="store_true", help="show what would be removed without deleting")
    fmin.set_defaults(func=cmd_fuzz, fuzz_action="minimize")
    fp.set_defaults(func=cmd_fuzz, fuzz_action="payloads")

    # ── Parse & dispatch ───────────────────────────────────────────
    # Handle 'sentinel help' and 'sentinel help <command>' as UX aliases
    argv = sys.argv[1:]
    if argv and argv[0] == "help":
        if len(argv) > 1:
            argv = [argv[1], "--help"]
        else:
            argv = ["--help"]

    args = parser.parse_args(argv)

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    if args.quiet:
        console.quiet = True
        import logging as _log
        import warnings
        _log.disable(_log.WARNING)
        warnings.filterwarnings("ignore")

    # Structured output owns stdout. Rich output and stray print() calls go
    # to stderr; report writers use the saved original stdout.
    _fmt = getattr(args, "format", "table")
    _out = getattr(args, "output", None)
    _aibom_fmt = getattr(args, "aibom_format", None)
    machine_output = (
        _fmt != "table"
        or bool(getattr(args, "json_output", False))
        or _aibom_fmt is not None
        or getattr(args, "refs_format", None) == "json"
    )
    set_machine_stdout(sys.stdout)
    if machine_output and not _out:
        console.file = sys.stderr

    if args.command is None:
        console.print(_BANNER)
        parser.print_help()
        return

    try:
        if machine_output and not _out:
            with redirect_stdout(sys.stderr):
                result = args.func(args)
        else:
            result = args.func(args)
        sys.exit(result if isinstance(result, int) else 0)
    except Exception as e:
        err.print(f"  [red]error:[/red] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
