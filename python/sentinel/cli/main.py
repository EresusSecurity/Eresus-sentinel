"""
Eresus Sentinel CLI — main entry point.

Usage:
    sentinel scan ./project/
    sentinel firewall "prompt text"
    sentinel firewall -d output "response"
    sentinel shell
    sentinel scanners
    sentinel version
"""

from __future__ import annotations

import argparse
import sys

from sentinel.cli._helpers import console, err


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
    parser.add_argument("-f", "--format", choices=["table", "json", "sarif", "csv", "markdown", "html"], default="table")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("--show-skipped", action="store_true", help="show files skipped due to unsupported format")
    parser.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="minimum severity to report")

    sub = parser.add_subparsers(dest="command")

    # ── Scan commands ──────────────────────────────────────────────
    from sentinel.cli.cmd_scan import (
        cmd_scan, cmd_firewall, cmd_artifact, cmd_hf_artifact,
        cmd_hf_scan, cmd_hf_guard,
    )

    p = sub.add_parser("scan", help="full scan")
    p.add_argument("path"); p.set_defaults(func=cmd_scan)

    p = sub.add_parser("firewall", aliases=["fw"], help="firewall scan")
    p.add_argument("input", help="text or - for stdin")
    p.add_argument("-d", "--direction", choices=["input", "output"], default="input")
    p.set_defaults(func=cmd_firewall)

    p = sub.add_parser("artifact", help="model artifact scan")
    p.add_argument("path"); p.set_defaults(func=cmd_artifact)

    p = sub.add_parser("hf-artifact", help="scan model artifacts from HuggingFace repo")
    p.add_argument("hf_repo", help="HuggingFace repo (e.g. org/model-name)")
    p.set_defaults(func=cmd_hf_artifact)

    p = sub.add_parser("hf-scan", help="scan HuggingFace model repo")
    p.add_argument("repo", help="HuggingFace repo (e.g. org/model)")
    p.set_defaults(func=cmd_hf_scan)

    p = sub.add_parser("hf-guard", help="pre-download HF repo assessment")
    p.add_argument("repo", help="HuggingFace repo (e.g. org/model)")
    p.add_argument("--deep", action="store_true", help="download and deep-scan files")
    p.add_argument("--block-pickle", action="store_true", help="block repos with pickle files")
    p.add_argument("--require-safetensors", action="store_true", help="require safetensors format")
    p.set_defaults(func=cmd_hf_guard)

    # ── Analysis commands ──────────────────────────────────────────
    from sentinel.cli.cmd_analysis import (
        cmd_sast, cmd_agent, cmd_supply_chain, cmd_diff,
        cmd_notebook, cmd_redteam, cmd_secrets_scan,
    )

    p = sub.add_parser("sast", help="static analysis")
    p.add_argument("path"); p.set_defaults(func=cmd_sast)

    p = sub.add_parser("agent", help="agent/mcp validation")
    p.add_argument("path"); p.set_defaults(func=cmd_agent)

    p = sub.add_parser("supply-chain", help="supply chain audit")
    p.add_argument("path"); p.set_defaults(func=cmd_supply_chain)

    p = sub.add_parser("diff", help="git diff scan")
    p.add_argument("target", nargs="?", default="--staged"); p.set_defaults(func=cmd_diff)

    p = sub.add_parser("notebook", aliases=["nb"], help="notebook scan")
    p.add_argument("path"); p.set_defaults(func=cmd_notebook)

    p = sub.add_parser("red-team", help="red team probes")
    p.add_argument("target"); p.set_defaults(func=cmd_redteam)

    p = sub.add_parser("secrets-scan", aliases=["secrets"], help="enterprise secrets scanner (120+ patterns)")
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--git-history", action="store_true", help="scan git history for leaked secrets")
    p.add_argument("--no-entropy", action="store_true", help="disable entropy detection")
    p.add_argument("--max-git-commits", type=int, default=500, help="max git commits to scan")
    p.set_defaults(func=cmd_secrets_scan)

    # ── Tool commands ──────────────────────────────────────────────
    from sentinel.cli.cmd_tools import (
        cmd_evaluate, cmd_plugins, cmd_reverse, cmd_stats, cmd_doctor,
        cmd_shell, cmd_benchmark, cmd_scanners, cmd_watch,
        cmd_config, cmd_version,
    )

    p = sub.add_parser("evaluate", aliases=["eval"], help="evaluate scanner effectiveness")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("plugins", help="list discovered scanner plugins")
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
    p.set_defaults(func=cmd_scanners)

    p = sub.add_parser("reverse", aliases=["rev"], help="deep format reverse engineering")
    p.add_argument("path", help="model file to reverse-engineer")
    p.set_defaults(func=cmd_reverse)

    p = sub.add_parser("stats", help="scan statistics and file distribution")
    p.add_argument("path", help="directory or file to analyze")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("doctor", help="system health check")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("config", help="show config as JSON")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("version", help="version info")
    p.set_defaults(func=cmd_version)

    # ── Service commands ───────────────────────────────────────────
    from sentinel.cli.cmd_serve import (
        cmd_serve, cmd_validate, cmd_policy, cmd_proxy,
        cmd_playbook, cmd_dep_scan,
    )

    p = sub.add_parser("policy", help="policy management")
    p.add_argument("action", choices=["init", "show", "validate"], default="show", nargs="?")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("serve", help="REST API server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--policy", default="")
    p.add_argument("--ui", action="store_true", help="serve web dashboard (React SPA + hardened API)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("validate", help="validate YAML rules")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("proxy", help="live MCP intercepting proxy")
    p.add_argument("--mode", choices=["enforce", "audit", "passthrough"], default="enforce")
    p.add_argument("--transport", choices=["stdio", "http"], default="http")
    p.add_argument("--upstream", default="http://localhost:3000", help="upstream MCP server URL")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--server-cmd", nargs="+", help="MCP server command (for stdio mode)")
    p.set_defaults(func=cmd_proxy)

    p = sub.add_parser("playbook", aliases=["pb"], help="attack playbook runner")
    p.add_argument("path", help="playbook YAML file or directory")
    p.add_argument("--report-format", choices=["json", "html", "sarif", "text"], default="text")
    p.add_argument("--report-output", help="report output file")
    p.add_argument("--fail-fast", action="store_true", help="stop on first failure")
    p.set_defaults(func=cmd_playbook)

    p = sub.add_parser("dep-scan", aliases=["deps"], help="live dependency vulnerability scanner")
    p.add_argument("path", help="project directory to scan")
    p.add_argument("--no-osv", action="store_true", help="disable OSV.dev queries")
    p.add_argument("--no-pip-audit", action="store_true", help="disable pip-audit")
    p.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
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
    fs.set_defaults(func=cmd_fuzz, fuzz_action="selftest")

    fp = fuzz_sub.add_parser("payloads", help="list adversarial payload templates")
    fp.set_defaults(func=cmd_fuzz, fuzz_action="payloads")

    # ── Parse & dispatch ───────────────────────────────────────────
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    if args.quiet:
        console.quiet = True

    if args.command is None:
        console.print(_BANNER)
        parser.print_help()
        return

    try:
        result = args.func(args)
        sys.exit(result if isinstance(result, int) else 0)
    except Exception as e:
        err.print(f"  [red]error:[/red] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
