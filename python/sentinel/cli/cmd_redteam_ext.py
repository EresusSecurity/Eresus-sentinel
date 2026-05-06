"""Extended red-team CLI commands.

  sentinel redteam compare  — Run probes against multiple models, side-by-side
  sentinel redteam schedule  — Manage and execute recurring scan schedules
  sentinel redteam pdf       — Export last redteam JSON results to PDF
  sentinel redteam budget    — Show budget usage for last run
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── compare ───────────────────────────────────────────────────────────────

def cmd_redteam_compare(args: argparse.Namespace) -> None:
    """sentinel redteam compare --models gpt-4o claude-3-sonnet --probes pair persuasion"""
    from sentinel.redteam.multi_model_compare import MultiModelComparison
    from sentinel.redteam.generators import get_generator

    models: list[str] = args.models
    probe_names: list[str] = args.probes or ["pair", "persuasion", "many_shot"]
    output_fmt: str = getattr(args, "format", "table")
    output_file: str | None = getattr(args, "output", None)
    max_prompts: int = args.max_prompts
    budget: float | None = args.budget

    generators = {}
    for model in models:
        provider = "litellm"
        if "ollama" in model:
            provider = "ollama"
        elif "openrouter" in model:
            provider = "openrouter"
        try:
            gen = get_generator(provider, model=model)
            if budget:
                from sentinel.redteam.budget import BudgetController
                gen = BudgetController(gen, max_cost_usd=budget / len(models))
            generators[model] = gen
        except Exception as exc:
            print(f"[!] Could not create generator for {model}: {exc}", file=sys.stderr)

    if not generators:
        print("[!] No generators available — aborting", file=sys.stderr)
        sys.exit(1)

    cmp = MultiModelComparison(generators, max_prompts=max_prompts)

    print(f"Running {len(probe_names)} probe(s) against {len(generators)} model(s)...")
    report = cmp.run(probe_names)

    if output_fmt in ("json",):
        out = report.to_dict() if hasattr(report, "to_dict") else vars(report)
        text = json.dumps(out, indent=2, default=str)
        if output_file:
            Path(output_file).write_text(text, encoding="utf-8")
            print(f"Saved to {output_file}")
        else:
            print(text)
    else:
        if hasattr(report, "summary_table"):
            print(report.summary_table())
        else:
            print(report)

    if args.pdf:
        pdf_path = args.pdf
        try:
            from sentinel.redteam.report_pdf import RedTeamPDFExporter
            exporter = RedTeamPDFExporter()
            written = exporter.from_comparison(report, pdf_path)
            print(f"PDF report saved to: {written}")
        except Exception as exc:
            print(f"[!] PDF export failed: {exc}", file=sys.stderr)


# ── schedule ──────────────────────────────────────────────────────────────

def cmd_redteam_schedule(args: argparse.Namespace) -> None:
    """sentinel redteam schedule [list|add|remove|run|run-now]"""
    from sentinel.redteam.scheduler import ScanScheduler, ScheduleEntry

    db_path = args.db or str(Path.home() / ".sentinel" / "schedules.json")
    scheduler = ScanScheduler(db_path=db_path)
    action = args.schedule_action or "list"

    if action == "list":
        entries = scheduler.list_entries()
        if not entries:
            print("No scheduled scans.")
        for e in entries:
            print(f"  [{e.id}] {e.name} — cron: {e.cron} — last: {e.last_run or 'never'} — status: {e.last_status or 'pending'}")

    elif action == "add":
        entry = ScheduleEntry(
            name=args.name,
            cron=args.cron,
            probe_names=args.probes or ["pair", "persuasion"],
            generator_config={"model": args.model} if args.model else {},
            notify_webhook=args.webhook,
        )
        scheduler.add(entry)
        print(f"Added schedule '{entry.name}' (id={entry.id})")

    elif action == "remove":
        scheduler.remove(args.id)
        print(f"Removed schedule id={args.id}")

    elif action == "run":
        print(f"Starting scheduler daemon (db={db_path})...")
        thread = scheduler.run_forever()
        try:
            thread.join()
        except KeyboardInterrupt:
            scheduler.stop()
            print("\nScheduler stopped.")

    elif action == "run-now":
        entry_id = args.id
        entry = next((e for e in scheduler.list_entries() if e.id == entry_id), None)
        if not entry:
            print(f"[!] No entry with id={entry_id}", file=sys.stderr)
            sys.exit(1)
        result = scheduler._execute(entry)
        print(f"Ran '{result.entry_name}': status={result.status}, duration={result.duration_s:.1f}s")

    else:
        print(f"Unknown schedule action: {action}", file=sys.stderr)
        sys.exit(1)


# ── pdf export ────────────────────────────────────────────────────────────

def cmd_redteam_pdf(args: argparse.Namespace) -> None:
    """sentinel redteam pdf <json_file> --output report.pdf"""
    from sentinel.redteam.report_pdf import RedTeamPDFExporter
    json_file = args.json_file
    out = args.output or json_file.replace(".json", ".pdf")
    exporter = RedTeamPDFExporter(backend=args.backend or "auto")
    written = exporter.from_json_file(json_file, out)
    print(f"Report saved: {written}")


# ── budget summary ─────────────────────────────────────────────────────────

def cmd_redteam_budget(args: argparse.Namespace) -> None:
    """sentinel redteam budget — Show live budget for an in-progress run."""
    print("Budget tracking is attached to individual generator instances.")
    print("Use BudgetController wrapping your generator and call .snapshot() for live data.")
    print("Example:")
    print("  from sentinel.redteam.budget import BudgetController")
    print("  bc = BudgetController(gen, max_cost_usd=1.0, max_tokens=50000)")
    print("  print(bc.snapshot())")
