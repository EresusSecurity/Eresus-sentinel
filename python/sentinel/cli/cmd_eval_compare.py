"""Eval compare commands — multi-provider side-by-side prompt evaluation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinel.cli._helpers import _fail, _header, _ok, _warn, console


def cmd_eval_compare(args) -> int:
    """Run side-by-side prompt comparison across multiple LLM providers."""
    config = getattr(args, "config", None)
    providers_arg = getattr(args, "providers", None)
    prompts_arg = getattr(args, "prompts", None)
    output = getattr(args, "output", None)
    fmt = getattr(args, "eval_format", "json")

    from sentinel.eval.comparator import (
        PromptCase,
        PromptComparator,
        ProviderConfig,
        load_cases_from_yaml,
        load_providers_from_yaml,
        assert_min_length,
    )

    # Build provider list
    providers: list[ProviderConfig] = []
    if config:
        try:
            providers = load_providers_from_yaml(config)
        except Exception as exc:
            _fail(f"failed to load providers from {config}: {exc}")
            return 2

    if providers_arg:
        for spec in providers_arg:
            parts = spec.split(":", 2)
            pname = parts[0]
            model = parts[1] if len(parts) > 1 else "gpt-4o-mini"
            providers.append(ProviderConfig(name=pname, provider=pname, model=model))

    if not providers:
        _fail("no providers specified — use --providers openai:gpt-4o-mini anthropic:claude-3-haiku-20240307 OR --config eval.yaml")
        return 2

    # Build prompt cases
    cases: list[PromptCase] = []
    if config:
        try:
            cases = load_cases_from_yaml(config)
        except Exception:
            pass

    if prompts_arg:
        for p in prompts_arg:
            cases.append(PromptCase(prompt=p))

    if not cases:
        _fail("no prompts specified — use --prompts 'prompt1' 'prompt2' OR --config eval.yaml")
        return 2

    concurrency = getattr(args, "concurrency", 4)
    timeout = getattr(args, "timeout", 30)

    _header(f"eval compare → {len(cases)} prompts × {len(providers)} providers")
    for p in providers:
        console.print(f"  [dim]· {p.name} ({p.provider}/{p.model})[/dim]")

    comparator = PromptComparator(
        providers=providers,
        concurrency=concurrency,
        timeout=timeout,
    )

    report = comparator.compare(cases)

    # Print summary
    pass_rates = report.overall_pass_rates
    lats = report.avg_latencies
    console.print("\n  [bold]Results:[/bold]")
    for pname in report.providers:
        pr = pass_rates.get(pname, 0.0)
        lat = lats.get(pname, 0.0)
        color = "green" if pr >= 0.8 else "yellow" if pr >= 0.5 else "red"
        console.print(f"  [{color}]  {pname:<20} {pr:.0%} pass  {lat:.0f}ms avg[/{color}]")

    # Export
    if fmt == "html":
        result_str = report.to_html()
        ext = ".html"
    elif fmt == "csv":
        result_str = _to_csv(report)
        ext = ".csv"
    else:
        result_str = report.to_json()
        ext = ".json"

    if output:
        out_path = output if output.endswith(ext) else output
        Path(out_path).write_text(result_str, encoding="utf-8")
        _ok(f"written → {out_path}")
    else:
        sys.stdout.write(result_str + "\n")

    return 0


def _to_csv(report) -> str:
    lines = ["case_id,prompt,provider,passed,score,latency_ms,error"]
    for result in report.results:
        for pname, resp in result.responses.items():
            prompt_esc = result.prompt[:100].replace('"', '""')
            err = (resp.error or "").replace('"', '""')
            lines.append(
                f'"{result.case_id}","{prompt_esc}","{pname}",'
                f'{str(resp.passed).lower()},{resp.score:.3f},{resp.latency_ms:.1f},"{err}"'
            )
    return "\n".join(lines)
