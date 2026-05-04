"""LLM Judge commands — consensus voting + finding classifier."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinel.cli._helpers import _fail, _header, _ok, _warn, console


def cmd_llm_judge(args) -> int:
    """Dispatcher for `sentinel llm-judge` subcommands."""
    action = getattr(args, "llm_judge_action", None) or "classify"
    if action == "classify":
        return _cmd_classify(args)
    if action == "consensus":
        return _cmd_consensus(args)
    _header("llm-judge — LLM-based finding enrichment")
    console.print("  [dim]subcommands: classify, consensus[/dim]")
    return 2


def _cmd_classify(args) -> int:
    """Enrich scan findings from a JSON file using LLM classifier."""
    findings_file = getattr(args, "findings", None) or getattr(args, "path", None)
    if not findings_file:
        _fail("--findings required: path to sentinel JSON findings file")
        return 2

    provider = getattr(args, "provider", "openai")
    model = getattr(args, "model", "gpt-4o-mini")
    min_sev = getattr(args, "min_severity", "MEDIUM") or "MEDIUM"
    output = getattr(args, "output", None)

    findings = _load_findings(findings_file)
    if not findings:
        _warn("no findings to classify")
        return 0

    _header(f"llm-judge classify → {len(findings)} findings (provider={provider}, min={min_sev})")

    from sentinel.llm_judge.classifier import LLMFindingClassifier

    classifier = LLMFindingClassifier(
        provider=provider,
        model=model,
        min_severity=min_sev,
        apply_in_place=False,
    )

    enriched = []
    for f in findings:
        result = classifier.classify(f)
        row = {**f}
        if result.error is None:
            row["llm_severity"] = result.severity_validated
            row["exploit_likelihood"] = result.exploit_likelihood
            row["attack_vector"] = result.attack_vector
            row["owasp_llm_validated"] = result.owasp_llm
            row["mitre_atlas"] = result.mitre_atlas
            row["remediation_improved"] = result.remediation_improved
            row["llm_tags"] = result.tags_extra
            row["llm_rationale"] = result.rationale
        else:
            row["llm_error"] = result.error
        enriched.append(row)

        sev = result.severity_validated
        orig = str(f.get("severity", "")).upper()
        escalated = (
            {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 0)
            > {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(orig, 0)
        )
        marker = "[red]↑[/red]" if escalated else "[dim]·[/dim]"
        console.print(
            f"  {marker} {f.get('rule_id', '')} [{orig}→{sev}] "
            f"exploit={result.exploit_likelihood:.2f} {result.rationale[:60]}"
        )

    payload = {"schema_version": "llm_judge.classify.v1", "count": len(enriched), "findings": enriched}
    result_json = json.dumps(payload, indent=2, default=str)

    if output:
        Path(output).write_text(result_json, encoding="utf-8")
        _ok(f"written → {output}")
    else:
        sys.stdout.write(result_json + "\n")

    return 0


def _cmd_consensus(args) -> int:
    """Run N-vote consensus on findings from a JSON file."""
    findings_file = getattr(args, "findings", None) or getattr(args, "path", None)
    if not findings_file:
        _fail("--findings required: path to sentinel JSON findings file")
        return 2

    provider = getattr(args, "provider", "openai")
    model = getattr(args, "model", "gpt-4o-mini")
    runs = getattr(args, "runs", 3)
    threshold = getattr(args, "threshold", 0.60)
    output = getattr(args, "output", None)

    findings = _load_findings(findings_file)
    if not findings:
        _warn("no findings to judge")
        return 0

    _header(f"llm-judge consensus → {len(findings)} findings (runs={runs}, threshold={threshold:.0%})")

    from sentinel.llm_judge.consensus import LLMConsensusJudge

    judge = LLMConsensusJudge(
        provider=provider,
        model=model,
        runs=runs,
        threshold=threshold,
    )

    kept, suppressed = [], []
    results_detail = []

    for f in findings:
        cr = judge.judge(f)
        is_tp = cr.is_true_positive
        if is_tp:
            kept.append(f)
        else:
            suppressed.append(f)

        tp_frac = cr.true_positive_votes / max(cr.total_runs, 1)
        verdict = "[green]TP[/green]" if is_tp else "[dim]FP[/dim]"
        console.print(
            f"  {verdict} {f.get('rule_id', '')} "
            f"[{cr.true_positive_votes}/{cr.total_runs} votes, conf={cr.confidence:.2f}] "
            f"{cr.rationale[:60]}"
        )
        results_detail.append({
            "rule_id": f.get("rule_id", ""),
            "is_true_positive": is_tp,
            "confidence": cr.confidence,
            "tp_votes": cr.true_positive_votes,
            "fp_votes": cr.false_positive_votes,
            "uncertain_votes": cr.uncertain_votes,
            "total_runs": cr.total_runs,
            "rationale": cr.rationale,
        })

    _ok(f"kept {len(kept)}, suppressed {len(suppressed)} from {len(findings)}")

    payload = {
        "schema_version": "llm_judge.consensus.v1",
        "summary": {"kept": len(kept), "suppressed": len(suppressed), "total": len(findings)},
        "results": results_detail,
        "kept_findings": kept,
        "suppressed_findings": suppressed,
    }
    result_json = json.dumps(payload, indent=2, default=str)

    if output:
        Path(output).write_text(result_json, encoding="utf-8")
        _ok(f"written → {output}")
    else:
        sys.stdout.write(result_json + "\n")

    return 0


def _load_findings(path: str) -> list[dict]:
    """Load findings from a sentinel JSON file."""
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", [])
    return []
