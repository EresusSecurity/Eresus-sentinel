from __future__ import annotations

import json
from pathlib import Path

from sentinel.cli._helpers import console, machine_stdout
from sentinel.platform.assertions import AssertionRegistry
from sentinel.platform.config import config_graph, explain_config, resolve_config, simulate_config
from sentinel.platform.dataset import load_dataset
from sentinel.platform.hygiene import run_hygiene_gate
from sentinel.platform.providers import ProviderRegistry
from sentinel.platform.redteam import AttackRegistry, RedTeamRunner
from sentinel.platform.reports import render_report
from sentinel.platform.runtime import RuntimePolicyEngine
from sentinel.platform.runner import EvalRunner
from sentinel.platform.store import RunStore
from sentinel.sntl.convert import compare_formats, convert_file, detect_format, inspect_file, load_any, migrate_tree, plan_conversion, roundtrip_file


def _emit(payload: dict | list | str, output: str | None = None) -> int:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, sort_keys=True, default=str)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        stream = machine_stdout()
        stream.write(text + "\n")
        stream.flush()
    return 0


def _issues(issues):
    return [issue.__dict__ for issue in issues]


def _migration_item(item):
    return {
        "source": item.source,
        "target": item.target,
        "source_format": item.source_format,
        "target_format": item.target_format,
        "schema": item.schema,
        "fingerprint": item.fingerprint,
        "valid": item.valid,
        "issues": _issues(item.issues),
    }


def _migration_plan(plan):
    return {
        "schema_version": "sentinel.sntl.migration.v1",
        "source_root": plan.source_root,
        "target_root": plan.target_root,
        "target_format": plan.target_format,
        "valid": plan.ok,
        "items": [_migration_item(item) for item in plan.items],
        "skipped": list(plan.skipped),
    }


def _inspection_payload(inspection):
    return {
        "schema_version": "sentinel.sntl.inspect.v1",
        "source": inspection.source,
        "format": inspection.format,
        "schema": inspection.schema,
        "inferred_schema": inspection.inferred_schema,
        "fingerprint": inspection.fingerprint,
        "valid": inspection.valid,
        "top_level_keys": list(inspection.top_level_keys),
        "item_count": inspection.item_count,
        "capabilities": inspection.capabilities,
        "issues": _issues(inspection.issues),
    }


def _roundtrip_payload(result):
    return {
        "schema_version": "sentinel.sntl.roundtrip.v1",
        "source": result.source,
        "source_format": result.source_format,
        "target_format": result.target_format,
        "return_format": result.return_format,
        "stable": result.stable,
        "source_fingerprint": result.source_fingerprint,
        "rendered_fingerprint": result.rendered_fingerprint,
        "returned_fingerprint": result.returned_fingerprint,
        "issues": _issues(result.issues),
    }


def cmd_platform(args):
    action = getattr(args, "platform_action", "status") or "status"
    if action == "status":
        return _emit({"schema_version": "sentinel.platform.status.v1", "offline": True, "deterministic_core": True})
    if action == "hygiene":
        result = run_hygiene_gate(getattr(args, "path", "."))
        _emit(result, getattr(args, "output", None))
        return 0 if result["ok"] else 1
    if action == "providers":
        return _emit({"schema_version": "sentinel.provider.registry.v1", "providers": ProviderRegistry().list()}, getattr(args, "output", None))
    if action == "provider-test":
        return _emit(ProviderRegistry().test(args.provider, {"allow_live": getattr(args, "allow_live", False)}), getattr(args, "output", None))
    if action == "assertions":
        return _emit({"schema_version": "sentinel.assertion.registry.v1", "assertions": AssertionRegistry().list()}, getattr(args, "output", None))
    if action == "assertion-run":
        spec = json.loads(args.spec)
        outcome = AssertionRegistry().evaluate(spec, args.output_text, json.loads(args.context or "{}"))
        return _emit({"schema_version": "sentinel.assertion.result.v1", "outcome": outcome.__dict__}, getattr(args, "output", None))
    if action == "dataset":
        dataset = load_dataset(args.path, key=getattr(args, "key", None))
        return _emit(
            {
                "schema_version": "sentinel.dataset.inspect.v1",
                "id": dataset.id,
                "fingerprint": dataset.fingerprint,
                "lineage": dataset.lineage,
                "record_count": len(dataset.records),
                "sample": [record.__dict__ for record in dataset.records[:5]],
            },
            getattr(args, "output", None),
        )
    if action == "config":
        resolved = resolve_config(args.paths, profile=getattr(args, "profile_name", None), environment=getattr(args, "environment", None))
        return _emit(
            {
                "schema_version": "sentinel.config.bundle.v1",
                "config": resolved.data,
                "explain": explain_config(resolved),
                "graph": config_graph(resolved),
                "simulation": simulate_config(resolved.data),
            },
            getattr(args, "output", None),
        )
    if action == "convert":
        if getattr(args, "capabilities", False):
            return _emit(compare_formats(), getattr(args, "output", None))
        if not getattr(args, "input", None):
            raise ValueError("input is required")
        if getattr(args, "inspect", False):
            inspection = inspect_file(args.input, source_format=getattr(args, "source_format", None), schema=getattr(args, "schema", None), name=getattr(args, "name", None))
            _emit(_inspection_payload(inspection), getattr(args, "output", None))
            return 0 if inspection.valid else 1
        if getattr(args, "check", False):
            result = roundtrip_file(
                args.input,
                source_format=getattr(args, "source_format", None),
                target_format=getattr(args, "target_format", "sntl"),
                return_format=getattr(args, "return_format", "json"),
                schema=getattr(args, "schema", None),
                name=getattr(args, "name", None),
            )
            _emit(_roundtrip_payload(result), getattr(args, "output", None))
            return 0 if result.stable else 1
        if getattr(args, "plan", False):
            plan = plan_conversion(
                args.input,
                getattr(args, "target", None),
                source_formats=getattr(args, "source_formats", None),
                target_format=getattr(args, "target_format", "sntl"),
                schema=getattr(args, "schema", None),
            )
            _emit(_migration_plan(plan), getattr(args, "output", None))
            return 0 if plan.ok else 1
        if getattr(args, "recursive", False):
            recursive_target = getattr(args, "target", None)
            if recursive_target is None:
                source_root = Path(args.input)
                recursive_target = str(source_root.parent / f"{source_root.name}-sntl")
            plan = migrate_tree(
                args.input,
                recursive_target,
                source_formats=getattr(args, "source_formats", None),
                target_format=getattr(args, "target_format", "sntl"),
                schema=getattr(args, "schema", None),
            )
            _emit(_migration_plan(plan), getattr(args, "output", None))
            return 0 if plan.ok else 1
        source = Path(args.input)
        output = convert_file(
            source,
            getattr(args, "target", None),
            source_format=getattr(args, "source_format", None),
            target_format=getattr(args, "target_format", "sntl"),
            schema=getattr(args, "schema", None),
            name=getattr(args, "name", None),
        )
        target_format = detect_format(path=output)
        document = load_any(output) if target_format in {"sntl", "sentinel"} else None
        return _emit(
            {
                "schema_version": "sentinel.sntl.convert.v1",
                "source": str(source),
                "source_format": detect_format(path=source, source_format=getattr(args, "source_format", None)),
                "target": str(output),
                "target_format": target_format,
                "fingerprint": document.fingerprint if document else None,
                "valid": document.ok if document else True,
                "issues": [issue.__dict__ for issue in document.issues] if document else [],
            },
            getattr(args, "output", None),
        )
    if action == "eval-plan":
        runner = EvalRunner(RunStore(getattr(args, "store", ".sentinel/runs/state.db")))
        resolved = runner.load([args.config], profile=getattr(args, "profile_name", None), environment=getattr(args, "environment", None))
        return _emit(runner.plan(resolved.data, Path(args.config).parent), getattr(args, "output", None))
    if action == "eval-run":
        runner = EvalRunner(RunStore(getattr(args, "store", ".sentinel/runs/state.db")))
        result = runner.run([args.config], profile=getattr(args, "profile_name", None), environment=getattr(args, "environment", None))
        report = render_report(result, getattr(args, "report_format", "json"))
        _emit(report, getattr(args, "output", None))
        return int(result["summary"]["exit_code"])
    if action == "replay":
        runner = EvalRunner(RunStore(getattr(args, "store", ".sentinel/runs/state.db")))
        return _emit(runner.replay(args.run_id), getattr(args, "output", None))
    if action == "trace":
        store = RunStore(getattr(args, "store", ".sentinel/runs/state.db"))
        run = store.get_run(args.run_id)
        if not run:
            raise ValueError(f"unknown run: {args.run_id}")
        return _emit({"schema_version": "sentinel.trace.list.v1", "run_id": args.run_id, "traces": run["traces"]}, getattr(args, "output", None))
    if action == "redteam-plan":
        packs = getattr(args, "packs", None)
        return _emit(AttackRegistry().plan(packs), getattr(args, "output", None))
    if action == "redteam-run":
        return _emit(RedTeamRunner().run({"packs": getattr(args, "packs", None) or []}), getattr(args, "output", None))
    if action == "runtime-inspect":
        event = json.loads(args.event)
        decision = RuntimePolicyEngine(getattr(args, "mode", "simulate")).inspect(event)
        return _emit({"schema_version": "sentinel.runtime.decision.v1", "decision": decision.__dict__}, getattr(args, "output", None))
    console.print_json(json.dumps({"error": "unknown platform action"}))
    return 2


def cmd_platform_eval(args):
    args.platform_action = "eval-run" if not getattr(args, "plan", False) else "eval-plan"
    args.report_format = getattr(args, "eval_report_format", getattr(args, "format", "json"))
    if args.report_format == "table":
        args.report_format = "json"
    return cmd_platform(args)


def cmd_platform_replay(args):
    args.platform_action = "replay"
    return cmd_platform(args)


def cmd_platform_trace(args):
    args.platform_action = "trace"
    return cmd_platform(args)


def cmd_platform_export(args):
    store = RunStore(getattr(args, "store", ".sentinel/runs/state.db"))
    run = store.get_run(args.run_id)
    if not run:
        raise ValueError(f"unknown run: {args.run_id}")
    result = {"run": {k: v for k, v in run.items() if k not in {"cells", "assertions", "traces"}}, "summary": run["summary"], "cells": run["cells"]}
    return _emit(render_report(result, args.export_format), getattr(args, "output", None))


def cmd_platform_import(args):
    data = json.loads(Path(args.path).read_text(encoding="utf-8"))
    return _emit({"schema_version": "sentinel.import.v1", "accepted": isinstance(data, dict), "source": args.path}, getattr(args, "output", None))


def cmd_platform_explain(args):
    resolved = resolve_config([args.config], profile=getattr(args, "profile_name", None), environment=getattr(args, "environment", None))
    return _emit(explain_config(resolved), getattr(args, "output", None))


def cmd_platform_simulate(args):
    resolved = resolve_config([args.config], profile=getattr(args, "profile_name", None), environment=getattr(args, "environment", None))
    return _emit(simulate_config(resolved.data), getattr(args, "output", None))


def cmd_platform_profile(args):
    resolved = resolve_config([args.config], profile=getattr(args, "profile_name", None), environment=getattr(args, "environment", None))
    return _emit({"schema_version": "sentinel.profile.v1", "profile": getattr(args, "profile_name", None), "config": resolved.data, "simulation": simulate_config(resolved.data)}, getattr(args, "output", None))


def cmd_platform_inspect(args):
    if args.inspect_kind == "dataset":
        dataset = load_dataset(args.path)
        return _emit({"schema_version": "sentinel.dataset.inspect.v1", "id": dataset.id, "fingerprint": dataset.fingerprint, "record_count": len(dataset.records), "sample": [record.__dict__ for record in dataset.records[:5]]}, getattr(args, "output", None))
    resolved = resolve_config([args.path])
    return _emit({"schema_version": "sentinel.config.inspect.v1", "fingerprint": resolved.fingerprint, "keys": sorted(resolved.data)}, getattr(args, "output", None))


def cmd_platform_compare(args):
    store = RunStore(getattr(args, "store", ".sentinel/runs/state.db"))
    left = store.get_run(args.left_run)
    right = store.get_run(args.right_run)
    if not left or not right:
        raise ValueError("both runs must exist")
    left_summary = left["summary"]
    right_summary = right["summary"]
    return _emit(
        {
            "schema_version": "sentinel.compare.v1",
            "left": {"run_id": args.left_run, "summary": left_summary},
            "right": {"run_id": args.right_run, "summary": right_summary},
            "delta": {
                "pass_rate": float(right_summary.get("pass_rate", 0)) - float(left_summary.get("pass_rate", 0)),
                "failed": int(right_summary.get("failed", 0)) - int(left_summary.get("failed", 0)),
            },
        },
        getattr(args, "output", None),
    )
