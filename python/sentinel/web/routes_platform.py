from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from sentinel.platform.assertions import AssertionRegistry
from sentinel.platform.config import config_graph, explain_config, lint_config, resolve_config, simulate_config
from sentinel.platform.dataset import inline_dataset, load_dataset
from sentinel.platform.hygiene import run_hygiene_gate
from sentinel.platform.providers import ProviderRegistry
from sentinel.platform.redteam import AttackRegistry, RedTeamRunner
from sentinel.platform.reports import render_report
from sentinel.platform.runtime import RuntimePolicyEngine
from sentinel.platform.runner import EvalRunner
from sentinel.platform.store import RunStore
from sentinel.web.state import AppState

router = APIRouter(prefix="/api", tags=["platform"])

_state: AppState = None
_store = RunStore()
_providers = ProviderRegistry()
_assertions = AssertionRegistry()
_runner = EvalRunner(_store, _providers, _assertions)
_attacks = AttackRegistry()
_redteam = RedTeamRunner(_providers, _assertions, _attacks)


def init(state: AppState):
    global _state
    _state = state


def _base() -> Path:
    return Path.cwd().resolve()


def _safe_path(value: str) -> Path:
    path = Path(value).expanduser()
    resolved = path.resolve() if path.is_absolute() else (_base() / path).resolve()
    if _base() not in (resolved, *resolved.parents):
        raise HTTPException(status_code=400, detail="Path is outside workspace")
    return resolved


async def _json(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    return data


@router.get("/providers")
async def providers_list():
    return {"schema_version": "sentinel.provider.registry.v1", "providers": _providers.list()}


@router.post("/providers/test")
async def providers_test(request: Request):
    data = await _json(request)
    provider_id = str(data.get("id") or data.get("provider") or "mock")
    return _providers.test(provider_id, data.get("config") or {})


@router.get("/assertions")
async def assertions_list():
    return {"schema_version": "sentinel.assertion.registry.v1", "assertions": _assertions.list()}


@router.post("/assertions/run")
async def assertions_run(request: Request):
    data = await _json(request)
    spec = data.get("assertion") or data.get("spec") or {}
    if not isinstance(spec, dict):
        raise HTTPException(status_code=400, detail="assertion must be an object")
    outcome = _assertions.evaluate(spec, str(data.get("output", "")), data.get("context") or {})
    return {"schema_version": "sentinel.assertion.result.v1", "outcome": outcome.__dict__}


@router.post("/datasets/inspect")
async def datasets_inspect(request: Request):
    data = await _json(request)
    if data.get("records") is not None:
        records = data["records"]
        if not isinstance(records, list):
            raise HTTPException(status_code=400, detail="records must be a list")
        dataset = inline_dataset(records, str(data.get("id") or "inline"))
    else:
        path = _safe_path(str(data.get("path", "")))
        dataset = load_dataset(path, key=data.get("key"))
    return {
        "schema_version": "sentinel.dataset.inspect.v1",
        "id": dataset.id,
        "fingerprint": dataset.fingerprint,
        "lineage": dataset.lineage,
        "record_count": len(dataset.records),
        "sample": [record.__dict__ for record in dataset.records[:5]],
    }


@router.post("/evals/plan")
async def evals_plan(request: Request):
    data = await _json(request)
    config = data.get("config") or data
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="config must be an object")
    issues = lint_config(config)
    errors = [issue for issue in issues if issue["severity"] == "error"]
    if errors:
        raise HTTPException(status_code=400, detail={"issues": errors})
    return _runner.plan(config, _base())


@router.post("/evals/run")
async def evals_run(request: Request):
    data = await _json(request)
    config = data.get("config") or data
    if not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="config must be an object")
    with tempfile.NamedTemporaryFile("w", suffix=".json", dir=_base(), delete=False, encoding="utf-8") as handle:
        json.dump(config, handle)
        tmp_path = Path(handle.name)
    try:
        return _runner.run([tmp_path], base_dir=_base())
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/runs")
async def runs_list():
    return {"schema_version": "sentinel.run.list.v1", "runs": _store.list_runs()}


@router.get("/runs/{run_id}")
async def runs_get(run_id: str):
    run = _store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.get("/traces/{run_id}")
async def traces_get(run_id: str):
    run = _store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"schema_version": "sentinel.trace.list.v1", "run_id": run_id, "traces": run["traces"]}


@router.post("/config/resolve")
async def config_resolve(request: Request):
    data = await _json(request)
    paths = [_safe_path(str(path)) for path in data.get("paths", [])]
    if not paths:
        raise HTTPException(status_code=400, detail="paths must not be empty")
    resolved = resolve_config(paths, profile=data.get("profile"), environment=data.get("environment"), overrides=data.get("overrides"))
    return {"schema_version": "sentinel.config.resolved.v1", "config": resolved.data, "explain": explain_config(resolved), "graph": config_graph(resolved), "simulation": simulate_config(resolved.data)}


@router.post("/reports/export")
async def reports_export(request: Request):
    data = await _json(request)
    run_id = str(data.get("run_id", ""))
    fmt = str(data.get("format", "json"))
    run = _store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    result = {"run": {k: v for k, v in run.items() if k not in {"cells", "assertions", "traces"}}, "summary": run["summary"], "cells": run["cells"]}
    return {"schema_version": "sentinel.report.export.v1", "format": fmt, "content": render_report(result, fmt)}


@router.get("/baselines")
async def baselines_list():
    return {"schema_version": "sentinel.baseline.list.v1", "baselines": []}


@router.get("/policies")
async def policies_list():
    return {"schema_version": "sentinel.policy.list.v1", "policies": [{"id": "local-deterministic", "mode": "enforceable"}]}


@router.get("/runtime-sessions")
async def runtime_sessions_list():
    return {"schema_version": "sentinel.runtime.session.list.v1", "sessions": []}


@router.post("/runtime-sessions/inspect")
async def runtime_sessions_inspect(request: Request):
    data = await _json(request)
    engine = RuntimePolicyEngine(str(data.get("mode") or "simulate"))
    decision = engine.inspect(data.get("event") if isinstance(data.get("event"), dict) else data)
    return {"schema_version": "sentinel.runtime.decision.v1", "decision": decision.__dict__}


@router.get("/redteam/packs")
async def redteam_packs():
    return {"schema_version": "sentinel.redteam.registry.v1", "packs": _attacks.list()}


@router.post("/redteam/plan")
async def redteam_plan(request: Request):
    data = await _json(request)
    packs = [str(item) for item in data.get("packs", [])] if isinstance(data.get("packs"), list) else None
    return _attacks.plan(packs)


@router.post("/redteam/run")
async def redteam_run(request: Request):
    data = await _json(request)
    return _redteam.run(data)


@router.get("/orgs")
async def orgs_list():
    return {"schema_version": "sentinel.org.list.v1", "orgs": [{"id": "local", "name": "Local"}]}


@router.get("/projects")
async def projects_list():
    return {"schema_version": "sentinel.project.list.v1", "projects": [{"id": "default", "org_id": "local", "name": "Default"}]}


@router.get("/api-keys")
async def api_keys_list():
    return {"schema_version": "sentinel.api-key.list.v1", "api_keys": []}


@router.get("/audit")
async def audit_list():
    return {"schema_version": "sentinel.audit.list.v1", "events": []}


@router.get("/hygiene")
async def hygiene_get():
    return run_hygiene_gate(_base())
