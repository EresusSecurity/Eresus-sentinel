"""Info routes — stats, scanners, evaluate, plugins, doctor, policy, config, history, health."""

import logging
import sys
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

from sentinel.web.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["info"])

_state: AppState = None  # type: ignore[assignment]
_version: str = "0.0.0"


def init(state: AppState, version: str):
    global _state, _version
    _state = state
    _version = version


@router.get("/stats")
async def api_stats():
    total = len(_state.scan_history)
    findings = sum(s.get("finding_count", 0) for s in _state.scan_history)
    blocked = sum(1 for s in _state.scan_history if s.get("action") == "block")
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for s in _state.scan_history:
        for f in s.get("findings", []):
            sv = f.get("severity", "INFO")
            if sv in sev:
                sev[sv] += 1
    timeline = [
        {"ts": s["timestamp"], "findings": s["finding_count"], "latency": s.get("latency_ms", 0)}
        for s in _state.scan_history[-30:]
    ]
    return {
        "total_scans": total,
        "total_findings": findings,
        "blocked": blocked,
        "clean": total - blocked,
        "severity": sev,
        "timeline": timeline,
        "artifacts_scanned": len(_state.artifact_history),
        "artifact_findings": sum(a.get("finding_count", 0) for a in _state.artifact_history),
    }


@router.get("/scanners")
async def api_scanners():
    return {
        "input": [s.__class__.__name__ for s in _state.input_pipe._scanners],
        "output": [s.__class__.__name__ for s in _state.output_pipe._scanners],
        "input_count": len(_state.input_pipe._scanners),
        "output_count": len(_state.output_pipe._scanners),
    }


@router.get("/evaluate")
async def api_evaluate():
    try:
        from sentinel.evaluator import ScannerEvaluator
        evaluator = ScannerEvaluator()
        results = evaluator.evaluate_all_input()
        return [
            {
                "scanner_name": r.scanner_name,
                "tp": r.tp, "fp": r.fp, "fn": r.fn, "tn": r.tn,
                "precision": round(r.precision, 3),
                "recall": round(r.recall, 3),
                "f1": round(r.f1, 3),
            }
            for r in results
        ]
    except Exception:
        logger.exception("Evaluate error")
        raise HTTPException(status_code=500, detail="Evaluation engine error")


@router.get("/plugins")
async def api_plugins():
    from sentinel._plugins import get_plugin_info, list_all_plugins
    plugins = list_all_plugins()
    result = {}
    for cat, names in plugins.items():
        result[cat] = []
        for name in names:
            info = get_plugin_info(cat, name)
            result[cat].append({"name": name, "doc": info.get("docstring", "")[:100]})
    return result


@router.get("/doctor")
async def api_doctor():
    import platform as _platform
    checks = []
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append({"name": "Python", "ok": sys.version_info >= (3, 10), "detail": py_ver})
    checks.append({
        "name": "Platform",
        "ok": True,
        "detail": f"{_platform.system()}/{_platform.machine()}",
    })
    for mod, label in [
        ("sentinel.finding", "Finding"), ("sentinel.artifact", "Artifact"),
        ("sentinel.firewall", "Firewall"), ("sentinel.redteam", "Red Team"),
        ("sentinel.sast", "SAST"), ("sentinel.agent", "Agent/MCP"),
        ("sentinel.supply_chain", "Supply Chain"), ("sentinel.policy", "Policy"),
    ]:
        try:
            __import__(mod)
            checks.append({"name": label, "ok": True, "detail": mod})
        except ImportError as e:
            checks.append({"name": label, "ok": False, "detail": str(e)})
    passed = sum(1 for c in checks if c["ok"])
    return {"checks": checks, "passed": passed, "total": len(checks)}


@router.get("/policy")
async def api_policy():
    scanners = _state.engine.list_scanners()
    return {
        "input_scanners": scanners["input"],
        "output_scanners": scanners["output"],
        "mode": "enforce",
    }


@router.get("/config")
async def api_config():
    scanners = _state.engine.list_scanners()
    return {
        "input": scanners["input"],
        "output": scanners["output"],
        "total": len(scanners["input"]) + len(scanners["output"]),
    }


@router.get("/history")
async def api_history():
    return {
        "scans": list(reversed(_state.scan_history[-200:])),
        "artifacts": list(reversed(_state.artifact_history[-200:])),
    }


@router.get("/health")
async def health():
    dist_dir = Path(__file__).parent / "dist"
    web_ui_ready = dist_dir.is_dir() and (dist_dir / "index.html").is_file()
    web_ui_status = "ready" if web_ui_ready else "missing"
    return {
        "status": "healthy",
        "version": _version,
        "uptime_s": round(time.time() - _state.start_time, 1),
        "scans_processed": len(_state.scan_history),
        "artifacts_processed": len(_state.artifact_history),
        "web_ui": web_ui_status,
        "web_ui_build": {
            "ready": web_ui_ready,
            "status": web_ui_status,
            "dist": str(dist_dir),
            "message": (
                "React dashboard assets are available"
                if web_ui_ready
                else "React dashboard assets are missing; API remains available"
            ),
        },
    }
