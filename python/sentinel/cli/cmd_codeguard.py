"""CodeGuard, sandbox, and runtime tool-inspection CLI commands."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from rich import box
from rich.table import Table

from sentinel.cli._export import _export
from sentinel.cli._helpers import (
    _apply_severity_filter,
    _fail,
    _header,
    _ok,
    _print_findings,
    console,
    machine_stdout,
)
from sentinel.codeguard import CODEGUARD_SCHEMA_VERSION, CodeGuardScanner


DEFAULT_SANDBOX_POLICY = {
    "schema_version": "sandbox.policy.v1",
    "timeout_seconds": 30,
    "allowed_hosts": [],
    "blocked_paths": [
        "/etc/passwd",
        "/etc/shadow",
        "/root",
        "/proc/self",
        "/sys",
        "/dev/mem",
        "/dev/kmem",
        "/var/run/docker.sock",
    ],
    "allowed_syscalls": [],
    "block_network": True,
}


def cmd_codeguard(args) -> int:
    """Run CodeGuard static analysis."""
    action = getattr(args, "codeguard_action", "scan") or "scan"
    if action != "scan":
        _fail(f"unknown codeguard action: {action}")
        return 2

    path_value = getattr(args, "path", None)
    if not path_value:
        _fail("usage: sentinel codeguard scan PATH")
        return 2
    target = Path(path_value)
    if not target.exists():
        _fail(f"target not found: {target}")
        return 2

    findings = CodeGuardScanner().scan_path(target)
    findings = _apply_severity_filter(findings, args)

    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None):
        _export(args, findings)
        return 1 if findings else 0

    _header(f"codeguard scan → {target}", args=args)
    _print_findings(findings, "CodeGuard", args=args)
    if findings:
        _print_summary_table(findings)
    return 1 if findings else 0


def cmd_sandbox(args) -> int:
    """Configure and run commands through lightweight sandbox policy checks."""
    if getattr(args, "json_output", False):
        args.format = "json"
        console.file = sys.stderr

    action = getattr(args, "sandbox_action", "setup") or "setup"
    if action == "setup":
        return _cmd_sandbox_setup(args)
    if action == "run":
        return _cmd_sandbox_run(args)
    _fail(f"unknown sandbox action: {action}")
    return 2


def _cmd_sandbox_setup(args) -> int:
    output = Path(getattr(args, "output", "sandbox.yaml"))
    policy = dict(DEFAULT_SANDBOX_POLICY)
    policy["created_at"] = int(time.time())
    _write_policy(output, policy)

    payload = {
        "schema_version": "sandbox.setup.v1",
        "summary": {"status": "ok", "path": str(output)},
        "policy": policy,
    }
    if getattr(args, "json_output", False):
        _write_json(payload)
    else:
        _ok(f"written sandbox policy at {output}")
    return 0


def _cmd_sandbox_run(args) -> int:
    policy_path = Path(getattr(args, "policy", "sandbox.yaml"))
    if not policy_path.exists():
        _fail(f"policy not found: {policy_path}")
        return 2

    command = list(getattr(args, "cmd", []) or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _fail("sandbox run requires a command")
        return 2

    policy = _load_policy(policy_path)
    violations = _policy_violations(policy, command)
    if violations:
        _record_sandbox_event(command, "block", policy_path, violations)
        payload = _sandbox_payload(command, policy_path, policy, violations, returncode=None)
        if getattr(args, "json_output", False):
            _write_json(payload)
        else:
            _fail(f"sandbox blocked command: {violations[0]['description']}")
        return 1

    timeout = float(policy.get("timeout_seconds", DEFAULT_SANDBOX_POLICY["timeout_seconds"]))
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
    except subprocess.TimeoutExpired:
        violations = [{
            "type": "TIMEOUT",
            "severity": "HIGH",
            "description": f"Command exceeded sandbox timeout: {timeout}s",
        }]
        _record_sandbox_event(command, "block", policy_path, violations)
        payload = _sandbox_payload(command, policy_path, policy, violations, returncode=None)
        if getattr(args, "json_output", False):
            _write_json(payload)
        else:
            _fail(violations[0]["description"])
        return 1

    payload = _sandbox_payload(
        command,
        policy_path,
        policy,
        [],
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        elapsed_ms=elapsed_ms,
    )
    _record_sandbox_event(command, "allow", policy_path, [])
    if getattr(args, "json_output", False):
        _write_json(payload)
    else:
        if completed.stdout:
            machine_stdout().write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        _ok(f"sandbox command exited {completed.returncode}")
    return completed.returncode


def _print_summary_table(findings) -> None:
    table = Table(title="CodeGuard Summary", box=box.SIMPLE_HEAVY)
    table.add_column("rule")
    table.add_column("count", justify="right")
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    for rule_id, count in sorted(counts.items()):
        table.add_row(rule_id, str(count))
    console.print(table)


def _write_policy(path: Path, policy: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
        return
    try:
        import yaml
        path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    except Exception:
        path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")


def _load_policy(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
            data = yaml.safe_load(text) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            pass
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _policy_violations(policy: dict[str, Any], command: list[str]) -> list[dict[str, str]]:
    command_text = " ".join(command)
    blocked_paths = policy.get("blocked_paths") or DEFAULT_SANDBOX_POLICY["blocked_paths"]
    violations: list[dict[str, str]] = []
    for blocked in blocked_paths:
        if blocked and blocked in command_text:
            violations.append({
                "type": "PATH_ACCESS",
                "severity": "CRITICAL",
                "description": f"Command references blocked path: {blocked}",
                "path": blocked,
            })
    if policy.get("block_network", True) and any(tok in command[0].lower() for tok in ("curl", "wget", "nc", "ncat")):
        violations.append({
            "type": "NETWORK",
            "severity": "HIGH",
            "description": "Network-capable command blocked by sandbox policy",
        })
    return violations


def _sandbox_payload(
    command: list[str],
    policy_path: Path,
    policy: dict[str, Any],
    violations: list[dict[str, str]],
    *,
    returncode: int | None,
    stdout: str = "",
    stderr: str = "",
    elapsed_ms: float = 0.0,
) -> dict[str, Any]:
    return {
        "schema_version": "sandbox.run.v1",
        "summary": {
            "status": "blocked" if violations else "completed",
            "returncode": returncode,
            "violation_count": len(violations),
            "elapsed_ms": round(elapsed_ms, 3),
        },
        "policy": {
            "path": str(policy_path),
            "block_network": bool(policy.get("block_network", True)),
            "blocked_paths": list(policy.get("blocked_paths", [])),
            "allowed_syscalls": list(policy.get("allowed_syscalls", [])),
        },
        "command": command,
        "stdout": stdout,
        "stderr": stderr,
        "violations": violations,
    }


def _record_sandbox_event(command: list[str], verdict: str, policy_path: Path, violations: list[dict[str, str]]) -> None:
    try:
        from sentinel.audit_store import AuditStore
        AuditStore().record(
            event_type="sandbox.violation" if violations else "sandbox.run",
            target=command[0] if command else "",
            verdict=verdict,
            payload={
                "command": " ".join(command),
                "policy": str(policy_path),
                "violations": violations,
                "schema_version": CODEGUARD_SCHEMA_VERSION,
            },
        )
    except Exception:
        pass


def _write_json(payload: dict[str, Any]) -> None:
    out_stream = machine_stdout()
    out_stream.write(json.dumps(payload, indent=2, default=str))
    out_stream.write("\n")
    out_stream.flush()
