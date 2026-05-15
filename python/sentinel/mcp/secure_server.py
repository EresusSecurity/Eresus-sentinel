from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, BinaryIO

from sentinel import __version__
from sentinel.platform.assertions import AssertionRegistry
from sentinel.platform.config import explain_config, resolve_config
from sentinel.platform.dataset import load_dataset
from sentinel.platform.providers import ProviderRegistry
from sentinel.platform.redteam import AttackRegistry, RedTeamRunner
from sentinel.platform.reports import render_report
from sentinel.platform.runtime import RuntimePolicyEngine
from sentinel.platform.runner import EvalRunner
from sentinel.platform.store import RunStore
from sentinel.plugins.manifest import discover_manifests, manifest_to_dict, validate_manifest, validate_manifest_file

MAX_MESSAGE_BYTES = 1024 * 1024


class SecureMCPServer:
    def __init__(self, workspace_root: str | Path = ".") -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()

    def handle_request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id")
        method = str(message.get("method") or "")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        try:
            if method == "initialize":
                return self._response(request_id, {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "eresus-sentinel-secure-mcp", "version": __version__},
                })
            if method == "notifications/initialized":
                return None
            if method == "tools/list":
                return self._response(request_id, {"tools": self._tools()})
            if method == "tools/call":
                return self._response(request_id, self._call_tool(params))
            return self._error(request_id, -32601, f"Unknown method: {method}")
        except ValueError as exc:
            return self._error(request_id, -32602, str(exc))
        except Exception:
            return self._error(request_id, -32603, "Internal server error")

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if name == "sentinel.health":
            payload = self._health()
        elif name == "sentinel.plugins.list":
            payload = self._list_plugins()
        elif name == "sentinel.plugins.validate":
            payload = self._validate_plugin(arguments)
        elif name == "sentinel.rules.list":
            payload = self._list_rules()
        elif name == "sentinel.config.validate":
            payload = self._config_validate(arguments)
        elif name == "sentinel.config.explain":
            payload = self._config_explain(arguments)
        elif name == "sentinel.dataset.inspect":
            payload = self._dataset_inspect(arguments)
        elif name == "sentinel.provider.test":
            payload = self._provider_test(arguments)
        elif name == "sentinel.eval.run":
            payload = self._eval_run(arguments)
        elif name == "sentinel.eval.replay":
            payload = self._eval_replay(arguments)
        elif name == "sentinel.assertion.run":
            payload = self._assertion_run(arguments)
        elif name == "sentinel.redteam.plan":
            payload = self._redteam_plan(arguments)
        elif name == "sentinel.redteam.run":
            payload = self._redteam_run(arguments)
        elif name == "sentinel.runtime.session.inspect":
            payload = self._runtime_session_inspect(arguments)
        elif name == "sentinel.report.export":
            payload = self._report_export(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}],
            "structuredContent": payload,
            "isError": False,
        }

    def _health(self) -> dict[str, Any]:
        return {
            "schema_version": "sentinel.mcp.health.v1",
            "status": "ready",
            "server": "eresus-sentinel-secure-mcp",
            "version": __version__,
            "workspace_root": str(self.workspace_root),
            "capabilities": [
                "health",
                "plugins.list",
                "plugins.validate",
                "rules.list",
                "config.validate",
                "config.explain",
                "dataset.inspect",
                "provider.test",
                "eval.run",
                "eval.replay",
                "assertion.run",
                "redteam.plan",
                "redteam.run",
                "runtime.session.inspect",
                "report.export",
            ],
        }

    def _list_plugins(self) -> dict[str, Any]:
        manifests = []
        for manifest in discover_manifests(self.workspace_root):
            issues = validate_manifest(manifest)
            manifests.append(manifest_to_dict(manifest, issues))
        return {
            "schema_version": "sentinel.mcp.plugins.v1",
            "workspace_root": str(self.workspace_root),
            "plugins": manifests,
        }

    def _validate_plugin(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_path = arguments.get("path")
        if not raw_path:
            raise ValueError("path is required")
        path = self._resolve_workspace_path(str(raw_path))
        manifest, issues = validate_manifest_file(path, workspace_root=self.workspace_root)
        return {
            "schema_version": "sentinel.mcp.plugin_validation.v1",
            "manifest": manifest_to_dict(manifest, issues) if manifest else None,
            "issues": [issue.__dict__ for issue in issues],
        }

    def _list_rules(self) -> dict[str, Any]:
        roots = [
            self.workspace_root / "rules",
            self.workspace_root / "python" / "sentinel" / "config" / "yara_rules",
        ]
        rules = []
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in {".sentinel", ".yaml", ".yml", ".json", ".toml", ".yar", ".yara"}:
                    continue
                resolved = path.resolve()
                try:
                    resolved.relative_to(self.workspace_root)
                except ValueError:
                    continue
                rules.append({
                    "path": str(resolved),
                    "name": resolved.stem,
                    "format": resolved.suffix.lower().lstrip("."),
                    "bytes": resolved.stat().st_size,
                })
        return {
            "schema_version": "sentinel.mcp.rules.v1",
            "workspace_root": str(self.workspace_root),
            "rules": sorted(rules, key=lambda item: item["path"]),
        }

    def _config_validate(self, arguments: dict[str, Any]) -> dict[str, Any]:
        from sentinel.platform.config import lint_config

        path = self._resolve_workspace_path(str(arguments.get("path") or "sentinel.sntl"))
        resolved = resolve_config([path], profile=arguments.get("profile"), environment=arguments.get("environment"))
        issues = lint_config(resolved.data)
        return {"schema_version": "sentinel.mcp.config_validation.v1", "ok": not any(issue["severity"] == "error" for issue in issues), "issues": issues, "fingerprint": resolved.fingerprint}

    def _config_explain(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve_workspace_path(str(arguments.get("path") or "sentinel.sntl"))
        resolved = resolve_config([path], profile=arguments.get("profile"), environment=arguments.get("environment"))
        return explain_config(resolved)

    def _dataset_inspect(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve_workspace_path(str(arguments.get("path") or "dataset.sntl"))
        dataset = load_dataset(path, key=arguments.get("key"))
        return {
            "schema_version": "sentinel.mcp.dataset_inspect.v1",
            "id": dataset.id,
            "fingerprint": dataset.fingerprint,
            "lineage": dataset.lineage,
            "record_count": len(dataset.records),
            "sample": [record.__dict__ for record in dataset.records[:5]],
        }

    def _provider_test(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return ProviderRegistry().test(str(arguments.get("provider") or arguments.get("id") or "mock"), arguments.get("config") if isinstance(arguments.get("config"), dict) else {})

    def _eval_run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._resolve_workspace_path(str(arguments.get("path") or "sentinel.sntl"))
        runner = EvalRunner(RunStore(self.workspace_root / ".sentinel" / "runs" / "state.db"))
        return runner.run([path], profile=arguments.get("profile"), environment=arguments.get("environment"), base_dir=path.parent)

    def _eval_replay(self, arguments: dict[str, Any]) -> dict[str, Any]:
        run_id = str(arguments.get("run_id") or "")
        if not run_id:
            raise ValueError("run_id is required")
        runner = EvalRunner(RunStore(self.workspace_root / ".sentinel" / "runs" / "state.db"))
        return runner.replay(run_id)

    def _assertion_run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        spec = arguments.get("assertion") if isinstance(arguments.get("assertion"), dict) else {}
        outcome = AssertionRegistry().evaluate(spec, str(arguments.get("output") or ""), arguments.get("context") if isinstance(arguments.get("context"), dict) else {})
        return {"schema_version": "sentinel.mcp.assertion_result.v1", "outcome": outcome.__dict__}

    def _redteam_plan(self, arguments: dict[str, Any]) -> dict[str, Any]:
        packs = arguments.get("packs") if isinstance(arguments.get("packs"), list) else None
        return AttackRegistry().plan([str(item) for item in packs] if packs else None)

    def _redteam_run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return RedTeamRunner().run(arguments)

    def _runtime_session_inspect(self, arguments: dict[str, Any]) -> dict[str, Any]:
        engine = RuntimePolicyEngine(str(arguments.get("mode") or "simulate"))
        event = arguments.get("event") if isinstance(arguments.get("event"), dict) else {}
        decision = engine.inspect(event)
        return {"schema_version": "sentinel.mcp.runtime_session.v1", "session_id": str(arguments.get("session_id") or "local"), "decision": decision.__dict__}

    def _report_export(self, arguments: dict[str, Any]) -> dict[str, Any]:
        run_id = str(arguments.get("run_id") or "")
        if not run_id:
            raise ValueError("run_id is required")
        store = RunStore(self.workspace_root / ".sentinel" / "runs" / "state.db")
        run = store.get_run(run_id)
        if not run:
            raise ValueError(f"unknown run: {run_id}")
        result = {"run": {k: v for k, v in run.items() if k not in {"cells", "assertions", "traces"}}, "summary": run["summary"], "cells": run["cells"]}
        fmt = str(arguments.get("format") or "json")
        return {"schema_version": "sentinel.mcp.report_export.v1", "format": fmt, "content": render_report(result, fmt)}

    def _resolve_workspace_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.workspace_root / path
        resolved = path.resolve()
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError:
            raise ValueError(f"path escapes workspace root: {value}")
        return resolved

    def _tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "sentinel.health",
                "description": "Return secure local Sentinel MCP server status.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "sentinel.plugins.list",
                "description": "List trusted Sentinel plugin manifests inside the workspace.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "sentinel.plugins.validate",
                "description": "Validate one Sentinel plugin manifest without executing it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "sentinel.rules.list",
                "description": "List Sentinel rule files and YARA rule packs inside the workspace.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "sentinel.config.validate",
                "description": "Validate a Sentinel config deterministically.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "profile": {"type": "string"}, "environment": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
            },
            {
                "name": "sentinel.config.explain",
                "description": "Explain Sentinel config resolution.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "profile": {"type": "string"}, "environment": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
            },
            {
                "name": "sentinel.dataset.inspect",
                "description": "Inspect a local dataset without provider calls.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "key": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
            },
            {
                "name": "sentinel.provider.test",
                "description": "Validate provider configuration and policy constraints.",
                "inputSchema": {"type": "object", "properties": {"provider": {"type": "string"}, "config": {"type": "object"}}, "required": ["provider"], "additionalProperties": False},
            },
            {
                "name": "sentinel.eval.run",
                "description": "Run a deterministic local evaluation suite.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "profile": {"type": "string"}, "environment": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
            },
            {
                "name": "sentinel.eval.replay",
                "description": "Replay a stored evaluation run.",
                "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"], "additionalProperties": False},
            },
            {
                "name": "sentinel.assertion.run",
                "description": "Run one deterministic assertion.",
                "inputSchema": {"type": "object", "properties": {"assertion": {"type": "object"}, "output": {"type": "string"}, "context": {"type": "object"}}, "required": ["assertion", "output"], "additionalProperties": False},
            },
            {
                "name": "sentinel.redteam.plan",
                "description": "Build a deterministic red-team attack plan.",
                "inputSchema": {"type": "object", "properties": {"packs": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": False},
            },
            {
                "name": "sentinel.redteam.run",
                "description": "Run deterministic red-team attack packs with offline defaults.",
                "inputSchema": {"type": "object", "properties": {"packs": {"type": "array", "items": {"type": "string"}}, "provider": {"type": "object"}}, "additionalProperties": False},
            },
            {
                "name": "sentinel.runtime.session.inspect",
                "description": "Inspect a runtime security session.",
                "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}, "mode": {"type": "string"}, "event": {"type": "object"}}, "additionalProperties": False},
            },
            {
                "name": "sentinel.report.export",
                "description": "Export a stored run report.",
                "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}, "format": {"type": "string"}}, "required": ["run_id"], "additionalProperties": False},
            },
        ]

    def _response(self, request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _error(self, request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def serve_stdio(workspace_root: str | Path = ".") -> int:
    server = SecureMCPServer(workspace_root)
    reader = sys.stdin.buffer
    writer = sys.stdout.buffer
    while True:
        item = _read_message(reader)
        if item is None:
            return 0
        message, framed = item
        if not isinstance(message, dict):
            _write_message(writer, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}, framed)
            continue
        response = server.handle_request(message)
        if response is not None:
            _write_message(writer, response, framed)


def _read_message(reader: BinaryIO) -> tuple[Any, bool] | None:
    first = reader.readline(MAX_MESSAGE_BYTES + 1)
    if not first:
        return None
    if len(first) > MAX_MESSAGE_BYTES:
        raise ValueError("MCP message exceeds maximum size")
    if first.lower().startswith(b"content-length:"):
        headers = [first]
        while True:
            line = reader.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                return None
            if line in {b"\r\n", b"\n"}:
                break
            headers.append(line)
        content_length = _content_length(headers)
        if content_length > MAX_MESSAGE_BYTES:
            raise ValueError("MCP message exceeds maximum size")
        payload = reader.read(content_length)
        return json.loads(payload.decode("utf-8")), True
    text = first.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    return json.loads(text), False


def _content_length(headers: list[bytes]) -> int:
    for header in headers:
        name, _, value = header.decode("ascii", errors="ignore").partition(":")
        if name.lower() == "content-length":
            length = int(value.strip())
            if length < 0:
                raise ValueError("Negative Content-Length")
            return length
    raise ValueError("Missing Content-Length")


def _write_message(writer: BinaryIO, response: dict[str, Any], framed: bool) -> None:
    payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
    if framed:
        writer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
        writer.write(payload)
    else:
        writer.write(payload + b"\n")
    writer.flush()
