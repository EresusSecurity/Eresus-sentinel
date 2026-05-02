"""Live and manifest-based MCP server scanner."""

from __future__ import annotations

import json
import ipaddress
import queue
import subprocess
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from sentinel.agent.mcp.prompt_defense import PromptDefenseAnalyzer
from sentinel.agent.mcp.readiness_analyzer import ReadinessAnalyzer
from sentinel.agent.mcp.validator import MCPValidator
from sentinel.finding import Finding, Severity


@dataclass
class MCPLiveScanResult:
    """Result from a manifest, HTTP, or stdio MCP scan."""

    source: str
    transport: str
    server_info: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    instructions: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    readiness_score: float = 0.0
    readiness_grade: str = "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mcp-scan.v1",
            "source": self.source,
            "transport": self.transport,
            "server_info": self.server_info,
            "capabilities": self.capabilities,
            "auth": _auth_summary(self.server_info, self.capabilities),
            "counts": {
                "tools": len(self.tools),
                "prompts": len(self.prompts),
                "resources": len(self.resources),
                "instructions": len(self.instructions),
                "findings": len(self.findings),
                "errors": len(self.errors),
            },
            "readiness_score": round(self.readiness_score, 2),
            "readiness_grade": self.readiness_grade,
            "errors": self.errors,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class MCPManifestExtractor:
    """Normalize common MCP manifest and JSON-RPC response shapes."""

    def extract(self, payload: dict[str, Any], source: str, transport: str) -> MCPLiveScanResult:
        server_info = self._server_info(payload, source)
        capabilities = _as_dict(
            payload.get("capabilities") or payload.get("serverCapabilities") or {}
        )
        if payload.get("auth"):
            capabilities.setdefault("auth", payload["auth"])
        if payload.get("authorization"):
            capabilities.setdefault("authorization", payload["authorization"])
        tools = self._extract_items(payload, "tools")
        if not tools and (payload.get("inputSchema") or payload.get("name")):
            tools = [payload]
        result = MCPLiveScanResult(
            source=source,
            transport=transport,
            server_info=server_info,
            capabilities=capabilities,
            tools=tools,
            prompts=self._extract_items(payload, "prompts"),
            resources=self._extract_items(payload, "resources"),
            instructions=self._extract_instructions(payload),
        )
        return result

    def merge_rpc_results(
        self,
        source: str,
        transport: str,
        responses: dict[str, dict[str, Any]],
        errors: list[str],
    ) -> MCPLiveScanResult:
        initialize = responses.get("initialize", {})
        base = initialize.get("result", initialize)
        result = self.extract(base if isinstance(base, dict) else {}, source, transport)
        result.tools = self._extract_items(responses.get("tools/list", {}), "tools")
        result.prompts = self._extract_items(responses.get("prompts/list", {}), "prompts")
        result.resources = self._extract_items(responses.get("resources/list", {}), "resources")
        result.errors.extend(errors)
        return result

    @staticmethod
    def _server_info(payload: dict[str, Any], source: str) -> dict[str, Any]:
        result_payload = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        server_info = _as_dict(
            payload.get("serverInfo")
            or payload.get("server")
            or payload.get("info")
            or result_payload.get("serverInfo")
            or {}
        )
        if not server_info:
            server_info = {
                "name": payload.get("name") or Path(source).stem,
                "version": payload.get("version") or "",
                "description": payload.get("description") or "",
            }
        return server_info

    def _extract_items(self, payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
        candidates = [
            payload.get(key),
            payload.get("result", {}).get(key) if isinstance(payload.get("result"), dict) else None,
            payload.get("capabilities", {}).get(key)
            if isinstance(payload.get("capabilities"), dict)
            else None,
        ]
        for candidate in candidates:
            items = self._items_from_candidate(candidate, key)
            if items:
                return items
        return []

    @staticmethod
    def _items_from_candidate(candidate: Any, key: str) -> list[dict[str, Any]]:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
        if isinstance(candidate, dict):
            nested = candidate.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
            if candidate.get("name") or candidate.get("uri"):
                return [candidate]
        return []

    @staticmethod
    def _extract_instructions(payload: dict[str, Any]) -> list[str]:
        instructions: list[str] = []
        for key in ("instructions", "systemPrompt", "system_prompt", "toolInstructions"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                instructions.append(value)
            elif isinstance(value, list):
                instructions.extend(str(item) for item in value if str(item).strip())
        return instructions


class MCPLiveScanner:
    """Scan MCP servers from manifests, HTTP JSON-RPC endpoints, or stdio commands."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self._extractor = MCPManifestExtractor()
        self._validator = MCPValidator(enable_extended=True)
        self._prompt_defense = PromptDefenseAnalyzer()
        self._readiness = ReadinessAnalyzer()

    def scan_manifest(self, path: str | Path) -> MCPLiveScanResult:
        manifest_path = Path(path)
        payload = _load_manifest(manifest_path)
        result = self._extractor.extract(payload, str(manifest_path), "manifest")
        result.findings.extend(self._validator.validate_file(str(manifest_path)))
        self._analyze(result)
        try:
            from sentinel.agent.a2a_scanner import A2AScanner
            result.findings.extend(A2AScanner().scan_path(manifest_path))
        except Exception as exc:
            result.errors.append(f"A2A manifest validation failed: {exc}")
        result.findings = _deduplicate_findings(result.findings)
        return result

    def scan_http(self, url: str) -> MCPLiveScanResult:
        responses: dict[str, dict[str, Any]] = {}
        errors: list[str] = []
        for request_id, method in enumerate(
            ("initialize", "tools/list", "prompts/list", "resources/list"),
            start=1,
        ):
            try:
                responses[method] = self._http_jsonrpc(url, method, request_id)
            except Exception as exc:
                errors.append(f"{method}: {exc}")
        result = self._extractor.merge_rpc_results(url, "http", responses, errors)
        self._analyze(result)
        if not responses:
            result.findings.append(_connection_finding(url, "; ".join(errors)))
        return result

    def scan_stdio(self, command: list[str]) -> MCPLiveScanResult:
        source = " ".join(command)
        responses: dict[str, dict[str, Any]] = {}
        errors: list[str] = []
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for request_id, method in enumerate(
                ("initialize", "tools/list", "prompts/list", "resources/list"),
                start=1,
            ):
                try:
                    responses[method] = self._stdio_jsonrpc(proc, method, request_id)
                except Exception as exc:
                    errors.append(f"{method}: {exc}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()

        result = self._extractor.merge_rpc_results(source, "stdio", responses, errors)
        self._analyze(result)
        if not responses:
            result.findings.append(_connection_finding(source, "; ".join(errors)))
        return result

    def _analyze(self, result: MCPLiveScanResult) -> None:
        result.findings.extend(
            self._validator.validate_server(
                result.server_info,
                result.tools,
                result.capabilities,
                source=result.source,
            )
        )
        result.findings.extend(self._scan_prompt_like_items(result))
        result.findings.extend(self._scan_resource_uris(result))
        self._score_readiness(result)
        self._check_auth_surface(result)

    def _scan_prompt_like_items(self, result: MCPLiveScanResult) -> list[Finding]:
        findings: list[Finding] = []
        for kind, items in (("prompt", result.prompts), ("resource", result.resources)):
            for item in items:
                name = str(item.get("name") or item.get("uri") or "<unnamed>")
                text = str(
                    item.get("description")
                    or item.get("content")
                    or item.get("template")
                    or item.get("text")
                    or ""
                )
                synthetic = {
                    "name": f"{kind}:{name}",
                    "description": text,
                    "inputSchema": {"properties": {}, "required": []},
                }
                defense = self._prompt_defense.analyze_tool(synthetic)
                for issue in defense.issues:
                    findings.append(
                        Finding.agent_mcp(
                            rule_id=f"MCP-LIVE-{kind.upper()}-001",
                            title=f"Prompt injection in MCP {kind}",
                            description=(
                                f"MCP {kind} '{name}' field '{issue.field}' contains "
                                f"potential prompt injection content."
                            ),
                            severity=Severity.HIGH if issue.severity == "HIGH" else Severity.MEDIUM,
                            target=result.source,
                            evidence=issue.snippet,
                        )
                    )

        for idx, instruction in enumerate(result.instructions, start=1):
            defense = self._prompt_defense.analyze_tool(
                {
                    "name": f"instruction:{idx}",
                    "description": instruction,
                    "inputSchema": {"properties": {}, "required": []},
                }
            )
            for issue in defense.issues:
                findings.append(
                    Finding.agent_mcp(
                        rule_id="MCP-LIVE-INSTRUCTION-001",
                        title="Prompt injection in MCP server instructions",
                        description="Server-level MCP instructions contain injection-like content.",
                        severity=Severity.HIGH if issue.severity == "HIGH" else Severity.MEDIUM,
                        target=result.source,
                        evidence=issue.snippet,
                    )
                )
        return findings

    def _scan_resource_uris(self, result: MCPLiveScanResult) -> list[Finding]:
        findings: list[Finding] = []
        for item in result.resources:
            uri = str(item.get("uri") or item.get("name") or "")
            if not uri:
                continue
            parsed = urlparse(uri)
            lowered = uri.lower()
            if _resource_path_traversal(lowered):
                findings.append(
                    Finding.agent_mcp(
                        rule_id="MCP-LIVE-RESOURCE-002",
                        title="MCP resource URI path traversal",
                        description=(
                            "MCP resource URI references parent traversal or a sensitive "
                            "local file path."
                        ),
                        severity=Severity.HIGH,
                        target=result.source,
                        evidence=uri[:300],
                        confidence=0.9,
                    )
                )
            if parsed.scheme in {"http", "https"} and _is_private_host(parsed.hostname or ""):
                findings.append(
                    Finding.agent_mcp(
                        rule_id="MCP-LIVE-RESOURCE-003",
                        title="MCP resource URI targets internal network",
                        description=(
                            "MCP resource URI points at localhost, private IP space, "
                            "or a metadata endpoint and may enable SSRF."
                        ),
                        severity=Severity.HIGH,
                        target=result.source,
                        evidence=uri[:300],
                        confidence=0.9,
                    )
                )
        return findings

    def _score_readiness(self, result: MCPLiveScanResult) -> None:
        readiness = self._readiness.analyze(
            result.server_info,
            result.tools,
            result.capabilities,
        )
        result.readiness_score = readiness.percentage
        result.readiness_grade = readiness.grade

    def _check_auth_surface(self, result: MCPLiveScanResult) -> None:
        if result.transport not in {"http", "manifest"}:
            return
        auth_declared = bool(
            result.capabilities.get("auth")
            or result.capabilities.get("authorization")
            or result.server_info.get("auth")
            or result.server_info.get("authorization")
        )
        if result.transport == "http" and not auth_declared:
            result.findings.append(
                Finding.agent_mcp(
                    rule_id="MCP-LIVE-AUTH-001",
                    title="MCP HTTP endpoint does not declare auth",
                    description=(
                        "Live MCP HTTP scan did not observe OAuth, authorization, or API-key "
                        "capabilities in server metadata."
                    ),
                    severity=Severity.MEDIUM,
                    target=result.source,
                    confidence=0.7,
                )
            )

    def _http_jsonrpc(self, url: str, method: str, request_id: int) -> dict[str, Any]:
        if urlparse(url).scheme not in {"http", "https"}:
            raise ValueError("MCP HTTP scan only supports http:// and https:// URLs")
        body = json.dumps(_jsonrpc_request(method, request_id)).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc

    def _stdio_jsonrpc(
        self,
        proc: subprocess.Popen[str],
        method: str,
        request_id: int,
    ) -> dict[str, Any]:
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("stdio pipes are unavailable")
        proc.stdin.write(json.dumps(_jsonrpc_request(method, request_id)) + "\n")
        proc.stdin.flush()
        line = _readline_with_timeout(proc.stdout, self.timeout)
        if not line:
            raise TimeoutError(f"timeout waiting for {method}")
        return json.loads(line)


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"MCP manifest not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("MCP manifest must be a mapping")
    return data


def _readline_with_timeout(stream, timeout: float) -> str:
    lines: queue.Queue[str] = queue.Queue(maxsize=1)

    def read_line() -> None:
        lines.put(stream.readline())

    thread = threading.Thread(target=read_line, daemon=True)
    thread.start()
    try:
        return lines.get(timeout=timeout)
    except queue.Empty:
        return ""


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.target, finding.evidence or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _jsonrpc_request(method: str, request_id: int) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if method == "initialize":
        params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "sentinel", "version": "0.1"},
        }
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def _connection_finding(source: str, evidence: str) -> Finding:
    return Finding.agent_mcp(
        rule_id="MCP-LIVE-CONNECT-001",
        title="Unable to connect to MCP server",
        description="Sentinel could not complete live MCP JSON-RPC discovery.",
        severity=Severity.HIGH,
        target=source,
        evidence=evidence,
        confidence=0.8,
    )


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _auth_summary(server_info: dict[str, Any], capabilities: dict[str, Any]) -> dict[str, Any]:
    auth = (
        capabilities.get("auth")
        or capabilities.get("authorization")
        or server_info.get("auth")
        or server_info.get("authorization")
        or {}
    )
    auth_dict = auth if isinstance(auth, dict) else {"type": str(auth)}
    auth_type = str(auth_dict.get("type") or auth_dict.get("scheme") or "").lower()
    return {
        "declared": bool(auth),
        "type": auth_type or "",
        "supports_oauth": "oauth" in auth_type,
        "supports_bearer": "bearer" in auth_type,
        "supports_api_key": auth_type in {"api_key", "apikey", "x-api-key"},
        "supports_mtls": auth_type in {"mtls", "m_tls", "mutual_tls", "mutual-tls"},
    }


def _resource_path_traversal(uri: str) -> bool:
    return (
        "../" in uri
        or "..\\" in uri
        or uri.startswith("file:///etc/")
        or uri.startswith("file://etc/")
        or "/etc/passwd" in uri
        or "\\windows\\system32" in uri
    )


def _is_private_host(hostname: str) -> bool:
    host = hostname.strip().lower().strip("[]")
    if not host:
        return False
    if host in {"localhost", "metadata.google.internal"}:
        return True
    if host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or str(ip) == "169.254.169.254"
    )


def scan_mcp_manifest(path: str | Path) -> MCPLiveScanResult:
    """Convenience wrapper for offline MCP manifest scans."""

    return MCPLiveScanner().scan_manifest(path)
