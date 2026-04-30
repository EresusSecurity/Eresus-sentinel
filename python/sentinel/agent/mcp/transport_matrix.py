"""MCP transport parity matrix for live-scanner coverage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class MCPTransportSpec:
    name: str
    status: str
    scanner_surface: str
    scans_tools: bool
    scans_prompts: bool
    scans_resources: bool
    scans_instructions: bool
    auth_probe: str
    notes: str


MCP_TRANSPORT_MATRIX: tuple[MCPTransportSpec, ...] = (
    MCPTransportSpec(
        name="manifest",
        status="native-live",
        scanner_surface="MCPLiveScanner.scan_manifest",
        scans_tools=True,
        scans_prompts=True,
        scans_resources=True,
        scans_instructions=True,
        auth_probe="metadata auth declaration",
        notes="Offline JSON/YAML manifest scan with prompt/resource/instruction analysis.",
    ),
    MCPTransportSpec(
        name="http-jsonrpc",
        status="native-live",
        scanner_surface="MCPLiveScanner.scan_http",
        scans_tools=True,
        scans_prompts=True,
        scans_resources=True,
        scans_instructions=False,
        auth_probe="missing-auth finding for HTTP endpoints",
        notes="Deterministic JSON-RPC discovery over HTTP POST.",
    ),
    MCPTransportSpec(
        name="stdio",
        status="native-live",
        scanner_surface="MCPLiveScanner.scan_stdio",
        scans_tools=True,
        scans_prompts=True,
        scans_resources=True,
        scans_instructions=False,
        auth_probe="not applicable",
        notes="Launches a local stdio MCP command and runs JSON-RPC discovery.",
    ),
    MCPTransportSpec(
        name="sse",
        status="partial",
        scanner_surface="transport stance",
        scans_tools=False,
        scans_prompts=False,
        scans_resources=False,
        scans_instructions=False,
        auth_probe="planned bearer/OAuth fixture",
        notes=(
            "Reference supports SSE; Sentinel records the gap without "
            "network-only core dependencies."
        ),
    ),
    MCPTransportSpec(
        name="streamable-http",
        status="partial",
        scanner_surface="transport stance",
        scans_tools=False,
        scans_prompts=False,
        scans_resources=False,
        scans_instructions=False,
        auth_probe="planned bearer/OAuth fixture",
        notes="Reference supports streamable HTTP; current core handles JSON-RPC HTTP POST.",
    ),
    MCPTransportSpec(
        name="oauth",
        status="partial",
        scanner_surface="auth model/readiness",
        scans_tools=False,
        scans_prompts=False,
        scans_resources=False,
        scans_instructions=False,
        auth_probe="MCPAuthConfig redacted evidence",
        notes=(
            "Auth object model exists; live OAuth flow probing remains "
            "optional/integration-only."
        ),
    ),
)


def mcp_transport_matrix() -> tuple[MCPTransportSpec, ...]:
    return MCP_TRANSPORT_MATRIX


def mcp_transport_summary() -> dict[str, Any]:
    native = [spec for spec in MCP_TRANSPORT_MATRIX if spec.status == "native-live"]
    partial = [spec for spec in MCP_TRANSPORT_MATRIX if spec.status == "partial"]
    return {
        "total": len(MCP_TRANSPORT_MATRIX),
        "native_live": len(native),
        "partial": len(partial),
        "scans_prompts_resources": sum(
            1 for spec in native if spec.scans_prompts and spec.scans_resources
        ),
        "transports": [asdict(spec) for spec in MCP_TRANSPORT_MATRIX],
    }


__all__ = [
    "MCP_TRANSPORT_MATRIX",
    "MCPTransportSpec",
    "mcp_transport_matrix",
    "mcp_transport_summary",
]
