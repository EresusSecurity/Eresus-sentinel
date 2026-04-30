"""MCP inventory model — tools, prompts, resources per server."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MCPToolDef:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPPromptDef:
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MCPResourceDef:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


@dataclass
class MCPServerInventory:
    server_name: str
    transport: str = "stdio"
    command: str = ""
    tools: list[MCPToolDef] = field(default_factory=list)
    prompts: list[MCPPromptDef] = field(default_factory=list)
    resources: list[MCPResourceDef] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def tool_count(self) -> int:
        return len(self.tools)

    @property
    def prompt_count(self) -> int:
        return len(self.prompts)

    @property
    def resource_count(self) -> int:
        return len(self.resources)

    @property
    def total_capabilities(self) -> int:
        return self.tool_count + self.prompt_count + self.resource_count


class MCPInventoryIndex:
    """Index multiple MCP server inventories."""

    def __init__(self) -> None:
        self._servers: dict[str, MCPServerInventory] = {}

    def add(self, inventory: MCPServerInventory) -> None:
        self._servers[inventory.server_name] = inventory

    def get(self, name: str) -> MCPServerInventory | None:
        return self._servers.get(name)

    def all_tools(self) -> list[tuple[str, MCPToolDef]]:
        return [(s.server_name, t) for s in self._servers.values() for t in s.tools]

    def find_tool(self, tool_name: str) -> list[tuple[str, MCPToolDef]]:
        return [(s.server_name, t) for s in self._servers.values()
                for t in s.tools if t.name == tool_name]

    @property
    def server_count(self) -> int:
        return len(self._servers)

    @property
    def total_tools(self) -> int:
        return sum(s.tool_count for s in self._servers.values())
