"""MCP (Model Context Protocol) fuzzer backend.

Generates adversarial JSON-RPC 2.0 messages, tool call payloads,
and prompt injection attacks targeting MCP server implementations.
"""

from .generator import MCPGenerator
from .mutators import MCPMutator
from .payloads import MCPPayloadFactory
from .stateful import MCPFlow, MCPFlowStep, StatefulMCPFuzzer

__all__ = [
    "MCPGenerator",
    "MCPMutator",
    "MCPPayloadFactory",
    "MCPFlow",
    "MCPFlowStep",
    "StatefulMCPFuzzer",
]
