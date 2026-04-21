"""Back-compat re-export of the MCP validator.

The implementation lives in ``sentinel.agent.mcp``.
"""

from .mcp import MCPValidator

__all__ = ["MCPValidator"]
