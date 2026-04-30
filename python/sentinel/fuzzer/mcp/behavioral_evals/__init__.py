"""
MCP Behavioral Analysis Evaluation Suite.

MITRE ATT&CK-inspired categories for evaluating MCP server behavior.
Each eval script tests for a specific class of malicious behavior.
"""

from sentinel.fuzzer.mcp.behavioral_evals.runner import BehavioralEvalRunner

__all__ = ["BehavioralEvalRunner"]
