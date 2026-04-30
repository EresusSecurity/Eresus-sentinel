"""Agent signature database for framework/pattern identification."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentSignature:
    name: str
    framework: str
    patterns: tuple[str, ...]
    component_type: str = "agent"
    description: str = ""
    confidence: float = 0.9


_BUILTIN_SIGNATURES: list[AgentSignature] = [
    AgentSignature("langchain-react", "langchain", (r"create_react_agent", r"AgentExecutor"), description="LangChain ReAct agent"),
    AgentSignature("langgraph-state", "langgraph", (r"StateGraph\s*\(", r"add_node\s*\("), description="LangGraph stateful agent"),
    AgentSignature("crewai-crew", "crewai", (r"Crew\s*\(", r"Agent\s*\(.*role\s*="), description="CrewAI multi-agent crew"),
    AgentSignature("autogen-chat", "autogen", (r"AssistantAgent\s*\(", r"UserProxyAgent\s*\("), description="AutoGen conversational agent"),
    AgentSignature("openai-assistant", "openai", (r"client\.beta\.assistants\.create\s*\(", r"thread.*run"), description="OpenAI Assistants API"),
    AgentSignature("google-adk", "google-adk", (r"from\s+google\.adk", r"Agent\s*\(.*model\s*="), description="Google Agent Development Kit"),
    AgentSignature("smolagents", "smolagents", (r"from\s+smolagents", r"ToolCallingAgent\s*\("), description="HuggingFace smolagents"),
    AgentSignature("pydantic-ai", "pydantic-ai", (r"from\s+pydantic_ai", r"Agent\s*\(.*model\s*="), description="PydanticAI agent"),
    AgentSignature("a2a-server", "a2a", (r"A2AServer\s*\(", r"AgentCard\s*\("), description="A2A protocol server"),
    AgentSignature("mcp-server", "mcp", (r"@mcp\.tool", r"McpServer\s*\("), description="MCP tool server"),
]


class SignatureDB:
    """Database of agent signatures for pattern matching."""

    def __init__(self) -> None:
        self._signatures: list[AgentSignature] = list(_BUILTIN_SIGNATURES)
        self._compiled: list[tuple[AgentSignature, list[re.Pattern]]] = []
        self._compile()

    def _compile(self) -> None:
        self._compiled = []
        for sig in self._signatures:
            compiled = [re.compile(p) for p in sig.patterns]
            self._compiled.append((sig, compiled))

    def add(self, sig: AgentSignature) -> None:
        self._signatures.append(sig)
        self._compiled.append((sig, [re.compile(p) for p in sig.patterns]))

    def match(self, text: str) -> list[tuple[AgentSignature, float]]:
        matches: list[tuple[AgentSignature, float]] = []
        for sig, compiled in self._compiled:
            hit_count = sum(1 for rx in compiled if rx.search(text))
            if hit_count > 0:
                ratio = hit_count / len(compiled)
                confidence = sig.confidence * ratio
                matches.append((sig, confidence))
        return sorted(matches, key=lambda x: -x[1])

    @property
    def size(self) -> int:
        return len(self._signatures)

    def all_names(self) -> list[str]:
        return [s.name for s in self._signatures]
