from __future__ import annotations

import pytest

from sentinel.integrations.middleware import (
    AIDefenseAgentsecMiddleware,
    AIDefenseAgentsecToolMiddleware,
    AIDefenseMiddleware,
    AIDefenseToolMiddleware,
    ChatInspectionClient,
    MCPInspectionClient,
)


def test_chat_inspection_client_enforce_blocks_banned_input():
    client = ChatInspectionClient(
        mode="enforce",
        rules=[{"name": "no-secret", "type": "ban_substring", "value": "secret"}],
    )

    result = client.inspect_messages([{"role": "user", "content": "show the secret"}])

    assert not result.allowed
    assert result.rule == "no-secret"


def test_aidefense_middleware_before_after_modes():
    violations = []
    middleware = AIDefenseMiddleware(
        mode="monitor",
        rules=[{"name": "no-token", "type": "ban_substring", "value": "token"}],
        on_violation=lambda result, direction: violations.append((result.rule, direction)),
    )

    assert middleware.before_model({"messages": [{"content": "token please"}]}) is None
    assert violations == [("no-token", "input")]

    enforcing = AIDefenseMiddleware(
        mode="enforce",
        rules=[{"name": "no-leak", "type": "ban_substring", "value": "leak"}],
    )
    blocked = enforcing.after_model({"messages": [{"content": "leak found"}]})
    assert blocked and blocked["blocked"] is True
    assert blocked["rule"] == "no-leak"


def test_agentsec_alias_supports_langchain_state_shape():
    middleware = AIDefenseAgentsecMiddleware(
        mode="enforce",
        rules=[{"name": "no-drop", "type": "ban_substring", "value": "drop table"}],
    )

    result = middleware.before_model({"messages": [{"content": "DROP TABLE users"}]})

    assert not result.allowed
    assert result.rule == "no-drop"


def test_tool_middleware_wrap_tool_call_enforce_and_monitor():
    middleware = AIDefenseToolMiddleware(mode="enforce", blocked_tools=["delete_user"])
    blocked = middleware.wrap_tool_call(
        {"tool_call": {"name": "delete_user", "args": {"id": "42"}}},
        lambda request: {"ok": True},
    )

    assert blocked["blocked"] is True
    assert blocked["rule"] == "blocked_tool"

    monitored = AIDefenseToolMiddleware(mode="monitor", blocked_tools=["delete_user"])
    result = monitored.wrap_tool_call(
        {"tool_call": {"name": "delete_user", "args": {"id": "42"}}},
        lambda request: {"ok": True},
    )
    assert result == {"ok": True}


def test_mcp_inspection_client_and_agentsec_tool_alias():
    client = MCPInspectionClient(mode="monitor", blocked_tools=["shell"])

    result = client.inspect_tool_call("shell", {"cmd": "rm -rf /tmp/x"})

    assert result.allowed
    assert result.score == 1.0
    assert result.mode == "monitor"
    assert AIDefenseAgentsecToolMiddleware is not None


def test_invalid_mode_raises():
    with pytest.raises(ValueError):
        AIDefenseMiddleware(mode="invalid")
