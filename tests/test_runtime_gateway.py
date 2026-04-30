from sentinel.firewall.base import ScanAction, ScanResult
from sentinel.runtime_gateway import (
    CallableProviderAdapter,
    EchoProviderAdapter,
    GatewayAction,
    GatewayMode,
    SentinelGateway,
)


class FakeMiddleware:
    def guard_input(self, prompt):
        if "block input" in prompt:
            return ScanResult(prompt, ScanAction.BLOCK, 1.0)
        return ScanResult(prompt.replace("raw", "safe"), ScanAction.PASS, 0.0)

    def guard_output(self, _prompt, output):
        if "block output" in output:
            return ScanResult(output, ScanAction.BLOCK, 1.0)
        if "secret" in output:
            return ScanResult("[redacted]", ScanAction.REDACT, 0.7)
        return ScanResult(output, ScanAction.PASS, 0.0)


def test_gateway_enforces_input_blocks_before_provider_call():
    calls = []
    gateway = SentinelGateway(
        provider=CallableProviderAdapter(lambda request: calls.append(request.prompt) or "ok"),
        middleware=FakeMiddleware(),
    )

    decision = gateway.complete("please block input")

    assert decision.action == GatewayAction.BLOCK
    assert decision.response.status_code == 403
    assert calls == []


def test_gateway_sends_sanitized_prompt_and_redacts_output():
    seen = []

    def provider(request):
        seen.append(request.prompt)
        return "secret response"

    gateway = SentinelGateway(
        provider=CallableProviderAdapter(provider),
        middleware=FakeMiddleware(),
    )

    decision = gateway.complete("raw prompt")

    assert seen == ["safe prompt"]
    assert decision.action == GatewayAction.PASS
    assert decision.response.text == "[redacted]"


def test_gateway_monitor_mode_does_not_block_or_redact():
    gateway = SentinelGateway(
        provider=EchoProviderAdapter("secret block output"),
        mode=GatewayMode.MONITOR,
        middleware=FakeMiddleware(),
    )

    decision = gateway.complete("block input")

    assert decision.action == GatewayAction.PASS
    assert decision.response.text == "secret block output"
