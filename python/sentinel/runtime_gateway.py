"""Runtime LLM gateway contract.

The gateway is intentionally provider-adapter based: Sentinel owns policy
enforcement and observability, while concrete providers remain swappable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any

from sentinel.firewall.base import ScanAction, ScanResult
from sentinel.middleware import SentinelMiddleware

if TYPE_CHECKING:
    from collections.abc import Callable

    from sentinel.finding import Finding


class GatewayMode(str, Enum):
    """Runtime enforcement mode."""

    ENFORCE = "enforce"
    MONITOR = "monitor"
    PASSTHROUGH = "passthrough"


class GatewayAction(str, Enum):
    """Gateway decision action."""

    PASS = "pass"  # noqa: S105
    WARN = "warn"
    BLOCK = "block"
    ERROR = "error"


@dataclass
class GatewayRequest:
    """Provider-neutral LLM request."""

    prompt: str
    messages: list[dict[str, str]] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GatewayResponse:
    """Provider-neutral LLM response."""

    text: str
    model: str = ""
    status_code: int = 200
    raw: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GatewayDecision:
    """Full gateway decision with scan context."""

    action: GatewayAction
    request: GatewayRequest
    response: GatewayResponse | None = None
    input_result: ScanResult | None = None
    output_result: ScanResult | None = None
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.action == GatewayAction.BLOCK

    @property
    def findings(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.input_result:
            findings.extend(self.input_result.findings)
        if self.output_result:
            findings.extend(self.output_result.findings)
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "blocked": self.blocked,
            "request": {
                "prompt": self.request.prompt,
                "provider": self.request.provider,
                "model": self.request.model,
                "metadata": self.request.metadata,
            },
            "response": {
                "text": self.response.text,
                "model": self.response.model,
                "status_code": self.response.status_code,
                "metadata": self.response.metadata,
            }
            if self.response
            else None,
            "error": self.error,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }


class ProviderAdapter(ABC):
    """Provider adapter contract for runtime LLM calls."""

    name = "provider"

    @abstractmethod
    def complete(self, request: GatewayRequest) -> GatewayResponse:
        """Execute one completion request."""


class EchoProviderAdapter(ProviderAdapter):
    """Deterministic provider adapter for tests and dry runs."""

    name = "echo"

    def __init__(self, response_text: str | None = None) -> None:
        self._response_text = response_text

    def complete(self, request: GatewayRequest) -> GatewayResponse:
        return GatewayResponse(
            text=self._response_text if self._response_text is not None else request.prompt,
            model=request.model or "echo",
            metadata={"provider": self.name},
        )


class CallableProviderAdapter(ProviderAdapter):
    """Wrap any callable into the gateway provider contract."""

    name = "callable"

    def __init__(self, func: Callable[[GatewayRequest], str | GatewayResponse]) -> None:
        self._func = func

    def complete(self, request: GatewayRequest) -> GatewayResponse:
        result = self._func(request)
        if isinstance(result, GatewayResponse):
            return result
        return GatewayResponse(
            text=str(result),
            model=request.model,
            metadata={"provider": self.name},
        )


class SentinelGateway:
    """Runtime guardrail gateway for LLM traffic."""

    def __init__(
        self,
        provider: ProviderAdapter | None = None,
        mode: GatewayMode | str = GatewayMode.ENFORCE,
        middleware: SentinelMiddleware | None = None,
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        block_message: str = "I cannot process this request due to safety policies.",
    ) -> None:
        self.provider = provider or EchoProviderAdapter()
        self.mode = GatewayMode(mode)
        self.block_message = block_message
        self.middleware = middleware or SentinelMiddleware(
            input_scanners=input_scanners,
            output_scanners=output_scanners,
            block_message=block_message,
        )

    def complete(self, prompt: str, **metadata: Any) -> GatewayDecision:
        request = GatewayRequest(prompt=prompt, metadata=metadata)
        return self.handle(request)

    def handle(self, request: GatewayRequest) -> GatewayDecision:
        if self.mode == GatewayMode.PASSTHROUGH:
            response = self.provider.complete(request)
            return GatewayDecision(action=GatewayAction.PASS, request=request, response=response)

        try:
            input_result = self.middleware.guard_input(request.prompt)
            if self._should_block(input_result):
                return GatewayDecision(
                    action=GatewayAction.BLOCK,
                    request=request,
                    response=GatewayResponse(
                        text=self.block_message,
                        status_code=403,
                        metadata={"blocked_at": "input"},
                    ),
                    input_result=input_result,
                )

            provider_request = replace(request, prompt=input_result.sanitized)
            provider_response = self.provider.complete(provider_request)
            output_result = self.middleware.guard_output(request.prompt, provider_response.text)

            if self._should_block(output_result):
                return GatewayDecision(
                    action=GatewayAction.BLOCK,
                    request=request,
                    response=GatewayResponse(
                        text=self.block_message,
                        model=provider_response.model,
                        status_code=403,
                        raw=provider_response.raw,
                        metadata={"blocked_at": "output"},
                    ),
                    input_result=input_result,
                    output_result=output_result,
                )

            response = provider_response
            if self.mode == GatewayMode.ENFORCE and output_result.action == ScanAction.REDACT:
                response = replace(provider_response, text=output_result.sanitized)

            action = (
                GatewayAction.WARN
                if input_result.findings or output_result.findings
                else GatewayAction.PASS
            )
            return GatewayDecision(
                action=action,
                request=request,
                response=response,
                input_result=input_result,
                output_result=output_result,
            )
        except Exception as exc:
            return GatewayDecision(
                action=GatewayAction.ERROR,
                request=request,
                error=str(exc),
                response=GatewayResponse(text=str(exc), status_code=500),
            )

    def _should_block(self, result: ScanResult) -> bool:
        return self.mode == GatewayMode.ENFORCE and result.action == ScanAction.BLOCK
