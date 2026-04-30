"""MCP authentication configuration model with redacted evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MCPAuthType(str, Enum):
    NONE = "none"
    API_KEY = "api-key"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    CUSTOM = "custom"


@dataclass
class MCPAuthConfig:
    auth_type: MCPAuthType = MCPAuthType.NONE
    token_env_var: str = ""
    oauth_scopes: list[str] = field(default_factory=list)
    tls_client_cert: bool = False
    rate_limit_rpm: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_authenticated(self) -> bool:
        return self.auth_type != MCPAuthType.NONE

    def redacted_evidence(self) -> dict[str, Any]:
        evidence: dict[str, Any] = {"auth_type": self.auth_type.value}
        if self.token_env_var:
            evidence["token_env_var"] = self.token_env_var
        if self.oauth_scopes:
            evidence["oauth_scopes"] = self.oauth_scopes
        if self.tls_client_cert:
            evidence["tls_client_cert"] = True
        if self.rate_limit_rpm:
            evidence["rate_limit_rpm"] = self.rate_limit_rpm
        return evidence


@dataclass
class MCPServerAuth:
    server_name: str
    config: MCPAuthConfig = field(default_factory=MCPAuthConfig)
    risk_flags: list[str] = field(default_factory=list)

    def assess_risk(self) -> list[str]:
        flags: list[str] = []
        if not self.config.is_authenticated():
            flags.append("no-auth-configured")
        if self.config.auth_type == MCPAuthType.API_KEY and not self.config.token_env_var:
            flags.append("hardcoded-api-key-risk")
        if not self.config.tls_client_cert and self.config.auth_type == MCPAuthType.MTLS:
            flags.append("mtls-without-client-cert")
        if self.config.rate_limit_rpm == 0:
            flags.append("no-rate-limit")
        self.risk_flags = flags
        return flags
