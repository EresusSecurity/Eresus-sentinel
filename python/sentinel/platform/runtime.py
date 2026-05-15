from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from sentinel.platform.formats import stable_sha256


@dataclass(frozen=True)
class RuntimeDecision:
    id: str
    action: str
    mode: str
    reason: str
    findings: list[dict[str, Any]]
    sanitized_output: str | None
    trace: list[dict[str, Any]] = field(default_factory=list)


class RuntimePolicyEngine:
    def __init__(self, mode: str = "simulate") -> None:
        self.mode = mode if mode in {"simulate", "enforce"} else "simulate"
        self.secret_patterns = [
            re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
            re.compile(r"\b[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
            re.compile(r"(?i)\b(api[_-]?key|secret|password|token)\s*[:=]\s*[^\s]+"),
        ]
        self.exfil_patterns = [
            re.compile(r"(?i)\b(upload|exfiltrate|send|post)\b.{0,80}\b(secret|token|credential|private key)\b"),
            re.compile(r"(?i)\bbase64\b.{0,80}\b(secret|token|credential|private key)\b"),
        ]
        self.blocked_tools = {"shell", "exec", "filesystem.write", "network.raw", "browser.cookies"}

    def inspect(self, event: dict[str, Any]) -> RuntimeDecision:
        event_type = str(event.get("type") or "prompt")
        text = str(event.get("prompt") or event.get("output") or event.get("text") or "")
        tool = str(event.get("tool") or "")
        findings: list[dict[str, Any]] = []
        trace = [{"name": "runtime.inspect", "event_type": event_type, "mode": self.mode, "timestamp": time.time()}]
        for pattern in self.secret_patterns:
            if pattern.search(text):
                findings.append({"rule_id": "RUNTIME-SECRET", "severity": "HIGH", "kind": "secret", "evidence": pattern.pattern})
        for pattern in self.exfil_patterns:
            if pattern.search(text):
                findings.append({"rule_id": "RUNTIME-EXFIL", "severity": "CRITICAL", "kind": "exfiltration", "evidence": pattern.pattern})
        if tool and tool in self.blocked_tools:
            findings.append({"rule_id": "RUNTIME-TOOL", "severity": "HIGH", "kind": "tool", "tool": tool})
        sanitized = self._sanitize(text) if findings and event_type == "output" else None
        action = "block" if findings and self.mode == "enforce" else "observe" if findings else "allow"
        decision_id = f"rtd_{stable_sha256({'event': event, 'findings': findings, 'mode': self.mode})[:24]}"
        return RuntimeDecision(decision_id, action, self.mode, "policy findings present" if findings else "no policy findings", findings, sanitized, trace)

    def _sanitize(self, text: str) -> str:
        sanitized = text
        for pattern in self.secret_patterns:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized
