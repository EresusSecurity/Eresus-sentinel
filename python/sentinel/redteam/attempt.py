"""
Red Team Attempt Model.

Tracks the full lifecycle of an adversarial probe:
prompt → response → detection → scoring.

Supports multi-turn conversations and encoding tracking.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class AttemptStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    RECEIVED = "received"
    DETECTED = "detected"
    FAILED = "failed"


@dataclass
class Message:
    """A single message in a conversation."""
    role: str          # "system", "user", "assistant"
    content: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Attempt:
    """
    Encapsulates a single red team probe attempt.

    Tracks the complete lifecycle from prompt construction
    through response capture to detection scoring.

    Extended with multi-turn conversation support.
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    probe_classname: str = ""
    detector_classname: str = ""

    # Attack content
    prompt: str = ""
    triggers: list[str] = field(default_factory=list)
    encoding_used: Optional[str] = None

    # Response
    response: Optional[str] = None
    status: AttemptStatus = AttemptStatus.PENDING

    # Detection
    detector_score: float = 0.0    # 0.0 = benign, 1.0 = vulnerability found
    detector_results: dict = field(default_factory=dict)

    # Conversation context (for multi-turn probes)
    conversation: list[Message] = field(default_factory=list)
    turn_number: int = 0

    # Metadata
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict = field(default_factory=dict)

    def add_user_message(self, content: str) -> None:
        """Add a user message to the conversation."""
        self.conversation.append(Message(role="user", content=content))
        self.turn_number = len(
            [m for m in self.conversation if m.role == "user"]
        )

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant response to the conversation."""
        self.conversation.append(Message(role="assistant", content=content))

    def add_system_message(self, content: str) -> None:
        """Add a system message to the conversation."""
        self.conversation.append(Message(role="system", content=content))

    @property
    def is_successful_attack(self) -> bool:
        """True if the probe triggered a vulnerability."""
        return self.detector_score >= 0.5

    def to_dict(self) -> dict:
        """Serialize attempt for reporting."""
        return {
            "id": self.id,
            "probe_classname": self.probe_classname,
            "detector_classname": self.detector_classname,
            "prompt": self.prompt,
            "triggers": self.triggers,
            "encoding_used": self.encoding_used,
            "response": self.response,
            "status": self.status.value,
            "detector_score": self.detector_score,
            "conversation": [
                {"role": m.role, "content": m.content}
                for m in self.conversation
            ],
            "turn_number": self.turn_number,
            "timestamp": self.timestamp,
            "is_successful_attack": self.is_successful_attack,
        }
