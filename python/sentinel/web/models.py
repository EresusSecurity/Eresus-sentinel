"""Pydantic request models for all API endpoints."""

import re

from pydantic import BaseModel, Field, field_validator

from sentinel.web.state import MAX_PROMPT_LENGTH

# Safe git ref / target pattern: hex SHAs, branch/tag names, "--staged", etc.
# Blocks shell metacharacters and --upload-pack style injection.
_SAFE_GIT_TARGET_RE = re.compile(
    r"^(?:--staged|--unstaged|--all|-|[a-zA-Z0-9_./:@\-^~{}\\]+(?:\.\.[a-zA-Z0-9_./:@\-^~{}\\]+)?)$"
)


class FirewallScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_LENGTH)
    scan_type: str = Field(default="input", pattern=r"^(input|output)$")

    @field_validator("prompt")
    @classmethod
    def sanitize_prompt(cls, v: str) -> str:
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v)


class SastScanRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)


class DiffScanRequest(BaseModel):
    target: str = Field(default="--staged", max_length=4096)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        # Reject null bytes
        if "\x00" in v:
            raise ValueError("target contains null byte")
        # If it looks like a file path (contains path sep or extension), allow it through
        # — validate_scan_path in routes handles the rest.
        # Otherwise enforce safe git ref pattern.
        if "/" not in v and not v.endswith((".patch", ".diff")):
            if not _SAFE_GIT_TARGET_RE.match(v):
                raise ValueError("target contains unsafe characters")
        return v


class RedTeamRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=4096)


class SecretsScanRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)
    enable_entropy: bool = True
    git_history: bool = False


class DepScanRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)
    ecosystem: str = Field(default="pypi", pattern=r"^(pypi|npm)$")


class MCPScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=4096)
    manifest: str = Field(default="", max_length=4096)
    url: str = Field(default="", max_length=2048)


class A2AScanRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)


class AibomRequest(BaseModel):
    path: str = Field(default=".", min_length=1, max_length=4096)
    format: str = Field(default="cyclonedx", pattern=r"^(cyclonedx|spdx|sarif)$")


class HFScanRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=512)
    deep: bool = False
