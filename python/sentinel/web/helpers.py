"""Shared helper functions for the Sentinel dashboard API."""

import re
import urllib.parse
import uuid
from pathlib import Path

from fastapi import HTTPException

# Allowed HF repo pattern: org/repo (no raw URLs, no path traversal, no query strings)
_HF_REPO_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,128}/[A-Za-z0-9_.\-]{1,128}$')
# Private/RFC-1918 IP ranges to block in any URL input
_PRIVATE_IP_RE = re.compile(
    r'(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1|localhost)',
    re.IGNORECASE,
)


_FORBIDDEN_PATHS = frozenset({
    "/", "/etc", "/var", "/usr", "/System", "/Library",
    "/Applications", "/private", "/root", "/boot",
    "/dev", "/proc", "/sys", "/tmp",
    "C:\\", "C:\\Windows", "C:\\System32",
})


def validate_scan_path(path_str: str) -> str:
    """Validate and resolve scan path. Raises HTTPException on dangerous paths."""
    # Strip null bytes — prevent null-byte path truncation attacks
    if "\x00" in path_str:
        raise HTTPException(status_code=400, detail="Invalid path: null byte detected")
    # Decode percent-encoding to catch encoded traversal sequences (e.g. %2e%2e%2f)
    decoded = urllib.parse.unquote(path_str)
    if ".." in decoded or decoded != path_str:
        # Re-resolve after decoding
        path_str = decoded
    resolved = str(Path(path_str).resolve())
    # Block system directories
    if resolved in _FORBIDDEN_PATHS:
        raise HTTPException(status_code=400, detail=f"Scanning system path '{resolved}' is not allowed")
    # Block /etc/* and similar
    for forbidden in ("/etc/", "/proc/", "/sys/", "/dev/", "/private/etc/"):
        if resolved.startswith(forbidden):
            raise HTTPException(status_code=400, detail="Scanning system path is not allowed")
    # Verify path exists
    p = Path(resolved)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path_str}")
    return resolved


def safe_str(s: str, max_len: int = 500) -> str:
    """Truncate and strip dangerous chars."""
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    return s[:max_len]


def validate_hf_repo(repo: str) -> str:
    """Validate a HuggingFace repo ID to prevent SSRF and path injection.

    Only allows the canonical `org/model` format. Rejects raw URLs, IP
    addresses, path components, and any form of SSRF payload.
    """
    if not repo:
        raise HTTPException(status_code=400, detail="repo is required")
    repo = repo.strip()
    # Reject if it looks like a URL or contains path separators / query strings
    if any(c in repo for c in ("://", "?", "#", " ", "\x00")):
        raise HTTPException(status_code=400, detail="Invalid repo: URLs not accepted — use org/repo format")
    # Reject if it contains path traversal
    decoded = urllib.parse.unquote(repo)
    if ".." in decoded:
        raise HTTPException(status_code=400, detail="Invalid repo: path traversal detected")
    # Reject if it looks like an IP address or private hostname
    if _PRIVATE_IP_RE.search(repo):
        raise HTTPException(status_code=400, detail="Invalid repo: private network addresses not allowed")
    if not _HF_REPO_RE.match(repo):
        raise HTTPException(
            status_code=400,
            detail="Invalid repo format. Expected: org/model-name (e.g. meta-llama/Llama-3.1-8B)",
        )
    return repo


def validate_url_no_ssrf(url: str, *, max_len: int = 2048) -> str:
    """Validate a URL allowing only public https:// URLs, blocking SSRF targets."""
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    url = url.strip()
    if len(url) > max_len:
        raise HTTPException(status_code=400, detail="URL too long")
    if not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Only https:// URLs are accepted")
    if _PRIVATE_IP_RE.search(url):
        raise HTTPException(status_code=400, detail="URL resolves to a private/internal address")
    return url


def new_request_id() -> str:
    """Generate a short hex request correlation ID."""
    return uuid.uuid4().hex[:16]


def finding_to_dict(f) -> dict:
    """Convert any Finding object to a safe API dict."""
    sev = getattr(f, "severity", "INFO")
    sev_str = sev.name if hasattr(sev, "name") else (sev.value if hasattr(sev, "value") else str(sev))
    return {
        "rule_id": safe_str(str(getattr(f, "rule_id", "")), 100),
        "title": safe_str(str(getattr(f, "title", "")), 200),
        "severity": safe_str(sev_str, 10),
        "confidence": min(1.0, max(0.0, float(getattr(f, "confidence", 0.0)))),
        "description": safe_str(str(getattr(f, "description", "")), 500),
        "evidence": safe_str(str(getattr(f, "evidence", "")), 300),
        "cwe_ids": getattr(f, "cwe_ids", [])[:10],
        "remediation": safe_str(str(getattr(f, "remediation", "")), 300),
    }
