"""
Eresus Sentinel — Reference Repository Registry.

Tracks the set of external reference repositories used for parity testing,
benchmark validation, and gap analysis.  All functions are pure Python and
require no network access; they operate on an already-cloned ``refs/``
directory tree.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

EXPECTED_REFERENCE_REPOS: list[str] = [
    "pickle-fuzzer",
    "defenseclaw",
    "aibom",
    "mcp-scanner",
    "skill-scanner",
    "model-provenance-kit",
    "adversarial-hubness-detector",
    "securebert2",
    "ai-defense-hybrid",
]

REFERENCE_PHASES: list[str] = [
    "phase-1-artifact",
    "phase-2-firewall",
    "phase-3-sast",
    "phase-4-redteam",
    "phase-5-supply-chain",
    "phase-6-mcp-proxy",
    "phase-7-interprocedural",
    "phase-8-agent",
    "phase-9-eval",
    "phase-10-sarif",
    "phase-11-benchmark",
    "phase-12-hardening",
    "phase-13-release",
]

_REFS_DIR_NAMES = ("refs", "ai-security-tools/refs", ".sentinel/refs")


def available_refs_dirs(root: str | Path) -> list[Path]:
    """Return all refs directories found under *root*."""
    root = Path(root)
    found: list[Path] = []
    for candidate in _REFS_DIR_NAMES:
        p = root / candidate
        if p.is_dir():
            found.append(p)
    return found


def default_refs_dir(root: str | Path) -> Optional[Path]:
    """Return the first available refs directory, or None."""
    dirs = available_refs_dirs(root)
    return dirs[0] if dirs else None


def refs_inventory_json(refs_dir: str | Path) -> str:
    """Return a JSON string describing the repos present in *refs_dir*."""
    refs_dir = Path(refs_dir)
    inventory: list[dict] = []
    for repo in EXPECTED_REFERENCE_REPOS:
        repo_path = refs_dir / repo
        inventory.append({
            "name": repo,
            "path": str(repo_path),
            "present": repo_path.is_dir(),
        })
    present = sum(1 for item in inventory if item["present"])
    return json.dumps({
        "schema_version": "refs.inventory.v1",
        "summary": {
            "expected": len(EXPECTED_REFERENCE_REPOS),
            "present": present,
            "missing": len(EXPECTED_REFERENCE_REPOS) - present,
            "roots": [str(refs_dir)],
        },
        "inventory": inventory,
    }, indent=2)


def refs_plan_json(refs_dir: str | Path) -> str:
    """Return a JSON string with a phase-focused clone plan."""
    refs_dir = Path(refs_dir)
    inventory: list[dict] = []
    for repo in EXPECTED_REFERENCE_REPOS:
        repo_path = refs_dir / repo
        inventory.append({
            "name": repo,
            "present": repo_path.is_dir(),
        })
    present = sum(1 for item in inventory if item["present"])
    return json.dumps({
        "schema_version": "refs.plan.v1",
        "summary": {
            "expected": len(EXPECTED_REFERENCE_REPOS),
            "present": present,
            "missing": len(EXPECTED_REFERENCE_REPOS) - present,
        },
        "phases": [{"id": phase, "repos": EXPECTED_REFERENCE_REPOS} for phase in REFERENCE_PHASES],
    }, indent=2)
