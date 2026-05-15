from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml


SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache", ".sentinel"}


def _default_forbidden() -> list[str]:
    parts = [
        ("prompt", "foo"),
        ("defense", "claw"),
        ("ga", "rak"),
        ("py", "rit"),
        ("la", "kera"),
        ("re", "buff"),
        ("llm ", "guard"),
        ("model", "scan"),
        ("pickle", "scan"),
        ("fick", "ling"),
        ("cisco-ai-", "defense"),
        ("vigil-", "llm"),
        ("guardrails", "_pii"),
        ("p4rs3l", "t0ngv3"),
    ]
    return ["".join(part) for part in parts]


def _terms() -> list[str]:
    raw = os.environ.get("SENTINEL_FORBIDDEN_TERMS")
    if raw:
        return [term.strip() for term in raw.split(",") if term.strip()]
    return _default_forbidden()


def _iter_files(root: Path) -> list[Path]:
    out = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            out.append(path)
    return out


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def forbidden_reference_issues(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    issues = []
    terms = [re.compile(rf"(?<![a-z0-9]){re.escape(term.lower())}(?![a-z0-9])") for term in _terms()]
    for path in _iter_files(base):
        text = _read_text(path)
        if text is None:
            continue
        lowered = text.lower()
        for pattern in terms:
            if pattern.search(lowered):
                issues.append({"type": "forbidden-reference", "path": str(path), "term": pattern.pattern})
    return issues


def cache_file_issues(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    issues = []
    for path in base.rglob("*"):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            issues.append({"type": "generated-cache", "path": str(path)})
    return issues


def ui_emoji_issues(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    ui_root = base / "frontend" / "src"
    if not ui_root.exists():
        return []
    pattern = re.compile("[\U0001F300-\U0001FAFF]")
    issues = []
    for path in _iter_files(ui_root):
        if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".css", ".html"}:
            continue
        text = _read_text(path)
        if text and pattern.search(text):
            issues.append({"type": "ui-emoji", "path": str(path)})
    return issues


def duplicate_rule_id_issues(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    primary = base / "rules"
    rule_dirs = [primary] if primary.exists() else [base / "python" / "sentinel" / "rules"]
    seen: dict[str, str] = {}
    issues = []
    for rule_dir in rule_dirs:
        if not rule_dir.exists():
            continue
        for path in rule_dir.rglob("*"):
            if path.suffix.lower() not in {".yaml", ".yml", ".sntl", ".sentinel", ".yar", ".yara"}:
                continue
            ids = _rule_ids(path)
            for rule_id in ids:
                if rule_id in seen:
                    issues.append({"type": "duplicate-rule-id", "rule_id": rule_id, "path": str(path), "first_path": seen[rule_id]})
                else:
                    seen[rule_id] = str(path)
    return issues


def _rule_ids(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() in {".yar", ".yara"}:
        return re.findall(r"\brule\s+([A-Za-z0-9_.:-]+)", text)
    try:
        loaded = yaml.safe_load(text)
    except Exception:
        loaded = None
    ids: list[str] = []
    _collect_ids(loaded, ids)
    if ids:
        return ids
    return re.findall(r"(?m)^\s*id:\s*['\"]?([A-Za-z0-9_.:-]+)", text)


def _collect_ids(value: Any, ids: list[str]) -> None:
    if isinstance(value, dict):
        if "id" in value and isinstance(value["id"], (str, int)):
            ids.append(str(value["id"]))
        for child in value.values():
            _collect_ids(child, ids)
    elif isinstance(value, list):
        for child in value:
            _collect_ids(child, ids)


def unsafe_fixture_issues(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    issues = []
    for path in _iter_files(base):
        if "tests" in path.parts and "adversarial_corpus" in path.parts:
            continue
        if path.suffix.lower() in {".pkl", ".pickle"}:
            issues.append({"type": "unsafe-fixture", "path": str(path)})
    return issues


def run_hygiene_gate(root: str | Path = ".") -> dict[str, Any]:
    issues = []
    issues.extend(forbidden_reference_issues(root))
    issues.extend(cache_file_issues(root))
    issues.extend(ui_emoji_issues(root))
    issues.extend(duplicate_rule_id_issues(root))
    issues.extend(unsafe_fixture_issues(root))
    return {"schema_version": "sentinel.hygiene.v1", "ok": not issues, "issue_count": len(issues), "issues": issues}
