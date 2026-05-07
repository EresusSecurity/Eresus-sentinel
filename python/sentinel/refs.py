# ruff: noqa: E501
"""Local reference-suite inventory, parity plan, and clone-status utilities."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ReferenceRepo:
    name: str
    url: str
    priority: str
    domains: tuple[str, ...]
    p1_targets: tuple[str, ...]
    p2_targets: tuple[str, ...]


@dataclass(frozen=True)
class ReferenceInventoryItem:
    name: str
    url: str
    path: str
    present: bool
    source_root: str = ""
    priority: str = ""
    domains: tuple[str, ...] = ()
    remote_url: str = ""
    head: str = ""
    file_count: int = 0
    code_config_count: int = 0
    notable_paths: tuple[str, ...] = ()
    status: str = "missing"


@dataclass(frozen=True)
class ReferencePhase:
    phase: int
    title: str
    priority: str
    reference_repos: tuple[str, ...]
    sentinel_surfaces: tuple[str, ...]
    deliverables: tuple[str, ...]
    status: str


EXPECTED_REFERENCE_REPOS: tuple[ReferenceRepo, ...] = (
    ReferenceRepo(
        name="pickle-fuzzer",
        url="https://github.com/cisco-ai-defense/pickle-fuzzer.git",
        priority="P1/P2",
        domains=("artifact", "fuzzing", "ci"),
        p1_targets=("protocol matrix", "mutator catalog", "CI harness contract"),
        p2_targets=("Atheris/libFuzzer docs", "corpus minimization", "Rust backend selector"),
    ),
    ReferenceRepo(
        name="defenseclaw",
        url="https://github.com/cisco-ai-defense/defenseclaw.git",
        priority="P1/P2",
        domains=("runtime", "gateway", "governance"),
        p1_targets=("runtime gateway contract", "policy action schema", "audit sink registry"),
        p2_targets=("TUI stance", "observability bundles", "OS firewall privileged plugin"),
    ),
    ReferenceRepo(
        name="aibom",
        url="https://github.com/cisco-ai-defense/aibom.git",
        priority="P1/P2",
        domains=("bom", "inventory", "reporting"),
        p1_targets=("scanner registry contract", "endpoint classifier", "relationship postprocess"),
        p2_targets=("HTML dashboard snapshots", "catalog DB fixtures", "repo triage UX"),
    ),
    ReferenceRepo(
        name="mcp-scanner",
        url="https://github.com/cisco-ai-defense/mcp-scanner.git",
        priority="P1/P2",
        domains=("agent_mcp", "transport", "readiness"),
        p1_targets=("live transport matrix", "prompt/resource scanning", "readiness config"),
        p2_targets=("tree-sitter stance", "OAuth probing fixtures", "API route snapshots"),
    ),
    ReferenceRepo(
        name="skill-scanner",
        url="https://github.com/cisco-ai-defense/skill-scanner.git",
        priority="P1/P2",
        domains=("agent_skill", "rules", "evals"),
        p1_targets=("policy presets", "benchmark runner", "expected finding updater"),
        p2_targets=("wizard stance", "policy TUI stance", "pre-commit wrapper"),
    ),
    ReferenceRepo(
        name="model-provenance-kit",
        url="https://github.com/cisco-ai-defense/model-provenance-kit.git",
        priority="P1/P2",
        domains=("provenance", "supply_chain", "fingerprints"),
        p1_targets=("8-signal extraction", "db integrity", "pairwise compare CLI"),
        p2_targets=("streaming fingerprints", "cache integrity", "download workflow"),
    ),
    ReferenceRepo(
        name="adversarial-hubness-detector",
        url="https://github.com/cisco-ai-defense/adversarial-hubness-detector.git",
        priority="P1/P2",
        domains=("supply_chain", "rag", "embeddings"),
        p1_targets=("robust hubness", "concept-aware mode", "modality-aware mode"),
        p2_targets=("JSONL vector loader", "ranking plugin stance", "hybrid/rerank fixtures"),
    ),
    ReferenceRepo(
        name="securebert2",
        url="https://github.com/cisco-ai-defense/securebert2.git",
        priority="P2",
        domains=("supply_chain", "cyber_models", "evals"),
        p1_targets=(),
        p2_targets=("offline model catalog", "task fixtures", "HF model ID validation"),
    ),
    ReferenceRepo(
        name="ai-defense-hybrid",
        url="https://github.com/cisco-ai-defense/ai-defense-hybrid.git",
        priority="P2",
        domains=("deployment", "runtime", "kubernetes"),
        p1_targets=("gateway deployment contract", "policy bundle layout", "runtime topology"),
        p2_targets=("helm chart parity", "redis/cache wiring", "GPU/runtime examples"),
    ),
)


REFERENCE_PHASES: tuple[ReferencePhase, ...] = (
    ReferencePhase(1, "Clone and normalize references", "P1", tuple(repo.name for repo in EXPECTED_REFERENCE_REPOS), ("sentinel.refs",), ("normalized URL map", "clone status"), "native-live"),
    ReferencePhase(2, "Build reference inventory", "P1", tuple(repo.name for repo in EXPECTED_REFERENCE_REPOS), ("sentinel.refs", "sentinel.parity"), ("file/code counts", "remote/head metadata"), "native-live"),
    ReferencePhase(5, "Pickle fuzzer contract parity", "P1", ("pickle-fuzzer",), ("fuzzer.pickle", "artifact.PickleScanner"), ("protocol/mutator manifest", "self-test smoke"), "native-live"),
    ReferencePhase(7, "Runtime gateway governance", "P1", ("defenseclaw",), ("runtime_gateway", "gateway", "policy"), ("provider adapter contract", "verdict model"), "partial"),
    ReferencePhase(8, "Runtime audit observability", "P2", ("defenseclaw",), ("event_schemas", "sink_registry", "notifier"), ("sink schema map", "event contracts"), "partial"),
    ReferencePhase(9, "AIBOM scanner parity", "P1", ("aibom",), ("aibom.scanners", "aibom.scan_pipeline"), ("registry smoke", "endpoint classifier"), "partial"),
    ReferencePhase(10, "MCP scanner parity", "P1", ("mcp-scanner",), ("agent.mcp.live_scanner", "agent.mcp"), ("manifest/http/stdio matrix", "prompt/resource scan"), "native-live"),
    ReferencePhase(11, "Skill scanner policy parity", "P1", ("skill-scanner",), ("agent.skill_scanner", "agent.scan_policy"), ("policy presets", "strict schema checks"), "native-live"),
    ReferencePhase(12, "Model provenance parity", "P1", ("model-provenance-kit",), ("provenance", "cli provenance"), ("8 signals", "reference DB contract"), "partial"),
    ReferencePhase(13, "Hubness detection parity", "P1/P2", ("adversarial-hubness-detector",), ("supply_chain.hubness_detector",), ("robust/concept/modality detectors", "ranking stance"), "native-live"),
    ReferencePhase(14, "SecureBERT2 catalog parity", "P2", ("securebert2",), ("supply_chain.securebert2",), ("model catalog", "offline eval fixtures"), "native-live"),
    ReferencePhase(15, "Hybrid deployment parity", "P2", ("ai-defense-hybrid",), ("deploy", "gateway", "docs"), ("helm/runtime topology", "cluster docs"), "partial"),
    ReferencePhase(16, "Gap ledger and fixture import", "P1/P2", tuple(repo.name for repo in EXPECTED_REFERENCE_REPOS), ("sentinel.refs", "sentinel.parity", "tests"), ("fix queue", "fixture source map"), "partial"),
    ReferencePhase(17, "Parity manifest enforcement", "P1/P2", tuple(repo.name for repo in EXPECTED_REFERENCE_REPOS), ("sentinel.parity", "tests"), ("dynamic smoke checks", "native/partial/missing matrix"), "native-live"),
)


_CODE_CONFIG_SUFFIXES = {".py", ".go", ".rs", ".ts", ".js", ".yaml", ".yml", ".toml", ".json"}
_NOTABLE_NAMES = {
    "README.md",
    "action.yml",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "FEATURE.md",
    "TESTING.md",
}
_DEFAULT_REFS_DIR_NAMES = (".refs", "ai-security-tools/refs", "refs")


def _strip_git_suffix(value: str) -> str:
    return value[:-4] if value.endswith(".git") else value


def available_refs_dirs(start: str | Path = ".") -> tuple[Path, ...]:
    root = Path(start).resolve()
    seen: set[Path] = set()
    ordered: list[Path] = []

    def register(candidate: Path) -> None:
        candidate = candidate.expanduser().resolve()
        if candidate.exists() and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)

    explicit = os.getenv("SENTINEL_REFS_DIR")
    if explicit:
        register(Path(explicit))

    extra = os.getenv("SENTINEL_EXTRA_REFS_DIRS", "")
    for raw in extra.split(os.pathsep):
        raw = raw.strip()
        if raw:
            register(Path(raw))

    for candidate_root in (root, *root.parents):
        for relative in _DEFAULT_REFS_DIR_NAMES:
            register(candidate_root / relative)

    return tuple(ordered)


def default_refs_dir(start: str | Path = ".") -> Path:
    discovered = available_refs_dirs(start)
    if discovered:
        return discovered[0]
    return (Path(start).resolve() / ".refs").resolve()


def _git_value(path: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _candidate_roots(refs_dir: str | Path | None = None) -> tuple[Path, ...]:
    if refs_dir is not None:
        return (Path(refs_dir).resolve(),)
    return available_refs_dirs()


def inspect_references(refs_dir: str | Path | None = None) -> list[ReferenceInventoryItem]:
    roots = _candidate_roots(refs_dir)
    fallback_root = Path(refs_dir).resolve() if refs_dir is not None else default_refs_dir()
    items: list[ReferenceInventoryItem] = []

    for repo in EXPECTED_REFERENCE_REPOS:
        located_root = next((root for root in roots if (root / repo.name / ".git").is_dir()), fallback_root)
        path = located_root / repo.name
        present = (path / ".git").is_dir()
        if not present:
            items.append(
                ReferenceInventoryItem(
                    name=repo.name,
                    url=repo.url,
                    path=str(path),
                    present=False,
                    source_root=str(located_root),
                    priority=repo.priority,
                    domains=repo.domains,
                )
            )
            continue

        files = [
            file_path
            for file_path in path.rglob("*")
            if file_path.is_file() and ".git" not in file_path.parts
        ]
        code_config_files = [
            file_path for file_path in files if file_path.suffix.lower() in _CODE_CONFIG_SUFFIXES
        ]
        notable_paths = tuple(
            sorted(
                str(file_path.relative_to(path))
                for file_path in files
                if file_path.name in _NOTABLE_NAMES
            )[:20]
        )
        remote_url = _git_value(path, "remote", "get-url", "origin")
        head = _git_value(path, "rev-parse", "--short", "HEAD")
        remote_matches = _strip_git_suffix(remote_url) == _strip_git_suffix(repo.url)
        status = "present" if not remote_url or remote_matches else "remote-mismatch"

        items.append(
            ReferenceInventoryItem(
                name=repo.name,
                url=repo.url,
                path=str(path),
                present=True,
                source_root=str(located_root),
                priority=repo.priority,
                domains=repo.domains,
                remote_url=remote_url,
                head=head,
                file_count=len(files),
                code_config_count=len(code_config_files),
                notable_paths=notable_paths,
                status=status,
            )
        )
    return items


def p1_p2_matrix() -> list[dict[str, Any]]:
    return [
        {
            "name": repo.name,
            "priority": repo.priority,
            "domains": repo.domains,
            "p1_targets": repo.p1_targets,
            "p2_targets": repo.p2_targets,
        }
        for repo in EXPECTED_REFERENCE_REPOS
    ]


def refs_summary(refs_dir: str | Path | None = None) -> dict[str, Any]:
    inventory = inspect_references(refs_dir)
    return {
        "expected": len(EXPECTED_REFERENCE_REPOS),
        "present": sum(1 for item in inventory if item.present),
        "missing": [item.name for item in inventory if not item.present],
        "remote_mismatch": [item.name for item in inventory if item.status == "remote-mismatch"],
        "files": sum(item.file_count for item in inventory),
        "code_config_files": sum(item.code_config_count for item in inventory),
        "phases": len(REFERENCE_PHASES),
        "roots": [str(path) for path in _candidate_roots(refs_dir)],
    }


def refs_inventory_json(refs_dir: str | Path | None = None) -> str:
    payload = {
        "summary": refs_summary(refs_dir),
        "inventory": [asdict(item) for item in inspect_references(refs_dir)],
        "p1_p2_matrix": p1_p2_matrix(),
        "phases": [asdict(phase) for phase in REFERENCE_PHASES],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def refs_plan_json(refs_dir: str | Path | None = None) -> str:
    payload = {
        "summary": refs_summary(refs_dir),
        "p1_p2_matrix": p1_p2_matrix(),
        "phases": [asdict(phase) for phase in REFERENCE_PHASES],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def refs_plan_markdown(refs_dir: str | Path | None = None) -> str:
    summary = refs_summary(refs_dir)
    lines = [
        "# Reference Suite P1/P2 Plan",
        "",
        f"- Expected repos: `{summary['expected']}`",
        f"- Present repos: `{summary['present']}`",
        f"- Missing repos: `{', '.join(summary['missing']) or '-'}`",
        f"- Roots: `{', '.join(summary['roots']) or '-'}`",
        f"- Phases: `{summary['phases']}`",
        "",
        "## Repository Targets",
        "",
        "| Repo | Priority | Domains | P1 Targets | P2 Targets |",
        "|---|---|---|---|---|",
    ]
    for repo in EXPECTED_REFERENCE_REPOS:
        lines.append(
            "| "
            + " | ".join(
                [
                    repo.name,
                    repo.priority,
                    ", ".join(repo.domains),
                    ", ".join(repo.p1_targets) or "-",
                    ", ".join(repo.p2_targets) or "-",
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Phases",
            "",
            "| Phase | Priority | Status | Reference | Sentinel Surface | Deliverables |",
            "|---:|---|---|---|---|---|",
        ]
    )
    for phase in REFERENCE_PHASES:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(phase.phase),
                    phase.priority,
                    phase.status,
                    ", ".join(phase.reference_repos),
                    ", ".join(phase.sentinel_surfaces),
                    ", ".join(phase.deliverables),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def refs_inventory_markdown(refs_dir: str | Path | None = None) -> str:
    summary = refs_summary(refs_dir)
    inventory = inspect_references(refs_dir)
    lines = [
        "# Reference Suite Inventory",
        "",
        f"- Expected repos: `{summary['expected']}`",
        f"- Present repos: `{summary['present']}`",
        f"- Total files: `{summary['files']}`",
        f"- Code/config files: `{summary['code_config_files']}`",
        f"- Roots: `{', '.join(summary['roots']) or '-'}`",
        f"- Phases: `{summary['phases']}`",
        "",
        "## Clone Status",
        "",
        "| Repo | Status | Files | Code/Config | HEAD | Root | Remote |",
        "|---|---|---:|---:|---|---|---|",
    ]
    for item in inventory:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.name,
                    item.status,
                    str(item.file_count),
                    str(item.code_config_count),
                    item.head or "-",
                    item.source_root.replace("|", "/") or "-",
                    (item.remote_url or item.url).replace("|", "/"),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## P1/P2 Matrix",
            "",
            "| Repo | Priority | P1 Targets | P2 Targets |",
            "|---|---|---|---|",
        ]
    )
    for repo in EXPECTED_REFERENCE_REPOS:
        lines.append(
            "| "
            + " | ".join(
                [
                    repo.name,
                    repo.priority,
                    ", ".join(repo.p1_targets) or "-",
                    ", ".join(repo.p2_targets) or "-",
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## 17-Phase Execution Plan",
            "",
            "| Phase | Priority | Status | Title | Deliverables |",
            "|---:|---|---|---|---|",
        ]
    )
    for phase in REFERENCE_PHASES:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(phase.phase),
                    phase.priority,
                    phase.status,
                    phase.title,
                    ", ".join(phase.deliverables),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "EXPECTED_REFERENCE_REPOS",
    "REFERENCE_PHASES",
    "ReferenceInventoryItem",
    "ReferencePhase",
    "ReferenceRepo",
    "available_refs_dirs",
    "default_refs_dir",
    "inspect_references",
    "p1_p2_matrix",
    "refs_inventory_json",
    "refs_inventory_markdown",
    "refs_plan_json",
    "refs_plan_markdown",
    "refs_summary",
]
