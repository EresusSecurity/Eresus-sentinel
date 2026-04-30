# ruff: noqa: E501
"""Local `.refs` inventory, parity plan, and clone-status utilities."""

from __future__ import annotations

import json
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
        name="skill-scanner",
        url="https://github.com/cisco-ai-defense/skill-scanner.git",
        priority="P1/P2",
        domains=("agent_skill", "rules", "evals"),
        p1_targets=("policy presets", "benchmark runner", "expected finding updater"),
        p2_targets=("wizard stance", "policy TUI stance", "pre-commit wrapper"),
    ),
    ReferenceRepo(
        name="ai-defense-langchain-middleware",
        url="https://github.com/cisco-ai-defense/ai-defense-langchain-middleware.git",
        priority="P1/P2",
        domains=("runtime", "middleware", "langchain"),
        p1_targets=("AgentSec aliases", "chat/tool inspection clients", "monitor/enforce modes"),
        p2_targets=("middleware ordering tests", "env contract snapshots", "composed chain docs"),
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
        name="a2a-scanner",
        url="https://github.com/cisco-ai-defense/a2a-scanner.git",
        priority="P1/P2",
        domains=("agent_a2a", "rules", "endpoint"),
        p1_targets=("agent card validator", "YAML A2A rules", "CLI scan command"),
        p2_targets=("policy presets", "endpoint live probe stance", "API/report snapshots"),
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
)


REFERENCE_PHASES: tuple[ReferencePhase, ...] = (
    ReferencePhase(1, "Clone and normalize references", "P1", tuple(repo.name for repo in EXPECTED_REFERENCE_REPOS), (".refs",), ("normalized URL map", "clone status"), "native-live"),
    ReferencePhase(2, "Build reference inventory", "P1", tuple(repo.name for repo in EXPECTED_REFERENCE_REPOS), ("sentinel.refs",), ("file/code counts", "remote/head metadata"), "native-live"),
    ReferencePhase(3, "A2A static security parity", "P1", ("a2a-scanner",), ("agent.a2a_scanner", "rules/a2a_rules.yaml"), ("agent card findings", "endpoint URL risk"), "native-live"),
    ReferencePhase(4, "A2A policy/report parity", "P2", ("a2a-scanner",), ("cli a2a", "parity manifest"), ("CLI scan command", "smoke contract"), "native-live"),
    ReferencePhase(5, "Pickle fuzzer contract parity", "P1", ("pickle-fuzzer",), ("fuzzer.pickle", "artifact.PickleScanner"), ("protocol/mutator manifest", "self-test smoke"), "native-live"),
    ReferencePhase(6, "Pickle fuzzing CI parity", "P2", ("pickle-fuzzer",), ("fuzzer.ci_pipeline", "scripts"), ("Atheris/libFuzzer stance", "corpus policy"), "partial"),
    ReferencePhase(7, "Runtime gateway governance", "P1", ("defenseclaw",), ("runtime_gateway", "gateway", "policy"), ("provider adapter contract", "verdict model"), "partial"),
    ReferencePhase(8, "Runtime audit observability", "P2", ("defenseclaw",), ("event_schemas", "sink_registry", "notifier"), ("sink schema map", "event contracts"), "partial"),
    ReferencePhase(9, "AIBOM scanner parity", "P1", ("aibom",), ("aibom.scanners", "aibom.scan_pipeline"), ("registry smoke", "endpoint classifier"), "partial"),
    ReferencePhase(10, "AIBOM reporting parity", "P2", ("aibom",), ("aibom.reporters", "aibom.catalog_db"), ("dashboard/report stance", "catalog fixtures"), "partial"),
    ReferencePhase(11, "Skill scanner policy parity", "P1", ("skill-scanner",), ("agent.skill_scanner", "agent.scan_policy"), ("policy presets", "strict schema checks"), "native-live"),
    ReferencePhase(12, "Skill scanner eval parity", "P2", ("skill-scanner",), ("agent.rule_packs", "tests"), ("benchmark fixture map", "expected updater stance"), "partial"),
    ReferencePhase(13, "LangChain middleware parity", "P1", ("ai-defense-langchain-middleware",), ("integrations.middleware", "middleware"), ("AgentSec aliases", "chat/tool client contract"), "native-live"),
    ReferencePhase(14, "MCP scanner transport parity", "P1", ("mcp-scanner",), ("agent.mcp.live_scanner", "agent.mcp"), ("manifest/http/stdio matrix", "prompt/resource scan"), "native-live"),
    ReferencePhase(15, "Hubness detection parity", "P1/P2", ("adversarial-hubness-detector",), ("supply_chain.hubness_detector",), ("robust/concept/modality detectors", "ranking stance"), "native-live"),
    ReferencePhase(16, "SecureBERT2 catalog parity", "P2", ("securebert2",), ("supply_chain.securebert2",), ("model catalog", "offline eval fixtures"), "native-live"),
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


def _strip_git_suffix(value: str) -> str:
    return value[:-4] if value.endswith(".git") else value


def default_refs_dir(start: str | Path = ".") -> Path:
    root = Path(start).resolve()
    for candidate in (root, *root.parents):
        refs_dir = candidate / ".refs"
        if refs_dir.exists():
            return refs_dir
    return root / ".refs"


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


def inspect_references(refs_dir: str | Path | None = None) -> list[ReferenceInventoryItem]:
    root = Path(refs_dir) if refs_dir is not None else default_refs_dir()
    items: list[ReferenceInventoryItem] = []

    for repo in EXPECTED_REFERENCE_REPOS:
        path = root / repo.name
        present = (path / ".git").is_dir()
        if not present:
            items.append(
                ReferenceInventoryItem(
                    name=repo.name,
                    url=repo.url,
                    path=str(path),
                    present=False,
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

        items.append(
            ReferenceInventoryItem(
                name=repo.name,
                url=repo.url,
                path=str(path),
                present=True,
                remote_url=remote_url,
                head=head,
                file_count=len(files),
                code_config_count=len(code_config_files),
                notable_paths=notable_paths,
                status="present" if remote_matches else "remote-mismatch",
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
        "# `.refs` P1/P2 Execution Plan",
        "",
        f"- Expected repos: `{summary['expected']}`",
        f"- Present repos: `{summary['present']}`",
        f"- Missing repos: `{', '.join(summary['missing']) or '-'}`",
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
        "# `.refs` Reference Inventory",
        "",
        f"- Expected repos: `{summary['expected']}`",
        f"- Present repos: `{summary['present']}`",
        f"- Total files: `{summary['files']}`",
        f"- Code/config files: `{summary['code_config_files']}`",
        f"- Phases: `{summary['phases']}`",
        "",
        "## Clone Status",
        "",
        "| Repo | Status | Files | Code/Config | HEAD | Remote |",
        "|---|---|---:|---:|---|---|",
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
    "default_refs_dir",
    "inspect_references",
    "p1_p2_matrix",
    "refs_inventory_json",
    "refs_inventory_markdown",
    "refs_plan_json",
    "refs_plan_markdown",
    "refs_summary",
]
