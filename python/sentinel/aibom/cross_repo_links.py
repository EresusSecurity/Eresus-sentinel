"""Cross-repo link detection for multi-repository AIBOM scans."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_GIT_SUBMODULE_RE = re.compile(r"\[submodule\s+\"([^\"]+)\"\]")
_GIT_URL_RE = re.compile(r"url\s*=\s*(\S+)")
_PYPROJECT_DEP_RE = re.compile(r"""git\+https?://([^\s"']+)""")
_PACKAGE_JSON_GIT_RE = re.compile(r"""(?:git\+)?(?:https?|git)://([^\s"'#]+)""")


@dataclass
class RepoLink:
    source_repo: str
    target_url: str
    link_type: str  # "submodule", "git-dependency", "import-ref"
    evidence_file: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class CrossRepoLinker:
    """Detect cross-repository links in a project."""

    def __init__(self) -> None:
        self._links: list[RepoLink] = []

    def scan(self, root: Path) -> list[RepoLink]:
        self._links = []
        self._scan_git_submodules(root)
        self._scan_git_deps(root)
        return self._links

    def _scan_git_submodules(self, root: Path) -> None:
        gitmodules = root / ".gitmodules"
        if not gitmodules.exists():
            return
        text = gitmodules.read_text(encoding="utf-8", errors="replace")
        current_name = ""
        for line in text.splitlines():
            m = _GIT_SUBMODULE_RE.search(line)
            if m:
                current_name = m.group(1)
            url_m = _GIT_URL_RE.search(line)
            if url_m and current_name:
                self._links.append(RepoLink(
                    source_repo=str(root),
                    target_url=url_m.group(1),
                    link_type="submodule",
                    evidence_file=str(gitmodules),
                    metadata={"submodule_name": current_name},
                ))
                current_name = ""

    def _scan_git_deps(self, root: Path) -> None:
        for p in root.rglob("pyproject.toml"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for m in _PYPROJECT_DEP_RE.finditer(text):
                self._links.append(RepoLink(
                    source_repo=str(root),
                    target_url=f"https://{m.group(1)}",
                    link_type="git-dependency",
                    evidence_file=str(p),
                ))
        for p in root.rglob("package.json"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for m in _PACKAGE_JSON_GIT_RE.finditer(text):
                self._links.append(RepoLink(
                    source_repo=str(root),
                    target_url=f"https://{m.group(1)}",
                    link_type="git-dependency",
                    evidence_file=str(p),
                ))

    @property
    def link_count(self) -> int:
        return len(self._links)
