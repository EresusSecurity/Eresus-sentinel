"""
Eresus Sentinel — Unified Diff Parser.

Parses unified diff format (git diff, PR patches) into structured
representations for security analysis.

Supports:
- git diff (staged, unstaged, commit ranges)
- GitHub/GitLab PR patch format
- Piped stdin input
- Unified diff files (.patch, .diff)

Each parsed diff is decomposed into Hunks containing added/removed
lines with file context for targeted pattern matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class LineType(str, Enum):
    """Type of diff line."""
    ADDED = "+"
    REMOVED = "-"
    CONTEXT = " "


@dataclass
class DiffLine:
    """A single line in a diff hunk."""
    line_type: LineType
    content: str
    line_number: int  # Line number in the new file (for added/context)
    old_line_number: Optional[int] = None  # Line number in old file


@dataclass
class Hunk:
    """A contiguous block of changes within a file diff."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def added_lines(self) -> list[DiffLine]:
        return [l for l in self.lines if l.line_type == LineType.ADDED]

    @property
    def removed_lines(self) -> list[DiffLine]:
        return [l for l in self.lines if l.line_type == LineType.REMOVED]


@dataclass
class FileDiff:
    """All changes to a single file."""
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    is_binary: bool = False

    @property
    def path(self) -> str:
        """Canonical file path (prefers new_path)."""
        return self.new_path if self.new_path != "/dev/null" else self.old_path

    @property
    def extension(self) -> str:
        """File extension (lowercase)."""
        parts = self.path.rsplit(".", 1)
        return f".{parts[-1].lower()}" if len(parts) > 1 else ""

    @property
    def all_added_lines(self) -> list[DiffLine]:
        """All added lines across all hunks."""
        lines = []
        for hunk in self.hunks:
            lines.extend(hunk.added_lines)
        return lines

    @property
    def all_removed_lines(self) -> list[DiffLine]:
        """All removed lines across all hunks."""
        lines = []
        for hunk in self.hunks:
            lines.extend(hunk.removed_lines)
        return lines

    @property
    def added_text(self) -> str:
        """All added content concatenated."""
        return "\n".join(l.content for l in self.all_added_lines)

    @property
    def removed_text(self) -> str:
        """All removed content concatenated."""
        return "\n".join(l.content for l in self.all_removed_lines)


# ─── Parser ───────────────────────────────────────────────────────────

FILE_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
OLD_FILE = re.compile(r"^--- a/(.+)$")
NEW_FILE = re.compile(r"^\+\+\+ b/(.+)$")
OLD_FILE_NULL = re.compile(r"^--- /dev/null$")
NEW_FILE_NULL = re.compile(r"^\+\+\+ /dev/null$")
HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BINARY_MARKER = re.compile(r"^Binary files .+ differ$")


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """
    Parse a unified diff string into structured FileDiff objects.

    Args:
        diff_text: Raw unified diff output (from git diff or .patch file).

    Returns:
        List of FileDiff objects, one per changed file.
    """
    file_diffs: list[FileDiff] = []
    current_file: Optional[FileDiff] = None
    current_hunk: Optional[Hunk] = None
    new_line_num = 0
    old_line_num = 0

    for raw_line in diff_text.split("\n"):
        # File header
        match = FILE_HEADER.match(raw_line)
        if match:
            current_file = FileDiff(
                old_path=match.group(1),
                new_path=match.group(2),
            )
            file_diffs.append(current_file)
            current_hunk = None
            continue

        if current_file is None:
            continue

        # Binary marker
        if BINARY_MARKER.match(raw_line):
            current_file.is_binary = True
            continue

        # Old file path
        if OLD_FILE_NULL.match(raw_line):
            current_file.is_new = True
            continue
        match = OLD_FILE.match(raw_line)
        if match:
            current_file.old_path = match.group(1)
            continue

        # New file path
        if NEW_FILE_NULL.match(raw_line):
            current_file.is_deleted = True
            continue
        match = NEW_FILE.match(raw_line)
        if match:
            current_file.new_path = match.group(1)
            continue

        # Hunk header
        match = HUNK_HEADER.match(raw_line)
        if match:
            current_hunk = Hunk(
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or 1),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or 1),
            )
            current_file.hunks.append(current_hunk)
            new_line_num = current_hunk.new_start
            old_line_num = current_hunk.old_start
            continue

        if current_hunk is None:
            continue

        # Diff lines
        if raw_line.startswith("+"):
            current_hunk.lines.append(DiffLine(
                line_type=LineType.ADDED,
                content=raw_line[1:],
                line_number=new_line_num,
            ))
            new_line_num += 1
        elif raw_line.startswith("-"):
            current_hunk.lines.append(DiffLine(
                line_type=LineType.REMOVED,
                content=raw_line[1:],
                line_number=new_line_num,
                old_line_number=old_line_num,
            ))
            old_line_num += 1
        elif raw_line.startswith(" "):
            current_hunk.lines.append(DiffLine(
                line_type=LineType.CONTEXT,
                content=raw_line[1:],
                line_number=new_line_num,
                old_line_number=old_line_num,
            ))
            new_line_num += 1
            old_line_num += 1

    # Detect renames
    for fd in file_diffs:
        if fd.old_path != fd.new_path and not fd.is_new and not fd.is_deleted:
            fd.is_renamed = True

    return file_diffs
