"""Jupyter .ipynb parser — extracts cells, metadata, outputs into structured objects."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class NotebookCell:
    """A single parsed notebook cell."""
    index: int
    cell_type: str          # "code" | "markdown" | "raw"
    source: str             # concatenated source text
    outputs: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    execution_count: int | None = None

    @property
    def ref(self) -> str:
        return f"cell[{self.index}] ({self.cell_type})"

    @property
    def is_code(self) -> bool:
        return self.cell_type == "code"

    @property
    def is_markdown(self) -> bool:
        return self.cell_type == "markdown"


@dataclass
class ParsedNotebook:
    """Fully parsed notebook ready for plugin scanning."""
    path: str
    cells: list[NotebookCell] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    nbformat: int = 0
    kernel_name: str = ""
    language: str = ""
    error: str = ""

    @property
    def cell_count(self) -> int:
        return len(self.cells)

    @property
    def code_cells(self) -> list[NotebookCell]:
        return [c for c in self.cells if c.is_code]

    @property
    def markdown_cells(self) -> list[NotebookCell]:
        return [c for c in self.cells if c.is_markdown]


class NotebookParser:
    """Parses .ipynb JSON into structured NotebookCell objects."""

    def parse(self, path: str) -> ParsedNotebook:
        """Parse a single .ipynb file."""
        p = Path(path)
        notebook = ParsedNotebook(path=str(p))

        if not p.exists():
            notebook.error = f"File not found: {path}"
            return notebook

        if not p.suffix == ".ipynb":
            notebook.error = f"Not a notebook file: {path}"
            return notebook

        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            notebook.error = f"Parse error: {e}"
            return notebook

        notebook.metadata = raw.get("metadata", {})
        notebook.nbformat = raw.get("nbformat", 0)

        kernel = notebook.metadata.get("kernelspec", {})
        notebook.kernel_name = kernel.get("name", "")
        notebook.language = kernel.get("language", "")

        for idx, cell_data in enumerate(raw.get("cells", [])):
            source_lines = cell_data.get("source", [])
            source = "".join(source_lines) if isinstance(source_lines, list) else str(source_lines)

            cell = NotebookCell(
                index=idx,
                cell_type=cell_data.get("cell_type", "unknown"),
                source=source,
                outputs=cell_data.get("outputs", []),
                metadata=cell_data.get("metadata", {}),
                execution_count=cell_data.get("execution_count"),
            )
            notebook.cells.append(cell)

        return notebook

    @staticmethod
    def extract_output_text(output: dict) -> str:
        """Extract plaintext from a cell output object."""
        parts = []
        if "text" in output:
            text = output["text"]
            parts.append("".join(text) if isinstance(text, list) else str(text))
        if "data" in output:
            data = output["data"]
            for mime in ("text/plain", "text/html", "application/json"):
                if mime in data:
                    val = data[mime]
                    parts.append("".join(val) if isinstance(val, list) else str(val))
        return "\n".join(parts)
