"""Parse Jupyter notebooks to extract AI/ML components for BOM."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType

logger = logging.getLogger(__name__)

_MODEL_LOAD_RE = re.compile(r"""(?:from_pretrained|AutoModel|pipeline)\s*\(\s*["']([^"']+)["']""")
_IMPORT_RE = re.compile(r"^(?:from|import)\s+(\S+)", re.MULTILINE)
_AI_MODULES = frozenset({
    "torch", "tensorflow", "transformers", "langchain", "openai",
    "anthropic", "sklearn", "keras", "jax", "datasets",
})


def parse_notebook(path: Path) -> list[AIComponent]:
    """Extract AI components from a .ipynb notebook file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        logger.debug("Failed to parse notebook %s: %s", path, e)
        return []

    if not isinstance(data, dict):
        return []

    cells = data.get("cells", [])
    if not isinstance(cells, list):
        return []

    components: list[AIComponent] = []
    cell_sources: list[str] = []

    for i, cell in enumerate(cells):
        if not isinstance(cell, dict):
            continue
        cell_type = cell.get("cell_type", "")
        source = cell.get("source", [])
        if isinstance(source, list):
            text = "".join(source)
        elif isinstance(source, str):
            text = source
        else:
            continue

        if cell_type == "code":
            cell_sources.append(text)
            _extract_from_code_cell(path, text, i, components)

    full_text = "\n".join(cell_sources)
    _extract_imports(path, full_text, components)

    return components


def _extract_from_code_cell(
    path: Path, text: str, cell_idx: int, out: list[AIComponent]
) -> None:
    for m in _MODEL_LOAD_RE.finditer(text):
        model_id = m.group(1)
        out.append(AIComponent(
            type=AIComponentType.MODEL_LLM,
            name=model_id,
            path=str(path),
            description=f"Model loaded in notebook cell {cell_idx}",
            evidence=["notebook-model-load"],
            properties={"cell_index": cell_idx, "model_id": model_id},
        ))


def _extract_imports(path: Path, text: str, out: list[AIComponent]) -> None:
    found_modules: set[str] = set()
    for m in _IMPORT_RE.finditer(text):
        module = m.group(1).split(".")[0]
        if module in _AI_MODULES and module not in found_modules:
            found_modules.add(module)

    if found_modules:
        out.append(AIComponent(
            type=AIComponentType.CONFIG,
            name=f"notebook-imports:{path.name}",
            path=str(path),
            description=f"Notebook AI imports: {', '.join(sorted(found_modules))}",
            evidence=list(found_modules),
            properties={"modules": sorted(found_modules)},
        ))
