from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_SAFE_STRING_RE = re.compile(r"^[A-Za-z0-9_./@:+-]+(?: [A-Za-z0-9_./@:+-]+)*$")
_RESERVED = {"true", "false", "null", "none", "~"}


def dumps(data: Any) -> str:
    return _render(data, 0).rstrip() + "\n"


def dump(data: Any, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(dumps(data), encoding="utf-8")
    return p


def _render(value: Any, indent: int) -> str:
    if isinstance(value, dict):
        return _render_map(value, indent)
    if isinstance(value, list):
        return _render_list(value, indent)
    return " " * indent + _scalar(value)


def _render_map(value: dict[str, Any], indent: int) -> str:
    lines: list[str] = []
    pad = " " * indent
    for key, item in value.items():
        rendered_key = _key(str(key))
        if isinstance(item, dict):
            if item:
                lines.append(f"{pad}{rendered_key}:")
                lines.append(_render_map(item, indent + 2))
            else:
                lines.append(f"{pad}{rendered_key}: {{}}")
        elif isinstance(item, list):
            if item:
                lines.append(f"{pad}{rendered_key}:")
                lines.append(_render_list(item, indent + 2))
            else:
                lines.append(f"{pad}{rendered_key}: []")
        elif isinstance(item, str) and "\n" in item:
            lines.append(f"{pad}{rendered_key}: |")
            for line in item.splitlines():
                lines.append(f"{pad}  {line}")
        else:
            lines.append(f"{pad}{rendered_key}: {_scalar(item)}")
    return "\n".join(lines)


def _render_list(value: list[Any], indent: int) -> str:
    lines: list[str] = []
    pad = " " * indent
    for item in value:
        if isinstance(item, dict):
            if not item:
                lines.append(f"{pad}- {{}}")
                continue
            first = True
            for key, child in item.items():
                rendered_key = _key(str(key))
                if first:
                    prefix = f"{pad}- {rendered_key}:"
                    first = False
                else:
                    prefix = f"{pad}  {rendered_key}:"
                if isinstance(child, dict):
                    lines.append(prefix)
                    lines.append(_render_map(child, indent + 4 if prefix.startswith(f"{pad}-") else indent + 4))
                elif isinstance(child, list):
                    lines.append(prefix)
                    lines.append(_render_list(child, indent + 4))
                elif isinstance(child, str) and "\n" in child:
                    lines.append(f"{prefix} |")
                    for line in child.splitlines():
                        lines.append(f"{pad}    {line}")
                else:
                    lines.append(f"{prefix} {_scalar(child)}")
        elif isinstance(item, list):
            lines.append(f"{pad}-")
            lines.append(_render_list(item, indent + 2))
        else:
            lines.append(f"{pad}- {_scalar(item)}")
    return "\n".join(lines)


def _key(value: str) -> str:
    if re.match(r"^[A-Za-z_][A-Za-z0-9_.:-]*$", value):
        return value
    return json.dumps(value)


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value)
    lowered = text.lower()
    if text and _SAFE_STRING_RE.match(text) and lowered not in _RESERVED and not text.startswith(("-", "{", "[", ">", "|")):
        return text
    return json.dumps(text, ensure_ascii=True)


def format_value(value: Any) -> str:
    return dumps(value)
