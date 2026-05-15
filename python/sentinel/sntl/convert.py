from __future__ import annotations

import csv
import io
import json
import re
import tomllib
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.sntl.canonical import fingerprint
from sentinel.sntl.parser import parse_document
from sentinel.sntl.schemas import validate
from sentinel.sntl.types import SntlDocument, SntlIssue, SntlParseError
from sentinel.sntl.writer import dumps


INPUT_FORMATS = {"sntl", "sentinel", "json", "jsonl", "ndjson", "toml", "yaml", "yml", "yara", "yar", "csv"}
OUTPUT_FORMATS = {"sntl", "sentinel", "json", "json-pretty", "jsonl", "ndjson", "toml"}
_FORMAT_BY_SUFFIX = {
    ".sntl": "sntl",
    ".sentinel": "sentinel",
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".yara": "yara",
    ".yar": "yara",
    ".csv": "csv",
}
_RULE_START_RE = re.compile(r"\b((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([^{\n]+))?\s*\{", re.MULTILINE)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


@dataclass(frozen=True)
class SntlConversion:
    source_format: str
    target_format: str
    source: str
    data: dict[str, Any]
    text: str
    fingerprint: str
    issues: tuple[SntlIssue, ...]

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)


@dataclass(frozen=True)
class SntlFormatInspection:
    source: str
    format: str
    schema: str | None
    inferred_schema: str | None
    fingerprint: str
    valid: bool
    top_level_keys: tuple[str, ...]
    item_count: int
    capabilities: dict[str, Any]
    issues: tuple[SntlIssue, ...]


@dataclass(frozen=True)
class SntlMigrationItem:
    source: str
    target: str
    source_format: str
    target_format: str
    schema: str | None
    fingerprint: str | None
    valid: bool
    issues: tuple[SntlIssue, ...]


@dataclass(frozen=True)
class SntlMigrationPlan:
    source_root: str
    target_root: str
    target_format: str
    items: tuple[SntlMigrationItem, ...]
    skipped: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not any(not item.valid for item in self.items)


@dataclass(frozen=True)
class SntlRoundTrip:
    source: str
    source_format: str
    target_format: str
    return_format: str
    stable: bool
    source_fingerprint: str
    rendered_fingerprint: str
    returned_fingerprint: str
    issues: tuple[SntlIssue, ...]


def format_capabilities() -> dict[str, dict[str, Any]]:
    return {
        "sntl": {
            "read": True,
            "write": True,
            "schema": True,
            "comments": True,
            "multiline": True,
            "null": True,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": True,
        },
        "json": {
            "read": True,
            "write": True,
            "schema": False,
            "comments": False,
            "multiline": False,
            "null": True,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": False,
        },
        "jsonl": {
            "read": True,
            "write": True,
            "schema": False,
            "comments": False,
            "multiline": False,
            "null": True,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": False,
        },
        "csv": {
            "read": True,
            "write": False,
            "schema": False,
            "comments": False,
            "multiline": False,
            "null": False,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": False,
        },
        "toml": {
            "read": True,
            "write": True,
            "schema": False,
            "comments": True,
            "multiline": True,
            "null": False,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": False,
        },
        "yaml": {
            "read": True,
            "write": False,
            "schema": False,
            "comments": True,
            "multiline": True,
            "null": True,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": False,
        },
        "yara": {
            "read": True,
            "write": False,
            "schema": False,
            "comments": True,
            "multiline": True,
            "null": False,
            "fingerprint": True,
            "safe_by_default": True,
            "rule_import": True,
        },
    }


def compare_formats() -> dict[str, Any]:
    capabilities = format_capabilities()
    keys = sorted({key for profile in capabilities.values() for key in profile})
    rows = []
    for fmt, profile in sorted(capabilities.items()):
        score = sum(1 for key in keys if profile.get(key) is True)
        rows.append({"format": fmt, "score": score, "capabilities": {key: profile.get(key, False) for key in keys}})
    return {"schema_version": "sentinel.sntl.format.compare.v1", "capabilities": keys, "formats": rows, "recommended_authoring_format": "sntl"}


def schema_for(data: Any, source_format: str | None = None) -> str:
    return _infer_schema(data, _normalize_format(source_format or "sntl"))


def normalize_document(data: Any, schema: str | None = None, name: str | None = None, source_format: str | None = None) -> dict[str, Any]:
    return wrap_imported(data, schema=schema, name=name, source_format=source_format)


def detect_format(path: str | Path | None = None, text: str | None = None, source_format: str | None = None) -> str:
    if source_format:
        return _normalize_format(source_format)
    if path is not None:
        suffix = Path(path).suffix.lower()
        if suffix in _FORMAT_BY_SUFFIX:
            return _FORMAT_BY_SUFFIX[suffix]
    if text is not None:
        stripped = text.lstrip()
        if stripped.startswith("%sntl"):
            return "sntl"
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        if _RULE_START_RE.search(stripped):
            return "yara"
        if "\n---" in f"\n{stripped[:4096]}" or re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*:", stripped):
            return "yaml"
        if re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=", stripped):
            return "toml"
    return "sntl"


def load_any(path: str | Path, source_format: str | None = None, schema: str | None = None, name: str | None = None, wrap: bool = True) -> SntlDocument:
    p = Path(path)
    return loads_any(p.read_text(encoding="utf-8"), source_format=source_format or detect_format(path=p), source=str(p), schema=schema, name=name, wrap=wrap)


def loads_any(
    text: str,
    source_format: str | None = None,
    source: str = "<memory>",
    schema: str | None = None,
    name: str | None = None,
    wrap: bool = True,
) -> SntlDocument:
    fmt = detect_format(text=text, source_format=source_format)
    try:
        data = _load_native(text, fmt, name=name)
        if wrap:
            data = wrap_imported(data, schema=schema, name=name, source_format=fmt)
        elif schema and isinstance(data, dict) and data.get("schema") is None:
            data = {**data, "schema": schema}
        if not isinstance(data, dict):
            data = wrap_imported(data, schema=schema, name=name, source_format=fmt)
        selected_schema = schema or data.get("schema")
        issues = tuple(validate(data, selected_schema))
        return SntlDocument(source, data, selected_schema, fingerprint(data), issues)
    except Exception as exc:
        issue = SntlIssue("error", source, str(exc))
        return SntlDocument(source, {}, schema, fingerprint({}), (issue,))


def convert_text(
    text: str,
    source_format: str | None = None,
    target_format: str = "sntl",
    schema: str | None = None,
    name: str | None = None,
) -> str:
    doc = loads_any(text, source_format=source_format, schema=schema, name=name).require()
    return _render_target(doc.data, target_format)


def convert(
    text: str,
    source_format: str | None = None,
    target_format: str = "sntl",
    schema: str | None = None,
    name: str | None = None,
    source: str = "<memory>",
) -> SntlConversion:
    doc = loads_any(text, source_format=source_format, source=source, schema=schema, name=name)
    rendered = _render_target(doc.data, target_format) if doc.ok else ""
    return SntlConversion(
        detect_format(text=text, source_format=source_format),
        _normalize_format(target_format),
        source,
        doc.data,
        rendered,
        doc.fingerprint,
        doc.issues,
    )


def convert_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    source_format: str | None = None,
    target_format: str | None = None,
    schema: str | None = None,
    name: str | None = None,
) -> Path:
    source = Path(input_path)
    target = Path(output_path) if output_path is not None else _default_output_path(source, target_format)
    selected_target = target_format or detect_format(path=target)
    rendered = convert_text(source.read_text(encoding="utf-8"), source_format=source_format or detect_format(path=source), target_format=selected_target, schema=schema, name=name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered, encoding="utf-8")
    return target


def migrate_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    source_format: str | None = None,
    target_format: str | None = None,
    schema: str | None = None,
    name: str | None = None,
) -> SntlMigrationItem:
    source = Path(input_path)
    try:
        target = convert_file(source, output_path, source_format=source_format, target_format=target_format, schema=schema, name=name)
        selected_target = detect_format(path=target)
        doc = load_any(target) if selected_target in {"sntl", "sentinel"} else None
        return SntlMigrationItem(
            str(source),
            str(target),
            detect_format(path=source, source_format=source_format),
            selected_target,
            doc.schema if doc else schema,
            doc.fingerprint if doc else None,
            doc.ok if doc else True,
            doc.issues if doc else (),
        )
    except Exception as exc:
        target = Path(output_path) if output_path is not None else _default_output_path(source, target_format)
        return SntlMigrationItem(
            str(source),
            str(target),
            detect_format(path=source, source_format=source_format),
            _normalize_format(target_format or detect_format(path=target)),
            schema,
            None,
            False,
            (SntlIssue("error", str(source), str(exc)),),
        )


def convert_tree(
    input_dir: str | Path,
    output_dir: str | Path,
    source_formats: set[str] | list[str] | tuple[str, ...] | None = None,
    target_format: str = "sntl",
    schema: str | None = None,
) -> list[Path]:
    root = Path(input_dir)
    out_root = Path(output_dir)
    formats = {_normalize_format(item) for item in source_formats} if source_formats else INPUT_FORMATS
    outputs: list[Path] = []
    for item in migrate_tree(root, out_root, source_formats=formats, target_format=target_format, schema=schema).items:
        if item.valid:
            outputs.append(Path(item.target))
    return outputs


def plan_conversion(
    input_path: str | Path,
    output_path: str | Path | None = None,
    source_formats: set[str] | list[str] | tuple[str, ...] | None = None,
    target_format: str = "sntl",
    schema: str | None = None,
) -> SntlMigrationPlan:
    source = Path(input_path)
    target_root = Path(output_path) if output_path is not None else _default_plan_output(source, target_format)
    formats = {_normalize_format(item) for item in source_formats} if source_formats else INPUT_FORMATS
    items: list[SntlMigrationItem] = []
    skipped: list[str] = []
    paths = sorted(item for item in source.rglob("*") if item.is_file()) if source.is_dir() else [source]
    for path in paths:
        fmt = detect_format(path=path)
        if fmt not in formats:
            skipped.append(str(path))
            continue
        target = target_root / path.relative_to(source).with_suffix(_suffix_for_target(target_format)) if source.is_dir() else target_root
        doc = load_any(path, source_format=fmt, schema=schema)
        items.append(
            SntlMigrationItem(
                str(path),
                str(target),
                fmt,
                _normalize_format(target_format),
                doc.schema,
                doc.fingerprint,
                doc.ok,
                doc.issues,
            )
        )
    return SntlMigrationPlan(str(source), str(target_root), _normalize_format(target_format), tuple(items), tuple(skipped))


def migrate_tree(
    input_dir: str | Path,
    output_dir: str | Path,
    source_formats: set[str] | list[str] | tuple[str, ...] | None = None,
    target_format: str = "sntl",
    schema: str | None = None,
) -> SntlMigrationPlan:
    plan = plan_conversion(input_dir, output_dir, source_formats=source_formats, target_format=target_format, schema=schema)
    items: list[SntlMigrationItem] = []
    for item in plan.items:
        items.append(migrate_file(item.source, item.target, source_format=item.source_format, target_format=item.target_format, schema=schema))
    return SntlMigrationPlan(plan.source_root, plan.target_root, plan.target_format, tuple(items), plan.skipped)


def inspect_text(text: str, source_format: str | None = None, source: str = "<memory>", schema: str | None = None, name: str | None = None) -> SntlFormatInspection:
    fmt = detect_format(text=text, source_format=source_format)
    doc = loads_any(text, source_format=fmt, source=source, schema=schema, name=name)
    inferred = schema_for(doc.data, fmt) if doc.data else schema
    return _inspection_from_document(source, fmt, inferred, doc)


def inspect_file(path: str | Path, source_format: str | None = None, schema: str | None = None, name: str | None = None) -> SntlFormatInspection:
    p = Path(path)
    return inspect_text(p.read_text(encoding="utf-8"), source_format=source_format or detect_format(path=p), source=str(p), schema=schema, name=name)


def roundtrip_text(
    text: str,
    source_format: str | None = None,
    target_format: str = "sntl",
    return_format: str = "json",
    schema: str | None = None,
    name: str | None = None,
    source: str = "<memory>",
) -> SntlRoundTrip:
    fmt = detect_format(text=text, source_format=source_format)
    first = loads_any(text, source_format=fmt, source=source, schema=schema, name=name)
    if not first.ok:
        return SntlRoundTrip(source, fmt, _normalize_format(target_format), _normalize_format(return_format), False, first.fingerprint, "", "", first.issues)
    rendered = _render_target(first.data, target_format)
    second = loads_any(rendered, source_format=target_format, source=f"{source}:rendered", schema=schema, name=name)
    if not second.ok:
        return SntlRoundTrip(source, fmt, _normalize_format(target_format), _normalize_format(return_format), False, first.fingerprint, second.fingerprint, "", second.issues)
    returned = _render_target(second.data, return_format)
    third = loads_any(returned, source_format=return_format, source=f"{source}:returned", schema=schema, name=name)
    issues = (*first.issues, *second.issues, *third.issues)
    stable = first.fingerprint == second.fingerprint == third.fingerprint and not any(issue.severity == "error" for issue in issues)
    return SntlRoundTrip(source, fmt, _normalize_format(target_format), _normalize_format(return_format), stable, first.fingerprint, second.fingerprint, third.fingerprint, tuple(issues))


def roundtrip_file(
    path: str | Path,
    source_format: str | None = None,
    target_format: str = "sntl",
    return_format: str = "json",
    schema: str | None = None,
    name: str | None = None,
) -> SntlRoundTrip:
    p = Path(path)
    return roundtrip_text(p.read_text(encoding="utf-8"), source_format=source_format or detect_format(path=p), target_format=target_format, return_format=return_format, schema=schema, name=name, source=str(p))


def from_json(text: str) -> Any:
    return json.loads(text)


def from_jsonl(text: str) -> list[Any]:
    rows: list[Any] = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rows.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            raise SntlParseError(str(exc), index, exc.colno) from exc
    return rows


def from_toml(text: str) -> dict[str, Any]:
    return tomllib.loads(text)


def from_yaml(text: str) -> dict[str, Any]:
    cleaned = _clean_yaml(text)
    return parse_document(cleaned)


def from_csv(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(reader, start=1):
        item: dict[str, Any] = {"id": row.get("id") or f"row-{index}"}
        item.update({key: _coerce_csv_value(value) for key, value in row.items() if key})
        rows.append(item)
    return rows


def from_yara(text: str, name: str | None = None) -> dict[str, Any]:
    rules = parse_yara(text)
    return {
        "schema": "sentinel.rulepack.v1",
        "name": name or "imported-yara-rules",
        "kind": "yara",
        "rules": rules,
        "lineage": {"source_format": "yara", "rule_count": len(rules)},
    }


def parse_yara(text: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for match in _RULE_START_RE.finditer(text):
        start = match.end() - 1
        end = _find_matching_brace(text, start)
        if end < 0:
            line = text[: start + 1].count("\n") + 1
            raise SntlParseError("unterminated yara rule", line, 1)
        body = text[start + 1 : end]
        prefix = match.group(1).strip()
        name = match.group(2)
        tags = [tag for tag in (match.group(3) or "").split() if tag]
        sections = _split_yara_sections(body)
        rules.append(
            {
                "id": _slug(name),
                "type": "yara",
                "name": name,
                "modifiers": prefix.split() if prefix else [],
                "tags": tags,
                "meta": _parse_yara_meta(sections.get("meta", [])),
                "strings": _parse_yara_strings(sections.get("strings", [])),
                "condition": _normalize_condition(sections.get("condition", [])),
                "source": {"format": "yara", "line": text[: match.start()].count("\n") + 1},
            }
        )
    return rules


def to_sntl(data: Any) -> str:
    return dumps(data)


def to_json(data: Any, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True, default=str) + "\n"
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str) + "\n"


def to_jsonl(data: Any) -> str:
    rows = data.get("records") if isinstance(data, dict) and isinstance(data.get("records"), list) else data
    if not isinstance(rows, list):
        rows = [rows]
    return "".join(json.dumps(row, sort_keys=True, ensure_ascii=True, default=str) + "\n" for row in rows)


def to_toml(data: Any) -> str:
    if not isinstance(data, dict):
        raise ValueError("toml output requires an object")
    lines: list[str] = []
    _write_toml_object(data, [], lines)
    return "\n".join(lines).rstrip() + "\n"


def wrap_imported(data: Any, schema: str | None = None, name: str | None = None, source_format: str | None = None) -> dict[str, Any]:
    fmt = _normalize_format(source_format or "sntl")
    if isinstance(data, dict) and data.get("schema"):
        out = deepcopy(data)
        if schema:
            out["schema"] = schema
        if name and "name" not in out:
            out["name"] = name
        return out
    if fmt == "yara" and isinstance(data, dict):
        return deepcopy(data)
    selected = schema or _infer_schema(data, fmt)
    if isinstance(data, dict):
        out = deepcopy(data)
        out.setdefault("schema", selected)
        if name is not None:
            out.setdefault("name", name)
        if selected in {"sentinel.dataset.v1", "sentinel.assertion.v1", "sentinel.provider.v1", "sentinel.rulepack.v1", "sentinel.redteam.v1", "sentinel.runtime.v1", "sentinel.policy.v1", "sentinel.baseline.v1", "sentinel.report.v1"}:
            return _complete_schema_container(out, selected, name)
        return out
    if selected == "sentinel.dataset.v1":
        return {"schema": selected, "name": name or "imported-records", "records": _records_from_value(data)}
    if selected == "sentinel.assertion.v1":
        return {"schema": selected, "name": name or "imported-assertions", "assertions": _objects_from_value(data, "assertion")}
    if selected == "sentinel.provider.v1":
        return {"schema": selected, "providers": _objects_from_value(data, "provider")}
    if selected == "sentinel.rulepack.v1":
        return {"schema": selected, "name": name or "imported-rules", "rules": _objects_from_value(data, "rule")}
    return {"schema": selected, "name": name or "imported-config", "value": data}


def _load_native(text: str, fmt: str, name: str | None = None) -> Any:
    selected = _normalize_format(fmt)
    if selected in {"sntl", "sentinel"}:
        return parse_document(text)
    if selected == "json":
        return from_json(text)
    if selected in {"jsonl", "ndjson"}:
        return from_jsonl(text)
    if selected == "toml":
        return from_toml(text)
    if selected in {"yaml", "yml"}:
        return from_yaml(text)
    if selected == "csv":
        return from_csv(text)
    if selected == "yara":
        return from_yara(text, name=name)
    raise ValueError(f"unsupported source format: {fmt}")


def _render_target(data: dict[str, Any], target_format: str) -> str:
    selected = _normalize_format(target_format)
    if selected in {"sntl", "sentinel"}:
        return to_sntl(data)
    if selected == "json":
        return to_json(data, pretty=False)
    if selected == "json-pretty":
        return to_json(data, pretty=True)
    if selected in {"jsonl", "ndjson"}:
        return to_jsonl(data)
    if selected == "toml":
        return to_toml(data)
    raise ValueError(f"unsupported target format: {target_format}")


def _normalize_format(value: str) -> str:
    fmt = value.strip().lower().lstrip(".")
    aliases = {"yml": "yaml", "yar": "yara", "ndjson": "jsonl", "sentinel": "sentinel"}
    fmt = aliases.get(fmt, fmt)
    if fmt not in INPUT_FORMATS and fmt not in OUTPUT_FORMATS and fmt != "json-pretty":
        raise ValueError(f"unsupported format: {value}")
    return fmt


def _default_output_path(path: Path, target_format: str | None) -> Path:
    selected = _normalize_format(target_format or "sntl")
    return path.with_suffix(_suffix_for_target(selected))


def _default_plan_output(path: Path, target_format: str) -> Path:
    if path.is_dir():
        return path.parent / f"{path.name}-sntl"
    return _default_output_path(path, target_format)


def _suffix_for_target(target_format: str) -> str:
    selected = _normalize_format(target_format)
    if selected == "sentinel":
        return ".sentinel"
    if selected == "json-pretty":
        return ".json"
    if selected == "jsonl":
        return ".jsonl"
    return f".{selected}"


def _inspection_from_document(source: str, fmt: str, inferred_schema: str | None, doc: SntlDocument) -> SntlFormatInspection:
    data = doc.data
    keys = tuple(sorted(data.keys())) if isinstance(data, dict) else ()
    return SntlFormatInspection(
        source,
        fmt,
        doc.schema,
        inferred_schema,
        doc.fingerprint,
        doc.ok,
        keys,
        _item_count(data),
        _capabilities_for_data(data, fmt),
        doc.issues,
    )


def _capabilities_for_data(data: dict[str, Any], fmt: str) -> dict[str, Any]:
    schema = data.get("schema") if isinstance(data, dict) else None
    return {
        "format": fmt,
        "schema": schema,
        "has_profiles": isinstance(data.get("profiles") if isinstance(data, dict) else None, dict),
        "has_environments": isinstance(data.get("environments") if isinstance(data, dict) else None, dict),
        "has_lineage": "lineage" in data if isinstance(data, dict) else False,
        "has_evidence": "evidence" in data or "artifacts" in data if isinstance(data, dict) else False,
        "records": len(data.get("records", [])) if isinstance(data, dict) and isinstance(data.get("records"), list) else 0,
        "rules": len(data.get("rules", [])) if isinstance(data, dict) and isinstance(data.get("rules"), list) else 0,
        "assertions": len(data.get("assertions", [])) if isinstance(data, dict) and isinstance(data.get("assertions"), list) else 0,
        "providers": len(data.get("providers", [])) if isinstance(data, dict) and isinstance(data.get("providers"), list) else 0,
        "prompts": len(data.get("prompts", [])) if isinstance(data, dict) and isinstance(data.get("prompts"), list) else 0,
    }


def _item_count(data: Any) -> int:
    if isinstance(data, dict):
        for key in ("records", "rules", "assertions", "providers", "prompts", "attacks", "policies", "events", "artifacts"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
        return len(data)
    if isinstance(data, list):
        return len(data)
    return 1


def _clean_yaml(text: str) -> str:
    lines: list[str] = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped in {"---", "..."}:
            continue
        if re.search(r"(^|\s)[!&*][A-Za-z0-9_.:-]+", line):
            raise SntlParseError("yaml tags, anchors, and aliases are not supported", index, 1)
        lines.append(line)
    return "\n".join(lines).strip() + "\n"


def _infer_schema(data: Any, fmt: str) -> str:
    if fmt in {"jsonl", "csv"} or isinstance(data, list):
        return "sentinel.dataset.v1"
    if isinstance(data, dict):
        keys = set(data)
        if "assertions" in keys and "providers" not in keys:
            return "sentinel.assertion.v1"
        if "providers" in keys and "prompts" in keys:
            return "sentinel.eval.v1"
        if "providers" in keys:
            return "sentinel.provider.v1"
        if "records" in keys:
            return "sentinel.dataset.v1"
        if "rules" in keys:
            return "sentinel.rulepack.v1"
        if "attacks" in keys:
            return "sentinel.redteam.v1"
        if "policies" in keys:
            return "sentinel.runtime.v1"
        if "events" in keys and "run_id" in keys:
            return "sentinel.trace.v1"
    return "sentinel.config.v1"


def _complete_schema_container(data: dict[str, Any], schema: str, name: str | None) -> dict[str, Any]:
    out = deepcopy(data)
    if schema == "sentinel.dataset.v1":
        out.setdefault("name", name or "imported-records")
        out.setdefault("records", _records_from_value(out.pop("data", [])))
    elif schema == "sentinel.assertion.v1":
        out.setdefault("name", name or "imported-assertions")
        out.setdefault("assertions", _objects_from_value(out.pop("data", out.get("assertions", [])), "assertion"))
    elif schema == "sentinel.provider.v1":
        out.setdefault("providers", _objects_from_value(out.pop("data", out.get("providers", [])), "provider"))
    elif schema == "sentinel.rulepack.v1":
        out.setdefault("name", name or "imported-rules")
        out.setdefault("rules", _objects_from_value(out.pop("data", out.get("rules", [])), "rule"))
    elif schema == "sentinel.redteam.v1":
        out.setdefault("name", name or "imported-redteam")
        out.setdefault("attacks", _objects_from_value(out.pop("data", out.get("attacks", [])), "attack"))
    elif schema == "sentinel.runtime.v1":
        out.setdefault("name", name or "imported-runtime")
        out.setdefault("policies", _objects_from_value(out.pop("data", out.get("policies", [])), "policy"))
    elif schema == "sentinel.policy.v1":
        out.setdefault("name", name or "imported-policy")
        out.setdefault("rules", _objects_from_value(out.pop("data", out.get("rules", [])), "rule"))
    elif schema == "sentinel.baseline.v1":
        out.setdefault("name", name or "imported-baseline")
        out.setdefault("runs", _objects_from_value(out.pop("data", out.get("runs", [])), "run"))
    elif schema == "sentinel.report.v1":
        out.setdefault("run_id", name or "imported-run")
        out.setdefault("artifacts", _objects_from_value(out.pop("data", out.get("artifacts", [])), "artifact"))
    return out


def _records_from_value(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        if all(isinstance(item, dict) for item in value):
            records: list[dict[str, Any]] = []
            for index, item in enumerate(value, start=1):
                record = deepcopy(item)
                record.setdefault("id", f"record-{index}")
                records.append(record)
            return records
        return [{"id": f"record-{index}", "value": item} for index, item in enumerate(value, start=1)]
    if isinstance(value, dict):
        record = deepcopy(value)
        record.setdefault("id", "record-1")
        return [record]
    return [{"id": "record-1", "value": value}]


def _objects_from_value(value: Any, prefix: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        values = value
    else:
        values = [value]
    objects: list[dict[str, Any]] = []
    for index, item in enumerate(values, start=1):
        if isinstance(item, dict):
            obj = deepcopy(item)
            obj.setdefault("id", f"{prefix}-{index}")
            objects.append(obj)
        else:
            objects.append({"id": f"{prefix}-{index}", "value": item})
    return objects


def _coerce_csv_value(value: str | None) -> Any:
    if value is None:
        return None
    stripped = value.strip()
    if stripped == "":
        return ""
    lowered = stripped.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none"}:
        return None
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        return stripped


def _find_matching_brace(text: str, start: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_yara_sections(body: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {"meta": [], "strings": [], "condition": []}
    current: str | None = None
    for line in body.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered in {"meta:", "strings:", "condition:"}:
            current = lowered[:-1]
            continue
        if current:
            sections[current].append(line)
    return sections


def _parse_yara_meta(lines: list[str]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if _IDENTIFIER_RE.match(key):
            meta[key] = _parse_yara_value(value.strip())
    return meta


def _parse_yara_strings(lines: list[str]) -> list[dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or "=" not in stripped:
            continue
        left, right = stripped.split("=", 1)
        identifier = left.strip()
        if not identifier.startswith("$"):
            continue
        pattern, modifiers = _split_yara_pattern(right.strip())
        strings.append({"id": identifier, "kind": _yara_pattern_kind(pattern), "pattern": pattern, "modifiers": modifiers})
    return strings


def _parse_yara_value(value: str) -> Any:
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _split_yara_pattern(value: str) -> tuple[str, list[str]]:
    if not value:
        return "", []
    if value[0] == '"':
        end = _find_unescaped(value, '"', 1)
        if end >= 0:
            return value[: end + 1], value[end + 1 :].split()
    if value[0] == "/":
        end = _find_unescaped(value, "/", 1)
        if end >= 0:
            return value[: end + 1], value[end + 1 :].split()
    if value[0] == "{":
        end = _find_matching_brace(value, 0)
        if end >= 0:
            return value[: end + 1], value[end + 1 :].split()
    return value, []


def _find_unescaped(value: str, needle: str, start: int) -> int:
    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == needle:
            return index
    return -1


def _yara_pattern_kind(pattern: str) -> str:
    if pattern.startswith('"'):
        return "text"
    if pattern.startswith("/"):
        return "regex"
    if pattern.startswith("{"):
        return "hex"
    return "raw"


def _normalize_condition(lines: list[str]) -> str:
    return "\n".join(line.rstrip() for line in lines).strip()


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-").lower()
    return slug or "rule"


def _write_toml_object(data: dict[str, Any], path: list[str], lines: list[str]) -> None:
    scalars: list[tuple[str, Any]] = []
    objects: list[tuple[str, dict[str, Any]]] = []
    arrays: list[tuple[str, list[Any]]] = []
    for key, value in data.items():
        if isinstance(value, dict):
            objects.append((key, value))
        elif isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            arrays.append((key, value))
        else:
            scalars.append((key, value))
    for key, value in scalars:
        lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    for key, value in objects:
        if lines and lines[-1] != "":
            lines.append("")
        section = ".".join(_toml_key(part) for part in [*path, key])
        lines.append(f"[{section}]")
        _write_toml_object(value, [*path, key], lines)
    for key, items in arrays:
        for item in items:
            if lines and lines[-1] != "":
                lines.append("")
            section = ".".join(_toml_key(part) for part in [*path, key])
            lines.append(f"[[{section}]]")
            _write_toml_object(item, [*path, key], lines)


def _toml_key(value: str) -> str:
    if _IDENTIFIER_RE.match(value):
        return value
    return json.dumps(value, ensure_ascii=True)


def _toml_value(value: Any) -> str:
    if value is None:
        raise ValueError("toml output cannot represent null")
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=True, default=str)
