from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinel.platform.config import config_graph, explain_config, resolve_config, simulate_config
from sentinel.sntl.canonical import canonical_json, fingerprint
from sentinel.sntl.convert import (
    INPUT_FORMATS,
    OUTPUT_FORMATS,
    SntlConversion,
    SntlFormatInspection,
    SntlMigrationItem,
    SntlMigrationPlan,
    SntlRoundTrip,
    compare_formats,
    convert,
    convert_file,
    convert_text,
    convert_tree,
    detect_format,
    format_capabilities,
    from_csv,
    from_json,
    from_jsonl,
    from_toml,
    from_yaml,
    from_yara,
    inspect_file,
    inspect_text,
    load_any,
    loads_any,
    migrate_file,
    migrate_tree,
    normalize_document,
    plan_conversion,
    parse_yara,
    roundtrip_file,
    roundtrip_text,
    schema_for,
    to_json,
    to_jsonl,
    to_sntl,
    to_toml,
    wrap_imported,
)
from sentinel.sntl.ops import diff, merge, redact
from sentinel.sntl.parser import parse, parse_document
from sentinel.sntl.path import get_path, query, set_path, walk
from sentinel.sntl.schemas import KNOWN_SCHEMAS, json_schema, validate, write_json_schema
from sentinel.sntl.types import SntlBundle, SntlDocument, SntlIssue, SntlParseError, SntlValidationError
from sentinel.sntl.writer import dump, dumps, format_value


def loads(text: str, source: str = "<memory>", schema: str | None = None) -> SntlDocument:
    try:
        loaded = parse_document(text)
    except SntlParseError as exc:
        issue = SntlIssue("error", f"{exc.line}:{exc.column}", str(exc))
        return SntlDocument(source, {}, schema, fingerprint({}), (issue,))
    selected_schema = schema or loaded.get("schema")
    issues = tuple(validate(loaded, selected_schema))
    return SntlDocument(source, loaded, selected_schema, fingerprint(loaded), issues)


def load(path: str | Path, schema: str | None = None) -> SntlDocument:
    p = Path(path)
    return loads(p.read_text(encoding="utf-8"), str(p), schema)


def resolve(
    paths: list[str | Path],
    profile: str | None = None,
    environment: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> SntlBundle:
    resolved = resolve_config(paths, profile=profile, environment=environment, overrides=overrides)
    issues = tuple(validate(resolved.data, resolved.data.get("schema")))
    layers = tuple(layer.__dict__ for layer in resolved.layers)
    return SntlBundle(resolved.data, resolved.fingerprint, profile, environment, layers, issues)


def explain(paths: list[str | Path], profile: str | None = None, environment: str | None = None) -> dict[str, Any]:
    resolved = resolve_config(paths, profile=profile, environment=environment)
    payload = explain_config(resolved)
    payload["schema_version"] = "sentinel.sntl.explain.v1"
    return payload


def graph(paths: list[str | Path], profile: str | None = None, environment: str | None = None) -> dict[str, Any]:
    resolved = resolve_config(paths, profile=profile, environment=environment)
    payload = config_graph(resolved)
    payload["schema_version"] = "sentinel.sntl.graph.v1"
    return payload


def simulate(data_or_paths: dict[str, Any] | list[str | Path], profile: str | None = None, environment: str | None = None) -> dict[str, Any]:
    if isinstance(data_or_paths, dict):
        return simulate_config(data_or_paths)
    return simulate_config(resolve(data_or_paths, profile=profile, environment=environment).data)
