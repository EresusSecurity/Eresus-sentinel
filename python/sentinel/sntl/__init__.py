from __future__ import annotations

_EXPORTS = {
    "KNOWN_SCHEMAS": "api",
    "INPUT_FORMATS": "api",
    "OUTPUT_FORMATS": "api",
    "SntlBundle": "api",
    "SntlConversion": "api",
    "SntlDocument": "api",
    "SntlFormatInspection": "api",
    "SntlIssue": "api",
    "SntlMigrationItem": "api",
    "SntlMigrationPlan": "api",
    "SntlParseError": "api",
    "SntlRoundTrip": "api",
    "SntlValidationError": "api",
    "canonical_json": "api",
    "cartesian_matrix": "api",
    "compare_formats": "api",
    "convert": "api",
    "convert_file": "api",
    "convert_text": "api",
    "convert_tree": "api",
    "detect_format": "api",
    "diff": "api",
    "dump": "api",
    "dumps": "api",
    "expand_matrix": "api",
    "extract_variables": "api",
    "flatten": "api",
    "explain": "api",
    "fingerprint": "api",
    "format_capabilities": "api",
    "format_value": "api",
    "from_csv": "api",
    "from_json": "api",
    "from_jsonl": "api",
    "from_toml": "api",
    "from_yaml": "api",
    "from_yara": "api",
    "get_path": "api",
    "graph": "api",
    "json_schema": "api",
    "inspect_file": "api",
    "inspect_text": "api",
    "interpolate": "api",
    "interpolate_document": "api",
    "load": "api",
    "load_any": "api",
    "loads": "api",
    "loads_any": "api",
    "merge": "api",
    "migrate_file": "api",
    "patch": "api",
    "migrate_tree": "api",
    "normalize_document": "api",
    "parse": "api",
    "parse_yara": "api",
    "plan_conversion": "api",
    "query": "api",
    "redact": "api",
    "render_prompt": "api",
    "resolve": "api",
    "roundtrip_file": "api",
    "roundtrip_text": "api",
    "schema_for": "api",
    "set_path": "api",
    "simulate": "api",
    "to_json": "api",
    "to_jsonl": "api",
    "to_sntl": "api",
    "to_toml": "api",
    "validate": "api",
    "select": "api",
    "walk": "api",
    "wildcard_query": "api",
    "wrap_imported": "api",
    "write_json_schema": "api",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(name)
    from importlib import import_module

    module = import_module(f"{__name__}.{module_name}")
    value = getattr(module, name)
    globals()[name] = value
    return value
