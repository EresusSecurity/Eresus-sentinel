from __future__ import annotations

_EXPORTS = {
    "KNOWN_SCHEMAS": "api",
    "SntlBundle": "api",
    "SntlDocument": "api",
    "SntlIssue": "api",
    "SntlParseError": "api",
    "SntlValidationError": "api",
    "canonical_json": "api",
    "diff": "api",
    "dump": "api",
    "dumps": "api",
    "explain": "api",
    "fingerprint": "api",
    "format_value": "api",
    "get_path": "api",
    "graph": "api",
    "json_schema": "api",
    "load": "api",
    "loads": "api",
    "merge": "api",
    "parse": "api",
    "query": "api",
    "redact": "api",
    "resolve": "api",
    "set_path": "api",
    "simulate": "api",
    "validate": "api",
    "walk": "api",
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
