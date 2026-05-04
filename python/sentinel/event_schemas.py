"""Event schema validation utility using JSON Schema."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

EVENT_SCHEMA_VERSION = "event.schema.v1"


def _get_schema_dir() -> Path:
    pkg = Path(__file__).parent / "config" / "schemas"
    if pkg.exists():
        return pkg
    dev = Path(__file__).parent.parent.parent / "config" / "schemas"
    if dev.exists():
        return dev
    return pkg


def load_schema(name: str) -> dict[str, Any]:
    """Load a JSON schema by name (without .json extension)."""
    path = _get_schema_dir() / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Schema not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_event(event: dict[str, Any], schema_name: str) -> tuple[bool, list[str]]:
    """Validate an event dict against a named schema. Returns (valid, errors)."""
    try:
        schema = load_schema(schema_name)
    except FileNotFoundError as e:
        return False, [str(e)]

    errors: list[str] = []
    required = schema.get("required", [])
    for field in required:
        if field not in event:
            errors.append(f"Missing required field: {field}")

    properties = schema.get("properties", {})
    for key, value in event.items():
        if key not in properties:
            continue
        prop_schema = properties[key]
        expected_type = prop_schema.get("type")
        if expected_type and not _type_matches(value, expected_type):
            errors.append(f"Field '{key}': expected {expected_type}, got {type(value).__name__}")
        if "enum" in prop_schema and value not in prop_schema["enum"]:
            errors.append(f"Field '{key}': value '{value}' not in enum {prop_schema['enum']}")
        if expected_type == "number":
            if "minimum" in prop_schema and isinstance(value, (int, float)) and value < prop_schema["minimum"]:
                errors.append(f"Field '{key}': {value} < minimum {prop_schema['minimum']}")
            if "maximum" in prop_schema and isinstance(value, (int, float)) and value > prop_schema["maximum"]:
                errors.append(f"Field '{key}': {value} > maximum {prop_schema['maximum']}")

    return (len(errors) == 0, errors)


def list_schemas() -> list[str]:
    """List all available schema names."""
    d = _get_schema_dir()
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.json"))


def build_scan_event(
    *,
    domain: str,
    status: str,
    target: str = "",
    finding_count: int = 0,
    duration_ms: float = 0.0,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "scan_id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "status": status,
        "target": target,
        "finding_count": finding_count,
        "duration_ms": duration_ms,
        "metadata": metadata or {},
    }


def build_gateway_event(
    *,
    event_type: str,
    payload: dict[str, Any],
    source: str = "sentinel.gateway",
    correlation_id: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "envelope_id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "version": "1.0",
        "source": source,
        "correlation_id": correlation_id,
        "payload": payload,
        "routing": {"destination": "audit", "priority": "normal"},
    }


def _type_matches(value: Any, expected: str) -> bool:
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    expected_type = type_map.get(expected)
    if expected_type is None:
        return True
    return isinstance(value, expected_type)
