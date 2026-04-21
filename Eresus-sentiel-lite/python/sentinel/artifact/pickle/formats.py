"""Format detection helpers for pickle streams."""

from __future__ import annotations

# Pickle protocol headers for nested detection
PROTO_HEADERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

# YAML deserialization markers
YAML_MARKERS = [
    b"!!python/object/apply",
    b"!!python/object/new",
    b"!!python/module",
    b"!!python/name",
    b"!!python/object:",
    b"!!python/tuple",
    b"!!python/bytes",
    b"tag:yaml.org,2002:python/object/apply",
    b"tag:yaml.org,2002:python/object/new",
    b"tag:yaml.org,2002:python/name",
    b"tag:yaml.org,2002:python/module",
]

# TAR magic
TAR_MAGIC = b"ustar"
TAR_MAGIC_OFFSET = 257


def detect_protocol(data: bytes) -> int:
    """Detect pickle protocol version from raw bytes."""
    from .._pickle_ops import PROTOCOL_MARKERS

    if len(data) < 2:
        return -1
    header = data[:2]
    if header in PROTOCOL_MARKERS:
        return PROTOCOL_MARKERS[header]
    if data[0:1] in (b"(", b"c", b"l", b"d"):
        return 0
    return -1


def detect_nested_pickle(data: bytes) -> bool:
    """Detect pickle-in-pickle exploit chaining.

    A valid pickle stream ends with one STOP (0x2e). If a PROTO header
    appears after the final STOP, there is a second pickle embedded.
    """
    if len(data) < 8:
        return False

    has_proto_start = any(data[:2] == m for m in PROTO_HEADERS)
    if not has_proto_start:
        return False

    last_stop = data.rfind(b"\x2e")
    if last_stop <= 0:
        return False

    remaining = data[last_stop + 1:]
    if len(remaining) < 4:
        return False

    for marker in PROTO_HEADERS:
        pos = remaining.find(marker)
        if pos >= 0 and pos + 2 < len(remaining):
            if remaining[pos + 1] <= 5:
                return True

    return False


def detect_tar(data: bytes) -> bool:
    """Detect TAR archive format (old PyTorch serialization)."""
    if len(data) > TAR_MAGIC_OFFSET + 5:
        return data[TAR_MAGIC_OFFSET:TAR_MAGIC_OFFSET + 5] == TAR_MAGIC
    return False


def detect_yaml_markers(data: bytes) -> bool:
    """Check for YAML deserialization markers in raw bytes."""
    for marker in YAML_MARKERS:
        if marker in data:
            return True
    return False


def parse_global_arg(arg: str) -> tuple[str, str]:
    """Parse a GLOBAL/INST opcode argument into (module, name)."""
    if not arg:
        return ("", "")
    if "\n" in arg:
        parts = arg.split("\n", 1)
    elif " " in arg:
        parts = arg.split(" ", 1)
    else:
        parts = [arg, ""]
    module = parts[0].strip() if len(parts) > 0 else ""
    name = parts[1].strip() if len(parts) > 1 else ""
    return (module, name)
