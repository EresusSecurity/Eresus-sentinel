"""Format detection helpers for pickle streams."""

from __future__ import annotations

# Pickle protocol headers for nested detection (protocols 1-5 have explicit headers)
# Protocol 0 is text-based and has no magic header — detected by leading opcodes
PROTO_HEADERS = [b"\x80\x01", b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

# Protocol-0 leading opcodes (text-based, no binary header)
# Valid first bytes for a protocol-0 pickle stream
PROTO0_LEAD_BYTES = {b"(", b"c", b"l", b"d", b"i", b"o", b"s", b"p", b"g"}

# All protocol magic bytes (incl. proto-0 heuristic detection marker)
ALL_PROTO_PREFIXES = PROTO_HEADERS  # proto-0 needs context-aware detection

# Dangerous protocol-0 gadgets: GLOBAL opcode ('c') followed by module\nname
# Protocol-0 encodes GLOBAL as ASCII text: c<module>\n<name>\n
PROTO0_GLOBAL_PATTERN = b"c"  # followed by printable ASCII module\nname\n

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
    # Protocol 0: text-based, starts with a recognised opcode byte
    if data[0:1] in PROTO0_LEAD_BYTES:
        return 0
    return -1


def detect_nested_pickle(data: bytes) -> bool:
    """Detect pickle-in-pickle exploit chaining.

    A valid pickle stream ends with one STOP (0x2e). If any protocol header
    (proto 1-5) OR a proto-0 GLOBAL opcode appears after the final STOP,
    a second pickle stream is embedded.
    """
    if len(data) < 8:
        return False

    last_stop = data.rfind(b"\x2e")
    if last_stop <= 0:
        return False

    remaining = data[last_stop + 1:]
    if not remaining:
        return False

    # Proto 1-5: check for explicit binary header after STOP
    for marker in PROTO_HEADERS:
        pos = remaining.find(marker)
        if pos >= 0 and pos + 2 < len(remaining):
            proto_byte = remaining[pos + 1]
            if 1 <= proto_byte <= 5:
                return True

    # Proto 0: GLOBAL opcode ('c' = 0x63) after STOP
    # A proto-0 GLOBAL looks like:  c<module>\n<name>\n
    c_pos = remaining.find(b"c")
    if c_pos >= 0 and c_pos + 3 < len(remaining):
        after_c = remaining[c_pos + 1:c_pos + 80]
        if b"\n" in after_c and all(
            0x20 <= b < 0x7F or b in (0x0A,) for b in after_c[:after_c.index(b"\n") + 1]
        ):
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
