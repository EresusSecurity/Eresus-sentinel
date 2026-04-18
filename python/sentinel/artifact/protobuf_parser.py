"""
Eresus Sentinel — Zero-Dependency Protobuf Wire Format Parser.

Shared utility for parsing protobuf-encoded binary data at the byte level.
Used by ONNX and TensorFlow SavedModel scanners to analyze model files
without requiring heavy framework dependencies.

Protobuf wire format reference:
  https://protobuf.dev/programming-guides/encoding/

Wire types:
  0 = Varint (int32, int64, uint32, uint64, sint32, sint64, bool, enum)
  1 = 64-bit (fixed64, sfixed64, double)
  2 = Length-delimited (string, bytes, embedded messages, packed repeated)
  5 = 32-bit (fixed32, sfixed32, float)
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

# ======================== WIRE TYPE CONSTANTS ========================

VARINT = 0
FIXED64 = 1
LENGTH_DELIMITED = 2
FIXED32 = 5


class ProtobufParser:
    """Zero-dependency protobuf wire format parser.

    All methods are static — no instance state required.
    Designed for security-critical analysis where we need to
    inspect raw protobuf without trusting the schema.
    """

    @staticmethod
    def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
        """Read a protobuf varint, return (value, new_offset).

        Varints use 7 bits per byte with MSB as continuation bit.
        """
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    @staticmethod
    def parse_fields(data: bytes) -> List[Tuple[int, int, bytes]]:
        """Parse protobuf fields into (field_number, wire_type, value_bytes) tuples.

        Handles all standard wire types. Stops on unknown wire types or
        data corruption (defensive parsing for security analysis).
        """
        fields: List[Tuple[int, int, bytes]] = []
        offset = 0
        while offset < len(data):
            try:
                tag, offset = ProtobufParser.read_varint(data, offset)
                field_number = tag >> 3
                wire_type = tag & 0x07

                if wire_type == VARINT:
                    value, offset = ProtobufParser.read_varint(data, offset)
                    fields.append((field_number, wire_type, value.to_bytes(8, "little")))
                elif wire_type == FIXED64:
                    fields.append((field_number, wire_type, data[offset:offset+8]))
                    offset += 8
                elif wire_type == LENGTH_DELIMITED:
                    length, offset = ProtobufParser.read_varint(data, offset)
                    if offset + length > len(data):
                        break
                    fields.append((field_number, wire_type, data[offset:offset+length]))
                    offset += length
                elif wire_type == FIXED32:
                    fields.append((field_number, wire_type, data[offset:offset+4]))
                    offset += 4
                else:
                    break  # Unknown wire type — stop parsing defensively
            except (IndexError, struct.error):
                break
        return fields

    @staticmethod
    def get_field_bytes(
        fields: List[Tuple[int, int, bytes]], field_num: int
    ) -> Optional[bytes]:
        """Get the first length-delimited field matching field_num."""
        for fn, wt, val in fields:
            if fn == field_num and wt == LENGTH_DELIMITED:
                return val
        return None

    @staticmethod
    def get_field_string(
        fields: List[Tuple[int, int, bytes]], field_num: int
    ) -> str:
        """Get a string field (UTF-8 decoded with error replacement)."""
        raw = ProtobufParser.get_field_bytes(fields, field_num)
        if raw:
            return raw.decode("utf-8", errors="replace")
        return ""

    @staticmethod
    def get_field_varint(
        fields: List[Tuple[int, int, bytes]], field_num: int
    ) -> int:
        """Get a varint field value."""
        for fn, wt, val in fields:
            if fn == field_num and wt == VARINT:
                return int.from_bytes(val[:8], "little")
        return 0

    @staticmethod
    def get_all_fields(
        fields: List[Tuple[int, int, bytes]], field_num: int
    ) -> List[bytes]:
        """Get all instances of a repeated length-delimited field."""
        return [val for fn, wt, val in fields if fn == field_num and wt == LENGTH_DELIMITED]

    @staticmethod
    def get_all_varints(
        fields: List[Tuple[int, int, bytes]], field_num: int
    ) -> List[int]:
        """Get all instances of a repeated varint field."""
        return [
            int.from_bytes(val[:8], "little")
            for fn, wt, val in fields
            if fn == field_num and wt == VARINT
        ]
