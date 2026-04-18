"""
Eresus Sentinel — FlatBuffer Wire Format Parser.

Zero-dependency parser for FlatBuffer binary format, used by TFLite models.
Provides table, string, vector, and scalar field reading with bounds checking.

FlatBuffer wire format:
  - Root table pointer at offset 4 (int32 LE, relative to start)
  - Each table has a vtable pointer at negative offset
  - VTable: [vtable_size, table_size, field_0_offset, field_1_offset, ...]
  - Strings: [length (int32), UTF-8 bytes]
  - Vectors: [length (int32), element_0, element_1, ...]
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple


class FlatBufferParser:
    """Zero-dependency FlatBuffer wire format parser with bounds checking."""

    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._size = len(buf)

    @property
    def buffer(self) -> bytes:
        return self._buf

    @property
    def size(self) -> int:
        return self._size

    def read_int32(self, offset: int) -> int:
        """Read a signed 32-bit integer at offset."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"int32 read out of bounds: offset={offset}, size={self._size}")
        return struct.unpack_from("<i", self._buf, offset)[0]

    def read_uint32(self, offset: int) -> int:
        """Read an unsigned 32-bit integer at offset."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"uint32 read out of bounds: offset={offset}, size={self._size}")
        return struct.unpack_from("<I", self._buf, offset)[0]

    def read_int16(self, offset: int) -> int:
        """Read a signed 16-bit integer at offset."""
        if offset < 0 or offset + 2 > self._size:
            raise ValueError(f"int16 read out of bounds: offset={offset}, size={self._size}")
        return struct.unpack_from("<h", self._buf, offset)[0]

    def read_uint16(self, offset: int) -> int:
        """Read an unsigned 16-bit integer at offset."""
        if offset < 0 or offset + 2 > self._size:
            raise ValueError(f"uint16 read out of bounds: offset={offset}, size={self._size}")
        return struct.unpack_from("<H", self._buf, offset)[0]

    def read_uint8(self, offset: int) -> int:
        """Read an unsigned 8-bit integer at offset."""
        if offset < 0 or offset + 1 > self._size:
            raise ValueError(f"uint8 read out of bounds: offset={offset}, size={self._size}")
        return self._buf[offset]

    def read_int64(self, offset: int) -> int:
        """Read a signed 64-bit integer at offset."""
        if offset < 0 or offset + 8 > self._size:
            raise ValueError(f"int64 read out of bounds: offset={offset}, size={self._size}")
        return struct.unpack_from("<q", self._buf, offset)[0]

    def root_table_offset(self) -> int:
        """Get the offset of the root table from the buffer start."""
        if self._size < 4:
            raise ValueError("Buffer too small for root table pointer")
        return self.read_uint32(0)

    def file_identifier(self) -> Optional[bytes]:
        """Read the 4-byte file identifier (at offset 4-8), if present."""
        if self._size >= 8:
            return self._buf[4:8]
        return None

    def read_vtable(self, table_offset: int) -> Tuple[int, int, List[int]]:
        """Read VTable for a table at given offset.

        Returns:
            (vtable_size, table_size, field_offsets)
        """
        if table_offset < 0 or table_offset + 4 > self._size:
            raise ValueError(f"Table offset out of bounds: {table_offset}")

        vtable_rel = self.read_int32(table_offset)
        vtable_offset = table_offset - vtable_rel

        if vtable_offset < 0 or vtable_offset + 4 > self._size:
            raise ValueError(f"VTable offset out of bounds: {vtable_offset}")

        vtable_size = self.read_uint16(vtable_offset)
        table_size = self.read_uint16(vtable_offset + 2)

        if vtable_size < 4 or vtable_offset + vtable_size > self._size:
            raise ValueError(
                f"VTable size invalid: vtable_size={vtable_size}, "
                f"vtable_offset={vtable_offset}, buf_size={self._size}"
            )

        num_fields = (vtable_size - 4) // 2
        field_offsets = []
        for i in range(num_fields):
            fo = self.read_uint16(vtable_offset + 4 + i * 2)
            field_offsets.append(fo)

        return vtable_size, table_size, field_offsets

    def read_field_offset(self, table_offset: int, field_index: int) -> Optional[int]:
        """Get the absolute offset of a field in a table, or None if absent."""
        _, _, field_offsets = self.read_vtable(table_offset)
        if field_index >= len(field_offsets):
            return None
        rel = field_offsets[field_index]
        if rel == 0:
            return None
        return table_offset + rel

    def read_string(self, offset: int) -> str:
        """Read a FlatBuffer string (int32 length + UTF-8 data) via indirect offset."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"String pointer out of bounds: {offset}")
        str_rel = self.read_uint32(offset)
        str_offset = offset + str_rel
        if str_offset + 4 > self._size:
            raise ValueError(f"String offset out of bounds: {str_offset}")
        length = self.read_uint32(str_offset)
        data_start = str_offset + 4
        if data_start + length > self._size:
            raise ValueError(f"String data out of bounds: start={data_start}, len={length}")
        return self._buf[data_start:data_start + length].decode("utf-8", errors="replace")

    def read_vector_length(self, offset: int) -> int:
        """Read the length of a vector via indirect offset."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"Vector pointer out of bounds: {offset}")
        vec_rel = self.read_uint32(offset)
        vec_offset = offset + vec_rel
        if vec_offset + 4 > self._size:
            raise ValueError(f"Vector offset out of bounds: {vec_offset}")
        return self.read_uint32(vec_offset)

    def read_vector_offsets(self, offset: int) -> List[int]:
        """Read a vector of table offsets (indirect references)."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"Vector pointer out of bounds: {offset}")
        vec_rel = self.read_uint32(offset)
        vec_offset = offset + vec_rel
        if vec_offset + 4 > self._size:
            raise ValueError(f"Vector offset out of bounds: {vec_offset}")

        length = self.read_uint32(vec_offset)
        data_start = vec_offset + 4

        offsets = []
        for i in range(length):
            elem_offset = data_start + i * 4
            if elem_offset + 4 > self._size:
                break
            rel = self.read_uint32(elem_offset)
            offsets.append(elem_offset + rel)
        return offsets

    def read_vector_scalars_int32(self, offset: int) -> List[int]:
        """Read a vector of int32 scalars."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"Vector pointer out of bounds: {offset}")
        vec_rel = self.read_uint32(offset)
        vec_offset = offset + vec_rel
        if vec_offset + 4 > self._size:
            raise ValueError(f"Vector offset out of bounds: {vec_offset}")

        length = self.read_uint32(vec_offset)
        data_start = vec_offset + 4
        values = []
        for i in range(length):
            val_offset = data_start + i * 4
            if val_offset + 4 > self._size:
                break
            values.append(self.read_int32(val_offset))
        return values

    def read_vector_scalars_uint8(self, offset: int) -> List[int]:
        """Read a vector of uint8 scalars."""
        if offset < 0 or offset + 4 > self._size:
            raise ValueError(f"Vector pointer out of bounds: {offset}")
        vec_rel = self.read_uint32(offset)
        vec_offset = offset + vec_rel
        if vec_offset + 4 > self._size:
            raise ValueError(f"Vector offset out of bounds: {vec_offset}")

        length = self.read_uint32(vec_offset)
        data_start = vec_offset + 4
        end = min(data_start + length, self._size)
        return list(self._buf[data_start:end])
