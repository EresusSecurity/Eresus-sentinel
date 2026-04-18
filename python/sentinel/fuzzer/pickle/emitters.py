"""Opcode emission helpers — encode opcodes + arguments into bytes.

Each emit_* function writes opcode bytes to buffer and updates PVM state.
"""

from __future__ import annotations

import io
import random
import struct

from .opcodes import OpcodeInfo
from .pvm import (
    PVMState, StackType,
    none_obj, bool_obj, int_obj, float_obj, string_obj, bytes_obj,
    bytearray_obj, list_obj, tuple_obj, dict_obj, set_obj, frozenset_obj,
    callable_obj, instance_obj, any_obj, mark,
)
from .stdlib_globals import get_random_global


def emit_int(buf: io.BytesIO, state: PVMState, rng: random.Random,
             available: list[OpcodeInfo]) -> None:
    int_ops = [op for op in available
               if op.name in ("INT", "LONG", "LONG1", "LONG4",
                               "BININT", "BININT1", "BININT2")]
    if not int_ops:
        buf.write(b"\x4e")
        state.push(none_obj())
        return

    op = rng.choice(int_ops)
    val = rng.randint(-2**31, 2**31 - 1)

    if op.name == "INT":
        buf.write(b"\x49")
        buf.write(f"{val}\n".encode())
    elif op.name == "LONG":
        buf.write(b"\x4c")
        buf.write(f"{val}L\n".encode())
    elif op.name == "LONG1":
        buf.write(b"\x8a")
        ib = val.to_bytes(4, "little", signed=True)
        buf.write(struct.pack("<B", len(ib)))
        buf.write(ib)
    elif op.name == "LONG4":
        buf.write(b"\x8b")
        ib = val.to_bytes(4, "little", signed=True)
        buf.write(struct.pack("<I", len(ib)))
        buf.write(ib)
    elif op.name == "BININT":
        buf.write(b"\x4a")
        buf.write(struct.pack("<i", val))
    elif op.name == "BININT1":
        buf.write(b"\x4b")
        buf.write(struct.pack("<B", val & 0xFF))
    elif op.name == "BININT2":
        buf.write(b"\x4d")
        buf.write(struct.pack("<H", val & 0xFFFF))

    state.push(int_obj(val))


def emit_float(buf: io.BytesIO, state: PVMState, rng: random.Random,
               op: OpcodeInfo) -> None:
    val = rng.uniform(-1e6, 1e6)
    if op.name == "FLOAT":
        buf.write(b"\x46")
        buf.write(f"{val}\n".encode())
    else:  # BINFLOAT
        buf.write(b"\x47")
        buf.write(struct.pack(">d", val))
    state.push(float_obj(val))


def emit_string(buf: io.BytesIO, op: OpcodeInfo, state: PVMState,
                rng: random.Random) -> None:
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    length = rng.randint(1, 32)
    s = "".join(rng.choice(charset) for _ in range(length))

    if op.name == "STRING":
        escaped = (s.replace("\\", "\\\\").replace("'", "\\'")
                    .replace("\n", "\\n").replace("\r", "\\r")
                    .replace("\t", "\\t"))
        buf.write(b"\x53")
        buf.write(f"'{escaped}'\n".encode())
    elif op.name == "UNICODE":
        buf.write(b"\x56")
        buf.write(f"{s}\n".encode())
    elif op.name == "SHORT_BINUNICODE":
        encoded = s.encode("utf-8")
        if len(encoded) < 256:
            buf.write(b"\x8c")
            buf.write(struct.pack("<B", len(encoded)))
            buf.write(encoded)
    elif op.name == "BINUNICODE":
        encoded = s.encode("utf-8")
        buf.write(b"\x58")
        buf.write(struct.pack("<I", len(encoded)))
        buf.write(encoded)
    elif op.name == "BINUNICODE8":
        encoded = s.encode("utf-8")
        buf.write(b"\x8d")
        buf.write(struct.pack("<Q", len(encoded)))
        buf.write(encoded)

    state.push(string_obj(s))


def emit_bytes_op(buf: io.BytesIO, op: OpcodeInfo, state: PVMState,
                  rng: random.Random) -> None:
    length = rng.randint(0, 32)
    data = bytes(rng.randint(0, 255) for _ in range(length))

    if op.name == "BINSTRING":
        buf.write(b"\x54")
        buf.write(struct.pack("<i", len(data)))
        buf.write(data)
        state.push(bytes_obj(data))
    elif op.name == "SHORT_BINSTRING":
        if len(data) < 256:
            buf.write(b"\x55")
            buf.write(struct.pack("<B", len(data)))
            buf.write(data)
            state.push(bytes_obj(data))
    elif op.name == "SHORT_BINBYTES":
        if len(data) < 256:
            buf.write(b"\x43")
            buf.write(struct.pack("<B", len(data)))
            buf.write(data)
            state.push(bytes_obj(data))
    elif op.name == "BINBYTES":
        buf.write(b"\x42")
        buf.write(struct.pack("<I", len(data)))
        buf.write(data)
        state.push(bytes_obj(data))
    elif op.name == "BINBYTES8":
        buf.write(b"\x8e")
        buf.write(struct.pack("<Q", len(data)))
        buf.write(data)
        state.push(bytes_obj(data))
    elif op.name == "BYTEARRAY8":
        buf.write(b"\x96")
        buf.write(struct.pack("<Q", len(data)))
        buf.write(data)
        state.push(bytearray_obj(data))


def emit_global(buf: io.BytesIO, state: PVMState, rng: random.Random) -> None:
    mod, attr = get_random_global(rng)
    buf.write(b"\x63")
    buf.write(f"{mod}\n{attr}\n".encode())
    state.push(callable_obj(mod, attr))


def emit_stack_global(buf: io.BytesIO, state: PVMState) -> None:
    buf.write(b"\x93")
    attr = state.pop()
    module = state.pop()
    if attr and module and attr.is_string and module.is_string:
        state.push(callable_obj(str(module.value or ""), str(attr.value or "")))
    else:
        state.push(callable_obj("builtins", "object"))


def emit_inst(buf: io.BytesIO, state: PVMState, rng: random.Random) -> None:
    mod, attr = get_random_global(rng)
    buf.write(b"\x69")
    buf.write(f"{mod}\n{attr}\n".encode())
    items = state.pop_to_mark()
    cbl = callable_obj(mod, attr)
    args = tuple_obj(items)
    state.push(instance_obj(cbl, args))


def emit_memo_put(buf: io.BytesIO, op: OpcodeInfo, state: PVMState) -> None:
    top = state.peek(0)
    if not top or top.is_mark:
        return

    if op.name == "PUT":
        idx = state.memo_counter
        buf.write(b"\x70")
        buf.write(f"{idx}\n".encode())
        state.memo_put(idx, top)
        state.memo_counter += 1
    elif op.name == "BINPUT":
        idx = state.memo_counter % 256
        buf.write(b"\x71")
        buf.write(struct.pack("<B", idx))
        state.memo_put(idx, top)
        state.memo_counter += 1
    elif op.name == "LONG_BINPUT":
        idx = state.memo_counter
        buf.write(b"\x72")
        buf.write(struct.pack("<I", idx))
        state.memo_put(idx, top)
        state.memo_counter += 1
    elif op.name == "MEMOIZE":
        buf.write(b"\x94")
        state.memo_put_next(top)


def emit_memo_get(buf: io.BytesIO, op: OpcodeInfo, state: PVMState,
                  rng: random.Random) -> None:
    if not state.memo:
        state.push(none_obj())
        return

    keys = sorted(state.memo.keys())
    idx = rng.choice(keys)

    if op.name == "GET":
        buf.write(b"\x67")
        buf.write(f"{idx}\n".encode())
    elif op.name == "BINGET":
        idx = min(255, idx)
        buf.write(b"\x68")
        buf.write(struct.pack("<B", idx))
    elif op.name == "LONG_BINGET":
        buf.write(b"\x6a")
        buf.write(struct.pack("<I", idx))

    obj = state.memo_get(idx)
    state.push(obj if obj else any_obj())


def emit_ext(buf: io.BytesIO, op: OpcodeInfo, state: PVMState,
             rng: random.Random) -> None:
    if op.name == "EXT1":
        buf.write(b"\x82")
        buf.write(struct.pack("<B", rng.randint(1, 255)))
    elif op.name == "EXT2":
        buf.write(b"\x83")
        buf.write(struct.pack("<H", rng.randint(1, 65535)))
    elif op.name == "EXT4":
        buf.write(b"\x84")
        buf.write(struct.pack("<i", max(1, rng.randint(1, 2**31 - 1))))
    state.push(callable_obj("builtins", "object"))


def emit_persid(buf: io.BytesIO, op: OpcodeInfo, state: PVMState,
                rng: random.Random) -> None:
    if op.name == "PERSID":
        pid = f"pid_{rng.randint(0, 999999)}\n"
        buf.write(b"\x50")
        buf.write(pid.encode())
        state.push(string_obj(pid.strip()))
    elif op.name == "BINPERSID":
        buf.write(b"\x51")
        state.pop()
        state.push(string_obj("persistent_object"))
