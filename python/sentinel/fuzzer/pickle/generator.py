"""Structure-aware pickle stream generator with PVM simulation."""

from __future__ import annotations

import io
import random
import struct
from typing import Optional

from ..base import Generator
from .opcodes import OpcodeInfo, opcodes_for_protocol
from .pvm import PVMState, none_obj, tuple_obj
from .validation import can_emit
from .emitters import (
    emit_int, emit_float, emit_string, emit_bytes_op, emit_global,
    emit_stack_global, emit_inst, emit_memo_put, emit_memo_get,
    emit_ext, emit_persid,
)
from .stack_ops import process_stack_op


class PickleGenerator(Generator):
    """Generates valid pickle byte streams for fuzzing.

    Uses PVM stack simulation to ensure structural validity.
    Protocol 0-5 support, type-aware validation, GLOBAL+REDUCE chains.
    """

    def __init__(
        self,
        protocol: int = 4,
        min_opcodes: int = 10,
        max_opcodes: int = 200,
        allow_ext: bool = False,
        allow_persist: bool = False,
        allow_buffer: bool = False,
        unsafe_mutations: bool = False,
        mutation_rate: float = 0.0,
    ):
        self.protocol = max(0, min(5, protocol))
        self.min_opcodes = min_opcodes
        self.max_opcodes = max_opcodes
        self.allow_ext = allow_ext
        self.allow_persist = allow_persist
        self.allow_buffer = allow_buffer
        self.unsafe_mutations = unsafe_mutations
        self.mutation_rate = mutation_rate
        self._available = opcodes_for_protocol(self.protocol)

    def generate(self, seed: Optional[int] = None) -> bytes:
        rng = random.Random(seed)
        buf = io.BytesIO()
        state = PVMState()

        if self.protocol >= 2:
            buf.write(b"\x80")
            buf.write(bytes([self.protocol]))
            state.proto_emitted = True

        frame_pos = None
        if self.protocol >= 4 and rng.random() < 0.7:
            frame_pos = buf.tell()
            buf.write(b"\x00" * 9)

        target_ops = rng.randint(self.min_opcodes, self.max_opcodes)
        emitted = 0

        for _ in range(target_ops * 2):
            if emitted >= target_ops:
                break

            candidates = self._get_valid_opcodes(state, rng)
            if not candidates:
                candidates = self._safe_push_opcodes()
            if not candidates:
                break

            op = rng.choice(candidates)
            self._emit_and_process(buf, op, state, rng)
            emitted += 1

        self._cleanup_for_stop(buf, state)
        buf.write(b"\x2e")

        raw = buf.getvalue()
        if frame_pos is not None:
            return self._patch_frame(raw, frame_pos)
        return raw

    def generate_from_bytes(self, data: bytes) -> bytes:
        seed = int.from_bytes(data[:8].ljust(8, b"\x00"), "little")
        return self.generate(seed=seed)

    def _get_valid_opcodes(self, state: PVMState, rng: random.Random) -> list[OpcodeInfo]:
        return [op for op in self._available
                if can_emit(op, state, self.allow_ext,
                           self.allow_persist, self.allow_buffer,
                           self.unsafe_mutations)]

    def _safe_push_opcodes(self) -> list[OpcodeInfo]:
        safe = {
            "NONE", "NEWTRUE", "NEWFALSE", "EMPTY_TUPLE",
            "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET",
            "BININT1", "BININT2", "BININT",
            "SHORT_BINUNICODE", "BINUNICODE", "SHORT_BINSTRING",
            "BINSTRING", "SHORT_BINBYTES", "BINBYTES",
            "FLOAT", "INT", "LONG",
        }
        return [op for op in self._available
                if op.name in safe and op.available_in(self.protocol)]

    def _emit_and_process(self, buf: io.BytesIO, op: OpcodeInfo,
                          state: PVMState, rng: random.Random) -> None:
        name = op.name

        # Integer opcodes
        if name in ("INT", "LONG", "LONG1", "LONG4",
                     "BININT", "BININT1", "BININT2"):
            emit_int(buf, state, rng, self._available)
            return

        # Float opcodes
        if name in ("FLOAT", "BINFLOAT"):
            emit_float(buf, state, rng, op)
            return

        # String opcodes
        if name in ("STRING", "UNICODE", "SHORT_BINUNICODE",
                     "BINUNICODE", "BINUNICODE8"):
            emit_string(buf, op, state, rng)
            return

        # Bytes opcodes
        if name in ("BINSTRING", "SHORT_BINSTRING",
                     "SHORT_BINBYTES", "BINBYTES", "BINBYTES8",
                     "BYTEARRAY8"):
            emit_bytes_op(buf, op, state, rng)
            return

        # GLOBAL
        if name == "GLOBAL":
            emit_global(buf, state, rng)
            return

        # STACK_GLOBAL
        if name == "STACK_GLOBAL":
            emit_stack_global(buf, state)
            return

        # INST
        if name == "INST":
            emit_inst(buf, state, rng)
            return

        # Memo PUT/GET
        if name in ("PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"):
            emit_memo_put(buf, op, state)
            return
        if name in ("GET", "BINGET", "LONG_BINGET"):
            emit_memo_get(buf, op, state, rng)
            return

        # Extension opcodes
        if name in ("EXT1", "EXT2", "EXT4"):
            emit_ext(buf, op, state, rng)
            return

        # Persistent IDs
        if name in ("PERSID", "BINPERSID"):
            emit_persid(buf, op, state, rng)
            return

        # Simple opcodes (just byte, no args)
        buf.write(op.char)
        process_stack_op(name, state, rng)

    def _cleanup_for_stop(self, buf: io.BytesIO, state: PVMState) -> None:
        safety = 0
        while state.has_mark() and safety < 100:
            buf.write(b"\x74")
            items = state.pop_to_mark()
            state.push(tuple_obj(items))
            safety += 1

        safety = 0
        while state.depth > 1 and safety < 10000:
            safety += 1
            if self.protocol < 2:
                buf.write(b"\x30")
                state.pop()
            elif state.depth >= 3:
                buf.write(b"\x87")
                c, b, a = state.pop(), state.pop(), state.pop()
                state.push(tuple_obj([x for x in [a, b, c] if x]))
            elif state.depth == 2:
                buf.write(b"\x86")
                b, a = state.pop(), state.pop()
                state.push(tuple_obj([x for x in [a, b] if x]))
            else:
                break

        if state.depth == 0:
            buf.write(b"\x4e")
            state.push(none_obj())

        top = state.peek(0)
        if top and top.is_mark:
            state.pop()
            if state.depth == 0:
                buf.write(b"\x4e")
                state.push(none_obj())

    def _patch_frame(self, raw: bytes, frame_pos: int) -> bytes:
        ba = bytearray(raw)
        frame_body_start = frame_pos + 9
        frame_size = len(ba) - frame_body_start
        ba[frame_pos] = 0x95
        struct.pack_into("<Q", ba, frame_pos + 1, frame_size)
        return bytes(ba)
