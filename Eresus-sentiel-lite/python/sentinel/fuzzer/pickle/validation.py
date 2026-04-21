"""Type-aware opcode validation — can_emit() logic."""

from __future__ import annotations

from .opcodes import OpcodeInfo
from .pvm import PVMState


def can_emit(
    op: OpcodeInfo,
    state: PVMState,
    allow_ext: bool = False,
    allow_persist: bool = False,
    allow_buffer: bool = False,
    unsafe: bool = False,
) -> bool:
    """Check if opcode can be safely emitted in current PVM state."""
    name = op.name
    depth = state.depth

    if name in ("STOP", "PROTO", "FRAME"):
        return False

    if name in ("EXT1", "EXT2", "EXT4") and not allow_ext:
        return False
    if name in ("PERSID", "BINPERSID") and not allow_persist:
        return False
    if name in ("NEXT_BUFFER", "READONLY_BUFFER") and not allow_buffer:
        return False

    # Stack manipulation
    if name == "POP":
        return depth >= 1
    if name == "DUP":
        if depth < 1:
            return False
        top = state.peek(0)
        return top is not None and not top.is_mark
    if name == "POP_MARK":
        return state.has_mark()

    # Value-producing (always valid)
    if name in (
        "NONE", "NEWTRUE", "NEWFALSE",
        "INT", "LONG", "LONG1", "LONG4",
        "BININT", "BININT1", "BININT2",
        "FLOAT", "BINFLOAT",
        "STRING", "BINSTRING", "SHORT_BINSTRING",
        "UNICODE", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
        "SHORT_BINBYTES", "BINBYTES", "BINBYTES8",
        "BYTEARRAY8",
        "EMPTY_LIST", "EMPTY_DICT", "EMPTY_TUPLE", "EMPTY_SET",
        "MARK", "GLOBAL",
    ):
        return True

    # STACK_GLOBAL — needs 2 strings
    if name == "STACK_GLOBAL":
        if unsafe:
            return depth >= 2
        return depth >= 2 and state.is_string_at(0) and state.is_string_at(1)

    # List ops
    if name == "APPEND":
        if depth < 2:
            return False
        top = state.peek(0)
        return state.is_list_at(1) and top is not None and not top.is_mark
    if name == "APPENDS":
        if not state.has_mark():
            return False
        count = state.count_items_above_mark()
        return state.is_list_at_mark() and count is not None and count > 0

    # Dict ops
    if name == "SETITEM":
        return depth >= 3 and state.is_dict_at(2)
    if name == "SETITEMS":
        if not state.has_mark():
            return False
        count = state.count_items_above_mark()
        return (state.is_dict_at_mark() and count is not None
                and count > 0 and count % 2 == 0)

    # Set ops
    if name == "ADDITEMS":
        if not state.has_mark():
            return False
        count = state.count_items_above_mark()
        return state.is_set_at_mark() and count is not None and count > 0

    # MARK-consuming constructors
    if name in ("TUPLE", "LIST", "FROZENSET"):
        return state.has_mark()
    if name == "DICT":
        if not state.has_mark():
            return False
        count = state.count_items_above_mark()
        return count is not None and count % 2 == 0

    # Tuple shortcuts
    if name == "TUPLE1":
        return depth >= 1 and not state.has_mark_in_top(1)
    if name == "TUPLE2":
        return depth >= 2 and not state.has_mark_in_top(2)
    if name == "TUPLE3":
        return depth >= 3 and not state.has_mark_in_top(3)

    # Object construction
    if name == "REDUCE":
        return (depth >= 2 and state.is_callable_at(1) and state.is_tuple_at(0))
    if name == "NEWOBJ":
        return (depth >= 2 and state.is_callable_at(1) and state.is_tuple_at(0))
    if name == "NEWOBJ_EX":
        return (depth >= 3 and state.is_callable_at(2)
                and state.is_tuple_at(1) and state.is_dict_at(0))
    if name == "BUILD":
        return (depth >= 2 and state.is_instance_at(1)
                and (state.is_tuple_at(0) or state.is_dict_at(0)))
    if name == "INST":
        count = state.count_items_above_mark()
        return state.has_mark() and count is not None and count > 0
    if name == "OBJ":
        return state.has_mark() and state.is_callable_above_mark()

    # Memo ops
    if name in ("GET", "BINGET", "LONG_BINGET"):
        return len(state.memo) > 0
    if name in ("PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"):
        if depth < 1:
            return False
        top = state.peek(0)
        return top is not None and not top.is_mark

    # Buffer ops
    if name == "READONLY_BUFFER":
        return allow_buffer and state.is_bytes_at(0)
    if name == "NEXT_BUFFER":
        return allow_buffer

    # Persistent IDs
    if name == "BINPERSID":
        return allow_persist and depth >= 1

    return False
