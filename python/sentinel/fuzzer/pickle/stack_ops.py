"""PVM stack operations — process simple opcodes.

Updates PVMState for opcodes that don't need argument encoding.
"""

from __future__ import annotations

import random

from .pvm import (
    PVMState,
    any_obj,
    bool_obj,
    bytes_obj,
    dict_obj,
    frozenset_obj,
    instance_obj,
    list_obj,
    mark,
    none_obj,
    set_obj,
    tuple_obj,
)


def process_stack_op(name: str, state: PVMState, rng: random.Random) -> None:
    """Update PVM state for a simple (no-arg) opcode."""

    if name == "POP":
        state.pop()
    elif name == "DUP":
        top = state.peek(0)
        if top and not top.is_mark:
            state.push(top)
    elif name == "MARK":
        state.push(mark())
    elif name == "POP_MARK":
        state.pop_to_mark()
    elif name == "EMPTY_LIST":
        state.push(list_obj())
    elif name == "EMPTY_DICT":
        state.push(dict_obj())
    elif name == "EMPTY_TUPLE":
        state.push(tuple_obj())
    elif name == "EMPTY_SET":
        state.push(set_obj())
    elif name == "NONE":
        state.push(none_obj())
    elif name == "NEWTRUE":
        state.push(bool_obj(True))
    elif name == "NEWFALSE":
        state.push(bool_obj(False))
    elif name == "APPEND":
        item = state.pop()
        top = state.peek(0)
        if top and top.is_list and item:
            top.children.append(item)
    elif name == "APPENDS":
        items = state.pop_to_mark()
        top = state.peek(0)
        if top and top.is_list:
            top.children.extend(items)
    elif name == "SETITEM":
        val = state.pop()
        key = state.pop()
        top = state.peek(0)
        if top and top.is_dict and key and val:
            top.children.extend([key, val])
    elif name == "SETITEMS":
        items = state.pop_to_mark()
        top = state.peek(0)
        if top and top.is_dict:
            top.children.extend(items)
    elif name == "ADDITEMS":
        items = state.pop_to_mark()
        top = state.peek(0)
        if top and top.is_set:
            top.children.extend(items)
    elif name == "LIST":
        items = state.pop_to_mark()
        state.push(list_obj(items))
    elif name == "TUPLE":
        items = state.pop_to_mark()
        state.push(tuple_obj(items))
    elif name == "DICT":
        items = state.pop_to_mark()
        d = dict_obj()
        d.children = items
        state.push(d)
    elif name == "FROZENSET":
        items = state.pop_to_mark()
        state.push(frozenset_obj(items))
    elif name == "TUPLE1":
        a = state.pop()
        state.push(tuple_obj([a] if a else []))
    elif name == "TUPLE2":
        b = state.pop()
        a = state.pop()
        state.push(tuple_obj([x for x in [a, b] if x]))
    elif name == "TUPLE3":
        c = state.pop()
        b = state.pop()
        a = state.pop()
        state.push(tuple_obj([x for x in [a, b, c] if x]))
    elif name == "REDUCE":
        args = state.pop()
        cbl = state.pop()
        state.push(instance_obj(cbl, args) if cbl and args else any_obj())
    elif name == "NEWOBJ":
        args = state.pop()
        cls = state.pop()
        state.push(instance_obj(cls, args) if cls and args else any_obj())
    elif name == "NEWOBJ_EX":
        state.pop()  # kwargs
        args = state.pop()
        cls = state.pop()
        state.push(instance_obj(cls, args) if cls and args else any_obj())
    elif name == "BUILD":
        new_state = state.pop()
        top = state.peek(0)
        if top and top.is_instance and new_state:
            top.args_ref = new_state
    elif name == "OBJ":
        items = state.pop_to_mark()
        if items:
            state.push(instance_obj(items[0], tuple_obj(items[1:])))
        else:
            state.push(any_obj())
    elif name == "NEXT_BUFFER":
        state.push(bytes_obj())
    elif name == "READONLY_BUFFER":
        state.pop()
        state.push(bytes_obj())
