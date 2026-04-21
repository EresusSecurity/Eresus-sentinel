"""Pickle Virtual Machine (PVM) stack simulation."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


class StackType(enum.Enum):
    """Types of objects on the PVM stack."""
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    NONE = "none"
    STRING = "string"
    BYTES = "bytes"
    BYTEARRAY = "bytearray"
    LIST = "list"
    TUPLE = "tuple"
    DICT = "dict"
    SET = "set"
    FROZENSET = "frozenset"
    MARK = "mark"
    GLOBAL = "global"
    CALLABLE = "callable"
    INSTANCE = "instance"
    EXTENSION = "extension"
    ANY = "any"


@dataclass
class StackObject:
    """A typed value on the PVM stack.

    Tracks the type and optional metadata (module/name for globals,
    children for containers) to enable type-aware opcode validation.
    """
    type: StackType
    # Value for scalars (int/float/bool/string/bytes)
    value: Any = None
    # For GLOBAL: (module, name)
    module: str = ""
    name: str = ""
    # For containers: list of child StackObjects
    children: list[StackObject] = field(default_factory=list)
    # For INSTANCE: the callable and args
    callable_ref: Optional[StackObject] = None
    args_ref: Optional[StackObject] = None

    @property
    def is_mark(self) -> bool:
        return self.type == StackType.MARK

    @property
    def is_list(self) -> bool:
        return self.type == StackType.LIST

    @property
    def is_dict(self) -> bool:
        return self.type == StackType.DICT

    @property
    def is_tuple(self) -> bool:
        return self.type == StackType.TUPLE

    @property
    def is_set(self) -> bool:
        return self.type == StackType.SET

    @property
    def is_string(self) -> bool:
        return self.type == StackType.STRING

    @property
    def is_bytes(self) -> bool:
        return self.type in (StackType.BYTES, StackType.BYTEARRAY)

    @property
    def is_callable(self) -> bool:
        return self.type in (StackType.CALLABLE, StackType.GLOBAL)

    @property
    def is_instance(self) -> bool:
        return self.type == StackType.INSTANCE

    @property
    def is_numeric(self) -> bool:
        return self.type in (StackType.INT, StackType.FLOAT, StackType.BOOL)

    def __repr__(self) -> str:
        if self.type == StackType.MARK:
            return "MARK"
        elif self.type == StackType.GLOBAL:
            return f"Global({self.module}.{self.name})"
        elif self.type == StackType.CALLABLE:
            return f"Callable({self.module}.{self.name})"
        elif self.type == StackType.INSTANCE:
            return f"Instance({self.callable_ref})"
        elif self.type in (StackType.LIST, StackType.TUPLE, StackType.DICT,
                           StackType.SET, StackType.FROZENSET):
            return f"{self.type.value}[{len(self.children)}]"
        else:
            return f"{self.type.value}({self.value!r})"


# ── Factory helpers ──────────────────────────────────────────────────

def mark() -> StackObject:
    return StackObject(type=StackType.MARK)

def none_obj() -> StackObject:
    return StackObject(type=StackType.NONE)

def bool_obj(val: bool) -> StackObject:
    return StackObject(type=StackType.BOOL, value=val)

def int_obj(val: int = 0) -> StackObject:
    return StackObject(type=StackType.INT, value=val)

def float_obj(val: float = 0.0) -> StackObject:
    return StackObject(type=StackType.FLOAT, value=val)

def string_obj(val: str = "") -> StackObject:
    return StackObject(type=StackType.STRING, value=val)

def bytes_obj(val: bytes = b"") -> StackObject:
    return StackObject(type=StackType.BYTES, value=val)

def bytearray_obj(val: bytes = b"") -> StackObject:
    return StackObject(type=StackType.BYTEARRAY, value=val)

def list_obj(children: list[StackObject] | None = None) -> StackObject:
    return StackObject(type=StackType.LIST, children=children or [])

def tuple_obj(children: list[StackObject] | None = None) -> StackObject:
    return StackObject(type=StackType.TUPLE, children=children or [])

def dict_obj() -> StackObject:
    return StackObject(type=StackType.DICT, children=[])

def set_obj() -> StackObject:
    return StackObject(type=StackType.SET, children=[])

def frozenset_obj(children: list[StackObject] | None = None) -> StackObject:
    return StackObject(type=StackType.FROZENSET, children=children or [])

def global_obj(module: str, name: str) -> StackObject:
    return StackObject(type=StackType.GLOBAL, module=module, name=name)

def callable_obj(module: str, name: str) -> StackObject:
    return StackObject(type=StackType.CALLABLE, module=module, name=name)

def instance_obj(callable_ref: StackObject, args_ref: StackObject) -> StackObject:
    return StackObject(
        type=StackType.INSTANCE,
        callable_ref=callable_ref,
        args_ref=args_ref,
    )

def extension_obj() -> StackObject:
    return StackObject(type=StackType.EXTENSION)

def any_obj() -> StackObject:
    return StackObject(type=StackType.ANY)


# ── PVM State ────────────────────────────────────────────────────────

class PVMState:
    """Full state of the pickle virtual machine.

    Tracks:
      - stack: list of StackObjects  (the main data stack)
      - memo:  dict[int, StackObject] (memo table for PUT/GET)
      - mark_positions: list of stack indices where MARKs are
      - proto_emitted: whether PROTO opcode has been written
    """

    def __init__(self) -> None:
        self.stack: list[StackObject] = []
        self.memo: dict[int, StackObject] = {}
        self.memo_counter: int = 0
        self.proto_emitted: bool = False

    def reset(self) -> None:
        self.stack.clear()
        self.memo.clear()
        self.memo_counter = 0
        self.proto_emitted = False

    def clone(self) -> PVMState:
        """Shallow clone for snapshot/rollback."""
        s = PVMState()
        s.stack = list(self.stack)
        s.memo = dict(self.memo)
        s.memo_counter = self.memo_counter
        s.proto_emitted = self.proto_emitted
        return s

    # ── Stack operations ─────────────────────────────────────────

    def push(self, obj: StackObject) -> None:
        self.stack.append(obj)

    def pop(self) -> Optional[StackObject]:
        if self.stack:
            return self.stack.pop()
        return None

    def peek(self, depth: int = 0) -> Optional[StackObject]:
        """Peek at stack position from the top (0 = TOS)."""
        idx = len(self.stack) - 1 - depth
        if 0 <= idx < len(self.stack):
            return self.stack[idx]
        return None

    @property
    def depth(self) -> int:
        return len(self.stack)

    # ── Mark operations ──────────────────────────────────────────

    def has_mark(self) -> bool:
        """Check if any MARK exists on the stack."""
        return any(obj.is_mark for obj in self.stack)

    def find_mark(self) -> Optional[int]:
        """Find the index of the topmost MARK (searching from top)."""
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].is_mark:
                return i
        return None

    def count_items_above_mark(self) -> Optional[int]:
        """Count items between the topmost MARK and TOS."""
        mark_idx = self.find_mark()
        if mark_idx is None:
            return None
        return len(self.stack) - 1 - mark_idx

    def pop_to_mark(self) -> list[StackObject]:
        """Pop items until MARK (inclusive). Returns items above mark."""
        items = []
        while self.stack:
            obj = self.stack.pop()
            if obj.is_mark:
                break
            items.append(obj)
        items.reverse()
        return items

    def has_mark_in_top(self, n: int) -> bool:
        """Check if any of the top N items is a MARK."""
        for i in range(min(n, len(self.stack))):
            if self.stack[-(i + 1)].is_mark:
                return True
        return False

    # ── Type queries ─────────────────────────────────────────────

    def is_type_at(self, depth: int, type_check) -> bool:
        """Check if the item at depth from TOS satisfies a type check."""
        obj = self.peek(depth)
        if obj is None:
            return False
        return type_check(obj)

    def is_list_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_list)

    def is_dict_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_dict)

    def is_tuple_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_tuple)

    def is_set_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_set)

    def is_string_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_string)

    def is_callable_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_callable)

    def is_instance_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_instance)

    def is_bytes_at(self, depth: int) -> bool:
        return self.is_type_at(depth, lambda o: o.is_bytes)

    def is_list_at_mark(self) -> bool:
        """Check if the item just below the topmost MARK is a list."""
        mark_idx = self.find_mark()
        if mark_idx is None or mark_idx == 0:
            return False
        return self.stack[mark_idx - 1].is_list

    def is_dict_at_mark(self) -> bool:
        """Check if the item just below the topmost MARK is a dict."""
        mark_idx = self.find_mark()
        if mark_idx is None or mark_idx == 0:
            return False
        return self.stack[mark_idx - 1].is_dict

    def is_set_at_mark(self) -> bool:
        """Check if the item just below the topmost MARK is a set."""
        mark_idx = self.find_mark()
        if mark_idx is None or mark_idx == 0:
            return False
        return self.stack[mark_idx - 1].is_set

    def is_callable_above_mark(self) -> bool:
        """Check if the first item above MARK is callable (for OBJ)."""
        mark_idx = self.find_mark()
        if mark_idx is None or mark_idx >= len(self.stack) - 1:
            return False
        return self.stack[mark_idx + 1].is_callable

    # ── Memo operations ──────────────────────────────────────────

    def memo_put(self, index: int, obj: StackObject) -> None:
        self.memo[index] = obj

    def memo_get(self, index: int) -> Optional[StackObject]:
        return self.memo.get(index)

    def memo_put_next(self, obj: StackObject) -> int:
        """Store in memo at next available slot. Returns the index used."""
        idx = self.memo_counter
        self.memo[idx] = obj
        self.memo_counter += 1
        return idx
