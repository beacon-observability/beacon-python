from __future__ import annotations

import os
import sys
import threading
import weakref
from dataclasses import dataclass

from .config import limit


@dataclass(frozen=True, slots=True)
class Mark:
    source_id: str
    node_id: int
    start: int
    end: int | None
    exact: bool = True
    unit: str = "unicode_code_point"


class ByteBudget:
    def __init__(self):
        self.maximum = limit(
            "beacon.security.max.process.tracked.bytes", 64 * 1024 * 1024
        )
        self.used = 0
        self.lock = threading.Lock()

    def reserve(self, size: int) -> bool:
        with self.lock:
            if self.used + size > self.maximum:
                return False
            self.used += size
            return True

    def release(self, size: int):
        with self.lock:
            self.used = max(0, self.used - size)


@dataclass(slots=True)
class Tracked:
    reference: object
    weak: bool
    size: int
    marks: tuple[Mark, ...]

    def value(self):
        return self.reference() if self.weak else self.reference


def reference(value, marks) -> Tracked | None:
    if type(value) in (str, bytes, bytearray):
        return Tracked(value, False, sys.getsizeof(value), tuple(marks))
    try:
        return Tracked(weakref.ref(value), True, 128, tuple(marks))
    except TypeError:
        # Only retain non-weak-referenceable carriers with a bounded, known shape.
        if (
            isinstance(value, tuple)
            and len(value) <= 16
            and all(type(v) in (str, bytes, int, type(None)) for v in value)
        ):
            return Tracked(
                value,
                False,
                sys.getsizeof(value) + sum(sys.getsizeof(v) for v in value),
                tuple(marks),
            )
        from pathlib import PurePath

        if isinstance(value, PurePath):
            return Tracked(
                value,
                False,
                sys.getsizeof(value) + sys.getsizeof(str(value)),
                tuple(marks),
            )
    return None


_constants: dict[int, object] = {}
_constants_size = 0
_constant_lock = threading.Lock()


def register_constants(code):
    import types

    global _constants_size
    with _constant_lock:
        pending = [code]
        while pending:
            current = pending.pop()
            for value in current.co_consts:
                if isinstance(value, types.CodeType):
                    pending.append(value)
                elif (
                    type(value) in (str, bytes) and id(value) not in _constants
                ):
                    size = sys.getsizeof(value)
                    if _constants_size + size <= 4 * 1024 * 1024:
                        _constants[id(value)] = value
                        _constants_size += size


def shared_scalar(value) -> bool:
    if type(value) not in (str, bytes):
        return False
    singleton = (
        not value
        or len(value) == 1
        and (type(value) is bytes or ord(value) < 256)
    )
    if singleton or _constants.get(id(value)) is value:
        return True
    check = getattr(sys, "_is_interned", None)
    return type(value) is str and check is not None and check(value)


def _after_fork():
    global _constant_lock
    _constant_lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
