from __future__ import annotations

import sys
from _thread import allocate_lock
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import fields
from functools import lru_cache
from os import environ
from typing import Iterator

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedAttribute,
    CapturedFrame,
    CapturedSample,
)

_INTERNAL = ContextVar("beacon_profiling_internal_work", default=False)
_FIELD_NAMES = {
    cls: tuple(field.name for field in fields(cls))
    for cls in (CapturedSample, CapturedAttribute)
}


@lru_cache(maxsize=4096)
def _frame_size(frame: CapturedFrame) -> int:
    return (
        sys.getsizeof(frame)
        + sys.getsizeof(frame.function)
        + sys.getsizeof(frame.filename)
        + sys.getsizeof(frame.lineno)
    )


def internal_work() -> bool:
    return _INTERNAL.get()


@contextmanager
def suppress_collection() -> Iterator[None]:
    token = _INTERNAL.set(True)
    try:
        yield
    finally:
        _INTERNAL.reset(token)


def _sample_size(sample: CapturedSample, limit: int) -> int:
    # Charge shared frame/string references conservatively per sample. The
    # budget bounds producer-owned raw data, not application heap snapshots
    # or temporary serialized messages. Never invoke user __sizeof__ hooks.
    pending: list[object] = [sample]
    seen: set[int] = set()
    total = 96  # Buffer entry and accounting overhead.
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if len(seen) > 4096:
            return limit + 1
        cls = type(value)
        if cls is CapturedFrame:
            if (
                type(value.function) is not str
                or type(value.filename) is not str
                or type(value.lineno) is not int
            ):
                return limit + 1
            if len(value.function) <= 512 and len(value.filename) <= 2048:
                total += _frame_size(value)
            else:
                total += sum(
                    sys.getsizeof(item)
                    for item in (
                        value,
                        value.function,
                        value.filename,
                        value.lineno,
                    )
                )
            if total > limit:
                return total
            continue
        if cls is CapturedSample or cls is CapturedAttribute:
            pending.extend(getattr(value, name) for name in _FIELD_NAMES[cls])
        elif cls is tuple or cls is list:
            if len(value) > 4096:
                return limit + 1
            pending.extend(value)
        elif cls is dict:
            if len(value) > 2048:
                return limit + 1
            pending.extend(value.keys())
            pending.extend(value.values())
        elif not any(
            cls is scalar
            for scalar in (str, bytes, bytearray, int, float, bool, type(None))
        ):
            return limit + 1
        total += sys.getsizeof(value)
        if total > limit:
            return total
    return total


class SampleBudget:
    def __init__(
        self, max_samples: int | None = None, max_bytes: int | None = None
    ) -> None:
        self.max_samples = (
            max_samples
            if max_samples is not None
            else int(environ.get("OTEL_PROFILING_MAX_BUFFER_SAMPLES", "10000"))
        )
        self.max_bytes = (
            max_bytes
            if max_bytes is not None
            else int(
                environ.get(
                    "OTEL_PROFILING_MAX_BUFFER_BYTES", str(8 * 1024 * 1024)
                )
            )
        )
        if self.max_samples < 1 or self.max_bytes < 1:
            raise ValueError("profile buffer limits must be positive")
        self.reset_after_fork()

    def reset_after_fork(self) -> None:
        self._lock = allocate_lock()
        self.generation = getattr(self, "generation", 0) + 1
        self._used_samples = 0
        self._used_bytes = 0
        self._dropped_samples = 0

    def reserve(self, sample: CapturedSample, generation: int) -> int | None:
        size = _sample_size(sample, self.max_bytes)
        with self._lock:
            if (
                generation != self.generation
                or self._used_samples >= self.max_samples
                or self._used_bytes + size > self.max_bytes
            ):
                self._dropped_samples += 1
                return None
            self._used_samples += 1
            self._used_bytes += size
            return size

    def release(self, count: int, size: int, generation: int) -> None:
        with self._lock:
            if generation != self.generation:
                return
            self._used_samples -= count
            self._used_bytes -= size

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "max_samples": self.max_samples,
                "max_bytes": self.max_bytes,
                "used_samples": self._used_samples,
                "used_bytes": self._used_bytes,
                "dropped_samples": self._dropped_samples,
            }


class SampleBuffer:
    """Caller-locked buffer sharing a single profiler-wide raw-data budget."""

    def __init__(self, budget: SampleBudget) -> None:
        self._budget = budget
        self._generation = budget.generation
        self._items: list[tuple[CapturedSample, int]] = []

    def __len__(self) -> int:
        return len(self._items)

    def append(self, sample: CapturedSample) -> None:
        size = self._budget.reserve(sample, self._generation)
        if size is not None:
            try:
                self._items.append((sample, size))
            except BaseException:
                self._budget.release(1, size, self._generation)
                raise

    def extend(self, samples: list[CapturedSample]) -> None:
        for sample in samples:
            self.append(sample)

    def drain(self) -> list[CapturedSample]:
        result = [sample for sample, _ in self._items]
        self.clear()
        return result

    def clear(self) -> None:
        items, self._items = self._items, []
        self._budget.release(
            len(items), sum(size for _, size in items), self._generation
        )

    def __enter__(self) -> SampleBuffer:
        return self

    def __exit__(self, *_: object) -> None:
        self.clear()
