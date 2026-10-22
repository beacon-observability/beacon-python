# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import asyncio
import asyncio.locks
import os
import sys
import threading
from time import monotonic_ns, time_ns
from types import FrameType, ModuleType
from typing import Any, Callable

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedAttribute,
    CapturedFrame,
    CapturedSample,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.trace import INVALID_SPAN_CONTEXT

_LOCK_ACQUIRE_SAMPLE_TYPE = "lock.acquire.duration"
_LOCK_HOLD_SAMPLE_TYPE = "lock.hold.duration"
_LOCK_WAIT_SAMPLE_TYPE = "lock.wait.duration"
_FACTORY_PATCH_MODE = "factory"
_SYNC_CLASS_PATCH_MODE = "sync_class"
_ASYNC_CLASS_PATCH_MODE = "async_class"
_COLLECTOR_FILE = os.path.normpath(os.path.realpath(__file__))
_THREADING_MODULE_FILE = getattr(threading, "__file__", None)
_ASYNCIO_LOCKS_MODULE_FILE = getattr(asyncio.locks, "__file__", None)


class _ProfiledPrimitiveState:
    __slots__ = (
        "acquired_time_ns",
        "collector",
        "init_location",
        "is_internal",
        "lock_kind",
    )

    def __init__(
        self,
        collector: "_PrimitiveCollector",
        *,
        lock_kind: str,
        is_internal: bool,
    ) -> None:
        self.acquired_time_ns: int | None = None
        self.collector = collector
        self.init_location = _resolve_init_location()
        self.is_internal = is_internal
        self.lock_kind = lock_kind


class _ProfiledPrimitiveProxy:
    __slots__ = ("_state", "_wrapped")

    def __init__(
        self,
        wrapped: Any,
        collector: "_PrimitiveCollector",
        *,
        lock_kind: str,
        is_internal: bool,
    ) -> None:
        self._wrapped = wrapped
        self._state = _ProfiledPrimitiveState(
            collector,
            lock_kind=lock_kind,
            is_internal=is_internal,
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _ProfiledPrimitiveProxy):
            return self._wrapped == other._wrapped
        return self._wrapped == other

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)

    def __hash__(self) -> int:
        return hash(self._wrapped)

    def __repr__(self) -> str:
        return (
            f"<_ProfiledPrimitiveProxy({self._wrapped!r}) "
            f"at {self._state.init_location}>"
        )

    def locked(self) -> bool:
        return bool(getattr(self._wrapped, "locked")())

    def acquire(self, *args: Any, **kwargs: Any) -> Any:
        return _acquire_sync_primitive(
            self._state, self._wrapped.acquire, *args, **kwargs
        )

    def __enter__(self, *args: Any, **kwargs: Any) -> Any:
        return _acquire_sync_primitive(
            self._state, self._wrapped.__enter__, *args, **kwargs
        )

    def release(self, *args: Any, **kwargs: Any) -> Any:
        return _release_sync_primitive(
            self._state, self._wrapped.release, *args, **kwargs
        )

    def __exit__(self, *args: Any, **kwargs: Any) -> Any:
        return _release_sync_primitive(
            self._state, self._wrapped.__exit__, *args, **kwargs
        )


class _PrimitiveCollector:
    PATCHED_LOCK_NAME = ""
    LOCK_KIND = ""
    PATCH_MODE = _FACTORY_PATCH_MODE
    TARGET_MODULES: tuple[ModuleType, ...] = ()
    INTERNAL_MODULE_FILE: str | None = None

    def __init__(
        self,
        context_bridge: ContextBridge,
        *,
        max_frames: int = 64,
        include_trace_context: bool = True,
    ) -> None:
        self._context_bridge = context_bridge
        self._max_frames = max_frames
        self._include_trace_context = include_trace_context
        self._buffer_lock = threading.Lock()
        self._buffer: list[CapturedSample] = []
        self._started = False
        self._original_targets: list[tuple[ModuleType, Any]] = []
        self._internal_module_file = _normalize_path(self.INTERNAL_MODULE_FILE)

    @property
    def max_frames(self) -> int:
        return self._max_frames

    def start(self) -> None:
        if self._started:
            return

        self._original_targets = []
        patched_target = None
        for module in self.TARGET_MODULES:
            original_target = getattr(module, self.PATCHED_LOCK_NAME)
            self._original_targets.append((module, original_target))
            if patched_target is None:
                patched_target = self._build_patched_target(original_target)
            setattr(module, self.PATCHED_LOCK_NAME, patched_target)

        self._started = True

    def stop(self) -> None:
        if not self._started:
            return

        # Existing proxies outlive the factory patch. Disable and drain under
        # the same lock used to append samples so an in-flight append cannot
        # leave retained samples after stop returns.
        with self._buffer_lock:
            self._started = False
            self._buffer.clear()
        for module, original_target in reversed(self._original_targets):
            setattr(module, self.PATCHED_LOCK_NAME, original_target)
        self._original_targets = []

    def capture(self) -> list[CapturedSample]:
        with self._buffer_lock:
            captured = self._buffer
            self._buffer = []
        return captured

    def reset_after_fork(self) -> None:
        if self._started:
            for module, original_target in reversed(self._original_targets):
                setattr(module, self.PATCHED_LOCK_NAME, original_target)
        self._buffer_lock = threading.Lock()
        self._buffer = []
        self._original_targets = []
        self._started = False

    def record_acquire(
        self,
        state: _ProfiledPrimitiveState,
        *,
        start_ns: int,
        end_ns: int,
        frames: tuple[CapturedFrame, ...],
    ) -> None:
        self._record_sample(
            state=state,
            sample_type=_LOCK_ACQUIRE_SAMPLE_TYPE,
            period_type="lock.acquire",
            value=max(end_ns - start_ns, 0),
            frames=frames,
        )

    def record_release(
        self,
        state: _ProfiledPrimitiveState,
        *,
        start_ns: int,
        end_ns: int,
        frames: tuple[CapturedFrame, ...],
    ) -> None:
        self._record_sample(
            state=state,
            sample_type=_LOCK_HOLD_SAMPLE_TYPE,
            period_type="lock.release",
            value=max(end_ns - start_ns, 0),
            frames=frames,
        )

    def record_wait(
        self,
        state: _ProfiledPrimitiveState,
        *,
        start_ns: int,
        end_ns: int,
        frames: tuple[CapturedFrame, ...],
    ) -> None:
        self._record_sample(
            state=state,
            sample_type=_LOCK_WAIT_SAMPLE_TYPE,
            period_type="lock.wait",
            value=max(end_ns - start_ns, 0),
            frames=frames,
        )

    def _build_patched_target(self, original_target: Any) -> Any:
        if self.PATCH_MODE == _FACTORY_PATCH_MODE:

            def profiled_factory(
                *args: Any, **kwargs: Any
            ) -> _ProfiledPrimitiveProxy:
                return _ProfiledPrimitiveProxy(
                    original_target(*args, **kwargs),
                    self,
                    lock_kind=self.LOCK_KIND,
                    is_internal=_is_internal_lock_allocation(
                        self._internal_module_file
                    ),
                )

            return profiled_factory

        if self.PATCH_MODE == _SYNC_CLASS_PATCH_MODE:
            return _build_profiled_sync_class(
                original_class=original_target,
                collector=self,
                lock_kind=self.LOCK_KIND,
                internal_module_file=self._internal_module_file,
            )

        if self.PATCH_MODE == _ASYNC_CLASS_PATCH_MODE:
            return _build_profiled_async_class(
                original_class=original_target,
                collector=self,
                lock_kind=self.LOCK_KIND,
                internal_module_file=self._internal_module_file,
            )

        raise ValueError(f"Unsupported patch mode: {self.PATCH_MODE}")

    def _record_sample(
        self,
        *,
        state: _ProfiledPrimitiveState,
        sample_type: str,
        period_type: str,
        value: int,
        frames: tuple[CapturedFrame, ...],
    ) -> None:
        if not self._started or not frames:
            return

        current_thread = threading.current_thread()
        thread_id = current_thread.ident or 0
        span_context = INVALID_SPAN_CONTEXT
        span_metadata = None
        if self._include_trace_context and thread_id != 0:
            span_metadata = self._context_bridge.span_metadata_for_thread(
                thread_id
            )
            if span_metadata is not None:
                span_context = span_metadata.span_context

        sample = CapturedSample(
            timestamp_unix_nano=time_ns(),
            thread_id=thread_id,
            thread_name=current_thread.name,
            frames=frames,
            trace_id=span_context.trace_id,
            span_id=span_context.span_id,
            local_root_span_id=(
                span_metadata.local_root_span_id
                if span_metadata is not None
                else span_context.span_id
            ),
            trace_type=(span_metadata.trace_type if span_metadata else None),
            trace_endpoint=(
                span_metadata.trace_endpoint if span_metadata else None
            ),
            class_name=(span_metadata.class_name if span_metadata else None),
            value=value,
            sample_type=sample_type,
            sample_unit="nanoseconds",
            period_type=period_type,
            period_unit="count",
            period=1,
            attributes=(
                CapturedAttribute(
                    key="lock.name",
                    value=state.init_location,
                ),
                CapturedAttribute(
                    key="lock.kind",
                    value=state.lock_kind,
                ),
            ),
        )

        with self._buffer_lock:
            if self._started:
                self._buffer.append(sample)


class ThreadingLockCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "Lock"
    LOCK_KIND = "threading.Lock"
    PATCH_MODE = _FACTORY_PATCH_MODE
    TARGET_MODULES = (threading,)
    INTERNAL_MODULE_FILE = _THREADING_MODULE_FILE


class ThreadingRLockCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "RLock"
    LOCK_KIND = "threading.RLock"
    PATCH_MODE = _FACTORY_PATCH_MODE
    TARGET_MODULES = (threading,)
    INTERNAL_MODULE_FILE = _THREADING_MODULE_FILE


class ThreadingSemaphoreCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "Semaphore"
    LOCK_KIND = "threading.Semaphore"
    PATCH_MODE = _SYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (threading,)
    INTERNAL_MODULE_FILE = _THREADING_MODULE_FILE


class ThreadingBoundedSemaphoreCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "BoundedSemaphore"
    LOCK_KIND = "threading.BoundedSemaphore"
    PATCH_MODE = _SYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (threading,)
    INTERNAL_MODULE_FILE = _THREADING_MODULE_FILE


class ThreadingConditionCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "Condition"
    LOCK_KIND = "threading.Condition"
    PATCH_MODE = _SYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (threading,)
    INTERNAL_MODULE_FILE = _THREADING_MODULE_FILE


class AsyncioLockCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "Lock"
    LOCK_KIND = "asyncio.Lock"
    PATCH_MODE = _ASYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (asyncio, asyncio.locks)
    INTERNAL_MODULE_FILE = _ASYNCIO_LOCKS_MODULE_FILE


class AsyncioSemaphoreCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "Semaphore"
    LOCK_KIND = "asyncio.Semaphore"
    PATCH_MODE = _ASYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (asyncio, asyncio.locks)
    INTERNAL_MODULE_FILE = _ASYNCIO_LOCKS_MODULE_FILE


class AsyncioBoundedSemaphoreCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "BoundedSemaphore"
    LOCK_KIND = "asyncio.BoundedSemaphore"
    PATCH_MODE = _ASYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (asyncio, asyncio.locks)
    INTERNAL_MODULE_FILE = _ASYNCIO_LOCKS_MODULE_FILE


class AsyncioConditionCollector(_PrimitiveCollector):
    PATCHED_LOCK_NAME = "Condition"
    LOCK_KIND = "asyncio.Condition"
    PATCH_MODE = _ASYNC_CLASS_PATCH_MODE
    TARGET_MODULES = (asyncio, asyncio.locks)
    INTERNAL_MODULE_FILE = _ASYNCIO_LOCKS_MODULE_FILE


def _build_profiled_sync_class(
    *,
    original_class: type[Any],
    collector: _PrimitiveCollector,
    lock_kind: str,
    internal_module_file: str | None,
) -> type[Any]:
    class _ProfiledSyncPrimitive(original_class):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            # Python 3.10 BoundedSemaphore resolves the patched global
            # Semaphore.__init__ on an instance outside that wrapper's MRO.
            original_class.__init__(self, *args, **kwargs)
            self._otel_profiled_state = _ProfiledPrimitiveState(
                collector,
                lock_kind=lock_kind,
                is_internal=_is_internal_lock_allocation(internal_module_file),
            )
            if _should_bind_instance_lock_methods(original_class):
                original_acquire = self.acquire
                original_release = self.release
                self.acquire = (  # type: ignore[method-assign]
                    lambda *inner_args,
                    **inner_kwargs: _acquire_sync_primitive(
                        self._otel_profiled_state,
                        original_acquire,
                        *inner_args,
                        **inner_kwargs,
                    )
                )
                self.release = (  # type: ignore[method-assign]
                    lambda *inner_args,
                    **inner_kwargs: _release_sync_primitive(
                        self._otel_profiled_state,
                        original_release,
                        *inner_args,
                        **inner_kwargs,
                    )
                )

        def acquire(self, *args: Any, **kwargs: Any) -> Any:
            return _acquire_sync_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.acquire(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        def __enter__(self, *args: Any, **kwargs: Any) -> Any:
            return _acquire_sync_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.__enter__(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        def release(self, *args: Any, **kwargs: Any) -> Any:
            return _release_sync_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.release(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        def __exit__(self, *args: Any, **kwargs: Any) -> Any:
            return _release_sync_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.__exit__(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        if _supports_wait_method(original_class):

            def wait(self, *args: Any, **kwargs: Any) -> Any:
                return _wait_sync_primitive(
                    self._otel_profiled_state,
                    lambda *inner_args, **inner_kwargs: original_class.wait(
                        self, *inner_args, **inner_kwargs
                    ),
                    *args,
                    **kwargs,
                )

    _ProfiledSyncPrimitive.__module__ = original_class.__module__
    _ProfiledSyncPrimitive.__name__ = original_class.__name__
    _ProfiledSyncPrimitive.__qualname__ = original_class.__qualname__
    return _ProfiledSyncPrimitive


def _build_profiled_async_class(
    *,
    original_class: type[Any],
    collector: _PrimitiveCollector,
    lock_kind: str,
    internal_module_file: str | None,
) -> type[Any]:
    class _ProfiledAsyncPrimitive(original_class):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._otel_profiled_state = _ProfiledPrimitiveState(
                collector,
                lock_kind=lock_kind,
                is_internal=_is_internal_lock_allocation(internal_module_file),
            )
            if _should_bind_instance_lock_methods(original_class):
                original_acquire = self.acquire
                original_release = self.release

                async def acquire_wrapper(
                    *inner_args: Any, **inner_kwargs: Any
                ) -> Any:
                    return await _acquire_async_primitive(
                        self._otel_profiled_state,
                        original_acquire,
                        *inner_args,
                        **inner_kwargs,
                    )

                def release_wrapper(
                    *inner_args: Any, **inner_kwargs: Any
                ) -> Any:
                    return _release_sync_primitive(
                        self._otel_profiled_state,
                        original_release,
                        *inner_args,
                        **inner_kwargs,
                    )

                self.acquire = acquire_wrapper  # type: ignore[method-assign]
                self.release = release_wrapper  # type: ignore[method-assign]

        async def acquire(self, *args: Any, **kwargs: Any) -> Any:
            return await _acquire_async_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.acquire(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        async def __aenter__(self, *args: Any, **kwargs: Any) -> Any:
            return await _acquire_async_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.__aenter__(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        def release(self, *args: Any, **kwargs: Any) -> Any:
            return _release_sync_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.release(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        async def __aexit__(self, *args: Any, **kwargs: Any) -> Any:
            return await _release_async_primitive(
                self._otel_profiled_state,
                lambda *inner_args, **inner_kwargs: original_class.__aexit__(
                    self, *inner_args, **inner_kwargs
                ),
                *args,
                **kwargs,
            )

        if _supports_wait_method(original_class):

            async def wait(self, *args: Any, **kwargs: Any) -> Any:
                return await _wait_async_primitive(
                    self._otel_profiled_state,
                    lambda *inner_args, **inner_kwargs: original_class.wait(
                        self, *inner_args, **inner_kwargs
                    ),
                    *args,
                    **kwargs,
                )

    _ProfiledAsyncPrimitive.__module__ = original_class.__module__
    _ProfiledAsyncPrimitive.__name__ = original_class.__name__
    _ProfiledAsyncPrimitive.__qualname__ = original_class.__qualname__
    return _ProfiledAsyncPrimitive


def _acquire_sync_primitive(
    state: _ProfiledPrimitiveState,
    inner_func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    start_ns = monotonic_ns()
    result = inner_func(*args, **kwargs)
    if result is False:
        return result

    end_ns = monotonic_ns()
    state.acquired_time_ns = end_ns
    if not state.is_internal:
        state.collector.record_acquire(
            state,
            start_ns=start_ns,
            end_ns=end_ns,
            frames=_capture_current_frames(
                max_frames=state.collector.max_frames
            ),
        )
    return result


async def _acquire_async_primitive(
    state: _ProfiledPrimitiveState,
    inner_func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    start_ns = monotonic_ns()
    result = await inner_func(*args, **kwargs)
    if result is False:
        return result

    end_ns = monotonic_ns()
    state.acquired_time_ns = end_ns
    if not state.is_internal:
        state.collector.record_acquire(
            state,
            start_ns=start_ns,
            end_ns=end_ns,
            frames=_capture_current_frames(
                max_frames=state.collector.max_frames
            ),
        )
    return result


def _release_sync_primitive(
    state: _ProfiledPrimitiveState,
    inner_func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    acquired_time_ns = state.acquired_time_ns
    state.acquired_time_ns = None
    result = inner_func(*args, **kwargs)
    if acquired_time_ns is None or state.is_internal:
        return result

    state.collector.record_release(
        state,
        start_ns=acquired_time_ns,
        end_ns=monotonic_ns(),
        frames=_capture_current_frames(max_frames=state.collector.max_frames),
    )
    return result


def _wait_sync_primitive(
    state: _ProfiledPrimitiveState,
    inner_func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    start_ns = monotonic_ns()
    result = inner_func(*args, **kwargs)
    if not state.is_internal:
        state.collector.record_wait(
            state,
            start_ns=start_ns,
            end_ns=monotonic_ns(),
            frames=_capture_current_frames(
                max_frames=state.collector.max_frames
            ),
        )
    return result


async def _release_async_primitive(
    state: _ProfiledPrimitiveState,
    inner_func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    acquired_time_ns = state.acquired_time_ns
    state.acquired_time_ns = None
    result = await inner_func(*args, **kwargs)
    if acquired_time_ns is None or state.is_internal:
        return result

    state.collector.record_release(
        state,
        start_ns=acquired_time_ns,
        end_ns=monotonic_ns(),
        frames=_capture_current_frames(max_frames=state.collector.max_frames),
    )
    return result


async def _wait_async_primitive(
    state: _ProfiledPrimitiveState,
    inner_func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    start_ns = monotonic_ns()
    result = await inner_func(*args, **kwargs)
    if not state.is_internal:
        state.collector.record_wait(
            state,
            start_ns=start_ns,
            end_ns=monotonic_ns(),
            frames=_capture_current_frames(
                max_frames=state.collector.max_frames
            ),
        )
    return result


def _capture_current_frames(*, max_frames: int) -> tuple[CapturedFrame, ...]:
    frames: list[CapturedFrame] = []
    current = _first_external_frame()
    while current is not None and len(frames) < max_frames:
        code = current.f_code
        frames.append(
            CapturedFrame(
                function=code.co_name,
                filename=code.co_filename,
                lineno=current.f_lineno,
            )
        )
        current = current.f_back
    return tuple(frames)


def _resolve_init_location() -> str:
    frame = _first_external_frame()
    if frame is None:
        return "unknown:0"

    code = frame.f_code
    return f"{os.path.basename(code.co_filename)}:{frame.f_lineno}"


def _is_internal_lock_allocation(internal_module_file: str | None) -> bool:
    if not internal_module_file:
        return False

    frame = _first_external_frame()
    if frame is None:
        return False

    return _normalize_path(frame.f_code.co_filename) == internal_module_file


def _first_external_frame() -> FrameType | None:
    try:
        current = sys._getframe(1)
    except ValueError:
        return None

    while current is not None:
        if _normalize_path(current.f_code.co_filename) != _COLLECTOR_FILE:
            return current
        current = current.f_back
    return None


def _normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return os.path.normpath(os.path.realpath(path))
    except OSError:
        return path


def _should_bind_instance_lock_methods(original_class: type[Any]) -> bool:
    return original_class.__name__ == "Condition"


def _supports_wait_method(original_class: type[Any]) -> bool:
    return hasattr(original_class, "wait")
