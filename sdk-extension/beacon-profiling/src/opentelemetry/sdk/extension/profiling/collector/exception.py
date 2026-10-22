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

import logging
import os
import random
import sys
import sysconfig
import threading
from math import ceil
from time import time_ns

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedAttribute,
    CapturedFrame,
    CapturedSample,
    captured_frame,
)
from opentelemetry.sdk.extension.profiling.collector.buffering import (
    SampleBudget,
    SampleBuffer,
    internal_work,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.trace import INVALID_SPAN_CONTEXT

_logger = logging.getLogger(__name__)

HAS_MONITORING = hasattr(sys, "monitoring")
_GIL_DISABLED = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
_MONITORING_TOOL_IDS = (5, 4)
MAX_EXCEPTION_MESSAGE_LEN = 128
_PROFILER_PATH_MARKER = os.path.normpath(
    "opentelemetry/sdk/extension/profiling"
)
_IGNORED_EXCEPTIONS = (
    GeneratorExit,
    StopAsyncIteration,
    StopIteration,
)


class _PoissonSampler:
    def __init__(self) -> None:
        self._random = random.Random()

    def sample(self, average_interval: int) -> int:
        if average_interval <= 1:
            return 1
        return max(1, ceil(self._random.expovariate(1.0 / average_interval)))


class ExceptionCollector:
    def __init__(
        self,
        context_bridge: ContextBridge,
        *,
        max_frames: int = 64,
        include_trace_context: bool = True,
        sampling_interval: int = 100,
        collect_message: bool = False,
        sample_budget: SampleBudget | None = None,
    ) -> None:
        if sampling_interval < 1:
            raise ValueError("sampling_interval must be >= 1")

        self._owns_sample_budget = sample_budget is None
        self._sample_budget = (
            sample_budget if sample_budget is not None else SampleBudget()
        )
        self._context_bridge = context_bridge
        self._max_frames = max_frames
        self._include_trace_context = include_trace_context
        self._sampling_interval = sampling_interval
        self._collect_message = collect_message

        self._buffer = SampleBuffer(self._sample_budget)
        self._buffer_lock = threading.Lock()
        self._sampler = _PoissonSampler()
        self._counter = 0
        self._next_sample = sampling_interval
        self._collecting_state = threading.local()
        self._monitoring_tool_id: int | None = None

    def start(self) -> None:
        if not HAS_MONITORING:
            _logger.debug(
                "Exception profiling requires sys.monitoring (Python 3.12+)"
            )
            return

        if _GIL_DISABLED:
            _logger.debug(
                "Exception profiling is not supported on free-threaded CPython"
            )
            return

        if self._monitoring_tool_id is not None:
            return

        for tool_id in _MONITORING_TOOL_IDS:
            try:
                sys.monitoring.use_tool_id(
                    tool_id, "opentelemetry-python-exception-profiler"
                )
                sys.monitoring.register_callback(
                    tool_id,
                    sys.monitoring.events.EXCEPTION_HANDLED,
                    self._on_exception_handled,
                )
                sys.monitoring.set_events(
                    tool_id, sys.monitoring.events.EXCEPTION_HANDLED
                )
            except ValueError:
                continue
            except Exception:
                _logger.exception(
                    "Failed to configure exception profiling with tool id %s",
                    tool_id,
                )
                self._cleanup_monitoring(tool_id)
                continue

            self._counter = 0
            self._next_sample = self._sampling_interval
            self._monitoring_tool_id = tool_id
            return

        _logger.debug(
            "No sys.monitoring tool id available for exception profiling"
        )

    def stop(self) -> None:
        tool_id = self._monitoring_tool_id
        with self._buffer_lock:
            self._monitoring_tool_id = None
            self._buffer.clear()
        if tool_id is None:
            return

        self._cleanup_monitoring(tool_id)

    def capture(self) -> list[CapturedSample]:
        with self._buffer_lock:
            return self._buffer.drain()

    def reset_after_fork(self) -> None:
        tool_id = self._monitoring_tool_id
        if tool_id is not None:
            self._cleanup_monitoring(tool_id)
        self._buffer_lock = threading.Lock()
        if self._owns_sample_budget:
            self._sample_budget.reset_after_fork()
        self._buffer = SampleBuffer(self._sample_budget)
        self._counter = 0
        self._next_sample = self._sampling_interval
        self._collecting_state = threading.local()
        self._monitoring_tool_id = None

    def _cleanup_monitoring(self, tool_id: int) -> None:
        try:
            sys.monitoring.register_callback(
                tool_id,
                sys.monitoring.events.EXCEPTION_HANDLED,
                None,
            )
        except Exception:
            _logger.debug(
                "Failed to unregister exception monitoring callback",
                exc_info=True,
            )

        try:
            sys.monitoring.set_events(tool_id, 0)
        except Exception:
            _logger.debug(
                "Failed to disable exception monitoring events",
                exc_info=True,
            )

        try:
            sys.monitoring.free_tool_id(tool_id)
        except Exception:
            _logger.debug("Failed to free monitoring tool id", exc_info=True)

    def _is_collecting(self) -> bool:
        return bool(getattr(self._collecting_state, "active", False))

    def _set_collecting(self, value: bool) -> None:
        self._collecting_state.active = value

    def _on_exception_handled(
        self,
        code,  # noqa: ANN001
        instruction_offset: int,
        exception: BaseException,
    ) -> None:
        del code, instruction_offset

        if self._is_collecting() or internal_work():
            return
        tool_id = self._monitoring_tool_id
        if tool_id is None:
            return

        self._counter += 1
        if self._counter < self._next_sample:
            return

        self._counter = 0
        self._next_sample = self._sampler.sample(self._sampling_interval)

        self._set_collecting(True)
        try:
            sample = self._build_sample(exception)
            if sample is None:
                return
            with self._buffer_lock:
                if self._monitoring_tool_id == tool_id:
                    self._buffer.append(sample)
        except Exception:
            _logger.debug("Failed to capture handled exception", exc_info=True)
        finally:
            self._set_collecting(False)

    def _build_sample(self, exception: BaseException) -> CapturedSample | None:
        if isinstance(exception, _IGNORED_EXCEPTIONS):
            return None

        if _is_profiler_internal_traceback(exception.__traceback__):
            return None

        frames = self._frames_from_traceback(exception.__traceback__)
        if not frames:
            return None

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

        attributes = [
            CapturedAttribute(
                key="exception.type",
                value=_format_exception_type(type(exception)),
            ),
            CapturedAttribute(key="exception.escaped", value=False),
        ]
        if self._collect_message:
            attributes.append(
                CapturedAttribute(
                    key="exception.message",
                    value=_format_exception_message(exception),
                )
            )

        return CapturedSample(
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
            sample_type="exceptions",
            sample_unit="count",
            period_type="exceptions",
            period_unit="count",
            period=self._sampling_interval,
            attributes=tuple(attributes),
        )

    def _frames_from_traceback(self, traceback) -> tuple[CapturedFrame, ...]:  # noqa: ANN001
        frames: list[CapturedFrame] = []
        current = traceback
        while current is not None:
            frame = current.tb_frame
            frames.append(
                captured_frame(
                    function=frame.f_code.co_name,
                    filename=frame.f_code.co_filename,
                    lineno=current.tb_lineno,
                )
            )
            current = current.tb_next

        frames.reverse()
        if self._max_frames > 0:
            frames = frames[: self._max_frames]
        return tuple(frames)


def _format_exception_type(exception_type: type[BaseException]) -> str:
    module = getattr(exception_type, "__module__", "")
    name = getattr(exception_type, "__qualname__", exception_type.__name__)
    if module:
        return f"{module}.{name}"
    return name


def _format_exception_message(exception: BaseException) -> str:
    try:
        message = str(exception)
    except Exception:
        return "<unprintable exception>"

    if len(message) > MAX_EXCEPTION_MESSAGE_LEN:
        return f"{message[:MAX_EXCEPTION_MESSAGE_LEN]}... (truncated)"
    return message


def _is_profiler_internal_traceback(traceback) -> bool:  # noqa: ANN001
    current = traceback
    while current is not None:
        filename = os.path.normpath(current.tb_frame.f_code.co_filename)
        if _PROFILER_PATH_MARKER in filename:
            return True
        current = current.tb_next
    return False
