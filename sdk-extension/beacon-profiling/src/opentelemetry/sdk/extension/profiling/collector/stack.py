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

import sys
import threading
import time

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedFrame,
    CapturedSample,
    captured_frame,
)
from opentelemetry.sdk.extension.profiling.collector.buffering import (
    SampleBudget,
    SampleBuffer,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.trace import INVALID_SPAN_CONTEXT

_PROFILE_SCHEDULER_THREAD_NAME = "OTelProfileScheduler"


class StackCollector:
    def __init__(
        self,
        context_bridge: ContextBridge,
        max_frames: int = 64,
        include_trace_context: bool = True,
        sample_budget: SampleBudget | None = None,
    ) -> None:
        self._sample_budget = (
            sample_budget if sample_budget is not None else SampleBudget()
        )
        self._context_bridge = context_bridge
        self._max_frames = max_frames
        self._include_trace_context = include_trace_context
        self._thread_cpu_times_ns: dict[int, int] = {}

    def start(self) -> None:
        self._thread_cpu_times_ns.clear()

    def stop(self) -> None:
        self._thread_cpu_times_ns.clear()

    def reset_after_fork(self) -> None:
        self._thread_cpu_times_ns.clear()

    def capture(self) -> list[CapturedSample]:
        current_thread_id = threading.current_thread().ident
        active_threads = {
            thread.ident: thread.name
            for thread in threading.enumerate()
            if thread.ident is not None
        }
        timestamp_unix_nano = time.time_ns()
        with SampleBuffer(self._sample_budget) as samples:
            sampled_thread_ids: set[int] = set()

            for thread_id, frame in sys._current_frames().items():
                thread_name = active_threads.get(
                    thread_id, f"thread-{thread_id}"
                )
                if (
                    thread_id == current_thread_id
                    or thread_name == _PROFILE_SCHEDULER_THREAD_NAME
                ):
                    continue
                sampled_thread_ids.add(thread_id)

                frames: list[CapturedFrame] = []
                current = frame
                while current is not None and len(frames) < self._max_frames:
                    code = current.f_code
                    frames.append(
                        captured_frame(
                            function=code.co_name,
                            filename=code.co_filename,
                            lineno=current.f_lineno,
                        )
                    )
                    current = current.f_back

                if not frames:
                    continue

                span_context = INVALID_SPAN_CONTEXT
                span_metadata = None
                if self._include_trace_context:
                    span_metadata = (
                        self._context_bridge.span_metadata_for_thread(
                            thread_id
                        )
                    )
                    if span_metadata is not None:
                        span_context = span_metadata.span_context

                samples.append(
                    CapturedSample(
                        timestamp_unix_nano=timestamp_unix_nano,
                        thread_id=thread_id,
                        thread_name=thread_name,
                        frames=tuple(frames),
                        trace_id=span_context.trace_id,
                        span_id=span_context.span_id,
                        local_root_span_id=(
                            span_metadata.local_root_span_id
                            if span_metadata is not None
                            else span_context.span_id
                        ),
                        trace_type=(
                            span_metadata.trace_type if span_metadata else None
                        ),
                        trace_endpoint=(
                            span_metadata.trace_endpoint
                            if span_metadata
                            else None
                        ),
                        class_name=(
                            span_metadata.class_name if span_metadata else None
                        ),
                        cpu_time_ns=self._thread_cpu_delta_ns(thread_id),
                    )
                )

            stale_thread_ids = (
                self._thread_cpu_times_ns.keys() - sampled_thread_ids
            )
            for thread_id in stale_thread_ids:
                del self._thread_cpu_times_ns[thread_id]

            return samples.drain()

    def _thread_cpu_delta_ns(self, thread_id: int) -> int:
        current = _read_thread_cpu_time_ns(thread_id)
        if current is None:
            self._thread_cpu_times_ns.pop(thread_id, None)
            return 0

        previous = self._thread_cpu_times_ns.get(thread_id)
        self._thread_cpu_times_ns[thread_id] = current
        if previous is None or current < previous:
            return 0
        return current - previous


def _read_thread_cpu_time_ns(thread_id: int) -> int | None:
    get_clock_id = getattr(time, "pthread_getcpuclockid", None)
    get_clock_time_ns = getattr(time, "clock_gettime_ns", None)
    if get_clock_id is None or get_clock_time_ns is None:
        return None
    try:
        return get_clock_time_ns(get_clock_id(thread_id))
    except (OSError, ValueError):
        return None
