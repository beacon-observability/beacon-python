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

import os
import threading
import tracemalloc
from time import monotonic, time_ns

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedAttribute,
    CapturedFrame,
    CapturedSample,
    captured_frame,
)
from opentelemetry.sdk.extension.profiling.collector.buffering import (
    SampleBudget,
    SampleBuffer,
)

_PROFILER_PATH_PATTERN = "*opentelemetry/sdk/extension/profiling/*"


class MemoryCollector:
    def __init__(
        self,
        *,
        max_frames: int = 64,
        capture_interval: float = 60.0,
        top_stats: int = 200,
        ignore_profiler: bool = True,
        sample_budget: SampleBudget | None = None,
    ) -> None:
        if top_stats < 1:
            raise ValueError("top_stats must be >= 1")
        if capture_interval < 0:
            raise ValueError("capture_interval must be >= 0")

        self._sample_budget = (
            sample_budget if sample_budget is not None else SampleBudget()
        )
        self._max_frames = max_frames
        self._capture_interval = capture_interval
        self._top_stats = top_stats
        self._ignore_profiler = ignore_profiler
        self._owns_tracemalloc = False
        self._last_capture_monotonic = 0.0
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if tracemalloc.is_tracing():
                return
            tracemalloc.start(self._max_frames)
            self._owns_tracemalloc = True

    def stop(self) -> None:
        with self._lock:
            if self._owns_tracemalloc and tracemalloc.is_tracing():
                tracemalloc.stop()
            self._owns_tracemalloc = False
            self._last_capture_monotonic = 0.0

    def capture(self) -> list[CapturedSample]:
        with self._lock:
            if not tracemalloc.is_tracing():
                return []

            now = monotonic()
            if (
                self._last_capture_monotonic
                and now - self._last_capture_monotonic < self._capture_interval
            ):
                return []

            self._last_capture_monotonic = now
            snapshot = tracemalloc.take_snapshot()

        if self._ignore_profiler:
            snapshot = snapshot.filter_traces(
                [tracemalloc.Filter(False, _PROFILER_PATH_PATTERN)]
            )

        timestamp_unix_nano = time_ns()
        with SampleBuffer(self._sample_budget) as samples:
            for stat in snapshot.statistics("traceback")[: self._top_stats]:
                frames = _frames_from_traceback(
                    stat.traceback,
                    max_frames=self._max_frames,
                )
                if not frames:
                    continue

                attributes = (
                    CapturedAttribute(key="memory.kind", value="heap"),
                    CapturedAttribute(
                        key="memory.source", value="tracemalloc"
                    ),
                )
                samples.append(
                    CapturedSample(
                        timestamp_unix_nano=timestamp_unix_nano,
                        thread_id=0,
                        thread_name="process",
                        frames=frames,
                        value=stat.size,
                        sample_type="memory.heap.bytes",
                        sample_unit="bytes",
                        period_type="memory.heap",
                        period_unit="count",
                        period=1,
                        attributes=attributes,
                    )
                )
                samples.append(
                    CapturedSample(
                        timestamp_unix_nano=timestamp_unix_nano,
                        thread_id=0,
                        thread_name="process",
                        frames=frames,
                        value=stat.count,
                        sample_type="memory.heap.objects",
                        sample_unit="count",
                        period_type="memory.heap",
                        period_unit="count",
                        period=1,
                        attributes=attributes,
                    )
                )

            return samples.drain()

    def reset_after_fork(self) -> None:
        self._lock = threading.Lock()
        self._last_capture_monotonic = 0.0
        self._owns_tracemalloc = (
            self._owns_tracemalloc and tracemalloc.is_tracing()
        )


def _frames_from_traceback(
    traceback: tracemalloc.Traceback,
    *,
    max_frames: int,
) -> tuple[CapturedFrame, ...]:
    frames = []
    for frame in reversed(traceback):
        frames.append(
            captured_frame(
                function=_frame_name(frame.filename, frame.lineno),
                filename=frame.filename,
                lineno=frame.lineno,
            )
        )
        if len(frames) >= max_frames:
            break
    return tuple(frames)


def _frame_name(filename: str, lineno: int) -> str:
    return f"{os.path.basename(filename)}:{lineno}"
