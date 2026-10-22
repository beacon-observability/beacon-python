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

from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    function: str
    filename: str
    lineno: int


@lru_cache(maxsize=4096)
def _cached_frame(function: str, filename: str, lineno: int) -> CapturedFrame:
    return CapturedFrame(function, filename, lineno)


def captured_frame(function: str, filename: str, lineno: int) -> CapturedFrame:
    if len(function) <= 512 and len(filename) <= 2048:
        return _cached_frame(function, filename, lineno)
    return CapturedFrame(function, filename, lineno)


@dataclass(frozen=True, slots=True)
class CapturedAttribute:
    key: str
    value: object
    unit: str = ""


@dataclass(frozen=True, slots=True)
class CapturedSample:
    timestamp_unix_nano: int
    thread_id: int
    thread_name: str
    frames: tuple[CapturedFrame, ...]
    trace_id: int = 0
    span_id: int = 0
    local_root_span_id: int = 0
    trace_type: str | None = None
    trace_endpoint: str | None = None
    class_name: str | None = None
    task_id: int | None = None
    task_name: str | None = None
    value: int = 1
    cpu_time_ns: int = 0
    sample_type: str = "samples"
    sample_unit: str = "count"
    period_type: str = "wall"
    period_unit: str = "nanoseconds"
    period: int = 0
    attributes: tuple[CapturedAttribute, ...] = ()


class Collector(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def capture(self) -> list[CapturedSample]: ...
