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

import atexit
import logging
import os
from os import environ
from threading import Lock

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedSample,
    Collector,
)
from opentelemetry.sdk.extension.profiling.collector.exception import (
    ExceptionCollector,
)
from opentelemetry.sdk.extension.profiling.collector.lock import (
    AsyncioBoundedSemaphoreCollector,
    AsyncioConditionCollector,
    AsyncioLockCollector,
    AsyncioSemaphoreCollector,
    ThreadingBoundedSemaphoreCollector,
    ThreadingConditionCollector,
    ThreadingLockCollector,
    ThreadingRLockCollector,
    ThreadingSemaphoreCollector,
)
from opentelemetry.sdk.extension.profiling.collector.memory import (
    MemoryCollector,
)
from opentelemetry.sdk.extension.profiling.collector.stack import (
    StackCollector,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.extension.profiling.environment_variables import (
    OTEL_PROFILING_EXCEPTION_COLLECT_MESSAGE,
    OTEL_PROFILING_EXCEPTION_ENABLED,
    OTEL_PROFILING_EXCEPTION_SAMPLING_INTERVAL,
    OTEL_PROFILING_EXPORT_INTERVAL,
    OTEL_PROFILING_EXPORTER,
    OTEL_PROFILING_INCLUDE_TRACE_CONTEXT,
    OTEL_PROFILING_LOCK_ENABLED,
    OTEL_PROFILING_MAX_FRAMES,
    OTEL_PROFILING_MEMORY_ENABLED,
    OTEL_PROFILING_MEMORY_IGNORE_PROFILER,
    OTEL_PROFILING_MEMORY_INTERVAL,
    OTEL_PROFILING_MEMORY_TOP_STATS,
    OTEL_PROFILING_PPROF_UPLOAD_URL,
    OTEL_PROFILING_SAMPLE_INTERVAL,
)
from opentelemetry.sdk.extension.profiling.export import (
    CompatiblePPROFExporter,
    create_otlp_profile_exporter,
)
from opentelemetry.sdk.extension.profiling.export.pprof import (
    PPROFProfileExporter,
)
from opentelemetry.sdk.extension.profiling.model.builder import (
    ProfilesRequestBuilder,
)
from opentelemetry.sdk.extension.profiling.model.pprof_builder import (
    CompatiblePprofProfileBuilder,
    PprofProfileBuilder,
)
from opentelemetry.sdk.extension.profiling.scheduler import ProfileScheduler
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import get_tracer_provider

_logger = logging.getLogger(__name__)

_DEFAULT_EXPORT_INTERVAL_SECONDS = 60.0


class Profiler:
    _active_instance: "Profiler | None" = None
    _active_lock = Lock()

    def __init__(
        self,
        *,
        exporter=None,
        resource: Resource | None = None,
        sample_interval: float | None = None,
        export_interval: float | None = None,
        max_frames: int | None = None,
        include_trace_context: bool | None = None,
        exception_enabled: bool | None = None,
        exception_sampling_interval: int | None = None,
        exception_collect_message: bool | None = None,
        lock_enabled: bool | None = None,
        memory_enabled: bool | None = None,
        memory_interval: float | None = None,
        memory_top_stats: int | None = None,
        memory_ignore_profiler: bool | None = None,
    ) -> None:
        self._resource = resource
        self._sample_interval = sample_interval or float(
            environ.get(OTEL_PROFILING_SAMPLE_INTERVAL, "0.01")
        )
        self._export_interval = (
            export_interval
            if export_interval is not None
            else float(
                environ.get(
                    OTEL_PROFILING_EXPORT_INTERVAL,
                    str(_DEFAULT_EXPORT_INTERVAL_SECONDS),
                )
            )
        )
        self._max_frames = max_frames or int(
            environ.get(OTEL_PROFILING_MAX_FRAMES, "64")
        )
        self._include_trace_context = (
            _parse_bool(
                environ.get(OTEL_PROFILING_INCLUDE_TRACE_CONTEXT, "true")
            )
            if include_trace_context is None
            else include_trace_context
        )
        self._exception_enabled = (
            _parse_bool(environ.get(OTEL_PROFILING_EXCEPTION_ENABLED, "false"))
            if exception_enabled is None
            else exception_enabled
        )
        self._exception_sampling_interval = exception_sampling_interval or int(
            environ.get(
                OTEL_PROFILING_EXCEPTION_SAMPLING_INTERVAL,
                "100",
            )
        )
        self._exception_collect_message = (
            _parse_bool(
                environ.get(
                    OTEL_PROFILING_EXCEPTION_COLLECT_MESSAGE,
                    "false",
                )
            )
            if exception_collect_message is None
            else exception_collect_message
        )
        self._lock_enabled = (
            _parse_bool(environ.get(OTEL_PROFILING_LOCK_ENABLED, "false"))
            if lock_enabled is None
            else lock_enabled
        )
        self._memory_enabled = (
            _parse_bool(environ.get(OTEL_PROFILING_MEMORY_ENABLED, "false"))
            if memory_enabled is None
            else memory_enabled
        )
        self._memory_interval = (
            memory_interval
            if memory_interval is not None
            else float(
                environ.get(
                    OTEL_PROFILING_MEMORY_INTERVAL,
                    str(self._export_interval),
                )
            )
        )
        self._memory_top_stats = memory_top_stats or int(
            environ.get(
                OTEL_PROFILING_MEMORY_TOP_STATS,
                "200",
            )
        )
        self._memory_ignore_profiler = (
            _parse_bool(
                environ.get(
                    OTEL_PROFILING_MEMORY_IGNORE_PROFILER,
                    "true",
                )
            )
            if memory_ignore_profiler is None
            else memory_ignore_profiler
        )

        self._buffer_lock = Lock()
        self._samples: list[CapturedSample] = []
        self._atexit_registered = False
        self._manual_exporter = exporter is not None
        self._context_bridge = ContextBridge()
        self._collectors: list[Collector] = [
            StackCollector(
                context_bridge=self._context_bridge,
                max_frames=self._max_frames,
                include_trace_context=self._include_trace_context,
            )
        ]
        if self._exception_enabled:
            self._collectors.append(
                ExceptionCollector(
                    context_bridge=self._context_bridge,
                    max_frames=self._max_frames,
                    include_trace_context=self._include_trace_context,
                    sampling_interval=self._exception_sampling_interval,
                    collect_message=self._exception_collect_message,
                )
            )
        if self._lock_enabled:
            self._collectors.extend(
                [
                    ThreadingLockCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    ThreadingRLockCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    ThreadingSemaphoreCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    ThreadingBoundedSemaphoreCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    ThreadingConditionCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    AsyncioLockCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    AsyncioSemaphoreCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    AsyncioBoundedSemaphoreCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                    AsyncioConditionCollector(
                        context_bridge=self._context_bridge,
                        max_frames=self._max_frames,
                        include_trace_context=self._include_trace_context,
                    ),
                ]
            )
        self._memory_collector: Collector | None = None
        if self._memory_enabled:
            self._memory_collector = MemoryCollector(
                max_frames=self._max_frames,
                capture_interval=self._memory_interval,
                top_stats=self._memory_top_stats,
                ignore_profiler=self._memory_ignore_profiler,
            )
        self._active_collectors: list[Collector] = []
        self._active_memory_collector: Collector | None = None
        self._exporter = exporter or self._create_exporter_from_env()
        self._builder = self._create_builder()
        self._scheduler = ProfileScheduler(
            capture=self._capture_regular_once,
            flush=self.flush,
            sample_interval=self._sample_interval,
            export_interval=self._export_interval,
        )
        self._memory_scheduler = ProfileScheduler(
            capture=self._capture_memory_once,
            flush=_noop,
            sample_interval=self._memory_interval,
            export_interval=self._export_interval,
        )
        self._started = False
        self._register_at_fork()

    def start(self) -> None:
        with self._active_lock:
            active = self.__class__._active_instance
            if active is not None and active is not self and active._started:
                _logger.error(
                    "A profiler is already running. Only one profiler "
                    "instance can be active at a time."
                )
                return
            if self._started:
                return
            self._context_bridge.start()
            self._active_collectors = self._start_collectors()
            self._scheduler.start()
            self._active_memory_collector = self._start_memory_collector()
            if self._active_memory_collector is not None:
                self._memory_scheduler.start()
            self._started = True
            self.__class__._active_instance = self
        if not self._atexit_registered:
            atexit.register(self.stop)
            self._atexit_registered = True

    def stop(self, flush: bool = True) -> None:
        with self._active_lock:
            if not self._started:
                if self._atexit_registered:
                    self._unregister_atexit()
                return
            actions = [
                self._scheduler.stop,
                self._memory_scheduler.stop,
                self._scheduler.join,
                self._memory_scheduler.join,
            ]
            if flush:
                actions.append(self.flush)
            actions.extend((self._stop_collectors, self._context_bridge.stop))
            if self._exporter is not None:
                actions.append(self._exporter.shutdown)
            failure: BaseException | None = None
            try:
                for action in actions:
                    try:
                        action()
                    except BaseException as error:
                        if failure is None:
                            failure = error
            finally:
                self._started = False
                if self.__class__._active_instance is self:
                    self.__class__._active_instance = None
                if self._atexit_registered:
                    self._unregister_atexit()
            if failure is not None:
                raise failure

    def capture_once(self) -> None:
        collectors = list(self._active_collectors)
        if self._active_memory_collector is not None:
            collectors.append(self._active_memory_collector)
        self._capture_collectors(collectors)

    def _capture_regular_once(self) -> None:
        self._capture_collectors(self._active_collectors)

    def _capture_memory_once(self) -> None:
        if self._active_memory_collector is None:
            return
        self._capture_collectors([self._active_memory_collector])

    def _capture_collectors(self, collectors: list[Collector]) -> None:
        captured: list[CapturedSample] = []
        for collector in collectors:
            try:
                captured.extend(collector.capture())
            except Exception:
                _logger.exception(
                    "Failed to capture samples from collector %s",
                    collector.__class__.__name__,
                )
        if not captured:
            return
        with self._buffer_lock:
            self._samples.extend(captured)

    def flush(self) -> None:
        if self._exporter is None:
            with self._buffer_lock:
                self._samples.clear()
            return

        with self._buffer_lock:
            if not self._samples:
                return
            batch = self._samples
            self._samples = []

        resource = self._resolve_resource()
        start_time_unix_nano = min(
            sample.timestamp_unix_nano for sample in batch
        )
        end_time_unix_nano = max(
            sample.timestamp_unix_nano for sample in batch
        )
        payload = self._builder.build(
            samples=batch,
            resource=resource,
            sample_period_ns=int(self._sample_interval * 1_000_000_000),
        )
        if isinstance(self._exporter, CompatiblePPROFExporter):
            self._exporter.export(
                payload,
                resource=resource,
                start_time_unix_nano=start_time_unix_nano,
                end_time_unix_nano=end_time_unix_nano,
            )
            return
        self._exporter.export(payload)

    def force_flush(self) -> None:
        self.flush()

    def _resolve_resource(self) -> Resource:
        if self._resource is not None:
            return self._resource
        tracer_provider = get_tracer_provider()
        resource = getattr(tracer_provider, "resource", None)
        if isinstance(resource, Resource):
            return resource
        return Resource.create()

    def _create_builder(self):
        if isinstance(self._exporter, CompatiblePPROFExporter):
            return CompatiblePprofProfileBuilder()
        if isinstance(self._exporter, PPROFProfileExporter):
            return PprofProfileBuilder()
        return ProfilesRequestBuilder()

    @staticmethod
    def _create_exporter_from_env():
        exporter_name = environ.get(OTEL_PROFILING_EXPORTER)
        if exporter_name is None:
            if environ.get(OTEL_PROFILING_PPROF_UPLOAD_URL):
                return CompatiblePPROFExporter()
            return create_otlp_profile_exporter()

        exporter_name = exporter_name.strip()
        if exporter_name == "none":
            return None
        if exporter_name == "pprof":
            return PPROFProfileExporter()
        if exporter_name == "pprof_http":
            return CompatiblePPROFExporter()
        if exporter_name != "otlp":
            raise ValueError(
                f"Unsupported profiling exporter '{exporter_name}'"
            )
        return create_otlp_profile_exporter()

    def _start_collectors(self) -> list[Collector]:
        active_collectors = []
        for collector in self._collectors:
            try:
                collector.start()
            except Exception:
                _logger.exception(
                    "Failed to start profiling collector %s",
                    collector.__class__.__name__,
                )
                continue
            active_collectors.append(collector)
        return active_collectors

    def _start_memory_collector(self) -> Collector | None:
        collector = self._memory_collector
        if collector is None:
            return None
        try:
            collector.start()
        except Exception:
            _logger.exception(
                "Failed to start profiling collector %s",
                collector.__class__.__name__,
            )
            return None
        return collector

    def _stop_collectors(self) -> None:
        for collector in reversed(self._active_collectors):
            try:
                collector.stop()
            except Exception:
                _logger.exception(
                    "Failed to stop profiling collector %s",
                    collector.__class__.__name__,
                )
        if self._active_memory_collector is not None:
            try:
                self._active_memory_collector.stop()
            except Exception:
                _logger.exception(
                    "Failed to stop profiling collector %s",
                    self._active_memory_collector.__class__.__name__,
                )
        self._active_collectors = []
        self._active_memory_collector = None

    def _register_at_fork(self) -> None:
        register_at_fork = getattr(os, "register_at_fork", None)
        if register_at_fork is None:
            return
        register_at_fork(after_in_child=self._after_fork_in_child)

    def _after_fork_in_child(self) -> None:
        was_started = self._started
        self.__class__._active_lock = Lock()
        self.__class__._active_instance = None
        self._buffer_lock = Lock()
        self._samples = []
        self._active_collectors = []
        self._active_memory_collector = None
        self._started = False
        self._atexit_registered = False
        self._reset_after_fork(self._context_bridge)
        for collector in self._collectors:
            self._reset_after_fork(collector)
        if self._memory_collector is not None:
            self._reset_after_fork(self._memory_collector)
        self._reset_after_fork(self._scheduler)
        self._reset_after_fork(self._memory_scheduler)
        self._reset_exporter_after_fork()
        self._builder = self._create_builder()
        if was_started:
            try:
                self.start()
            except Exception:
                _logger.exception(
                    "Failed to restart profiler in child process after fork"
                )

    def _reset_exporter_after_fork(self) -> None:
        if self._exporter is None:
            return
        if not self._manual_exporter:
            try:
                self._exporter.shutdown()
            except Exception:
                _logger.debug(
                    "Failed to shutdown inherited exporter after fork",
                    exc_info=True,
                )
            self._exporter = self._create_exporter_from_env()
            return
        after_fork = getattr(self._exporter, "after_fork_child", None)
        if callable(after_fork):
            after_fork()

    @staticmethod
    def _reset_after_fork(component) -> None:  # noqa: ANN001
        reset = getattr(component, "reset_after_fork", None)
        if callable(reset):
            reset()

    def _unregister_atexit(self) -> None:
        try:
            atexit.unregister(self.stop)
        except Exception:
            pass
        finally:
            self._atexit_registered = False


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _noop() -> None:
    return None
