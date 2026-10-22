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

import asyncio.events
from dataclasses import dataclass
from threading import RLock, get_ident
from typing import Callable, Optional

import opentelemetry.context as context_api
from opentelemetry.context import _RUNTIME_CONTEXT, Context
from opentelemetry.trace import INVALID_SPAN_CONTEXT, Span, get_current_span
from opentelemetry.trace.span import SpanContext


@dataclass(frozen=True)
class SpanMetadata:
    span_context: SpanContext
    trace_type: str | None
    trace_endpoint: str | None
    class_name: str | None
    local_root_span_id: int | None


class ContextBridge:
    def __init__(self) -> None:
        self._lock = RLock()
        self._started = False
        self._root_key = context_api.create_key("beacon_profiling_local_root")
        self._span_metadata_by_thread: dict[int, SpanMetadata] = {}
        self._original_attach: Optional[Callable] = None
        self._original_detach: Optional[Callable] = None
        self._original_asyncio_handle_run: Optional[Callable] = None

    def start(self) -> None:
        with self._lock:
            if self._started:
                return

            self._original_attach = context_api.attach
            self._original_detach = context_api.detach

            original_attach = self._original_attach
            original_detach = self._original_detach

            def attach_wrapper(context):
                root = self._local_root(context)
                if (
                    context_api.get_value(self._root_key, context=context)
                    is not root
                ):
                    context = context_api.set_value(
                        self._root_key, root, context=context
                    )
                token = original_attach(context)
                self._refresh_current_thread()
                return token

            def detach_wrapper(token) -> None:
                original_detach(token)
                self._refresh_current_thread()

            original_handle_run = asyncio.events.Handle._run

            def handle_run_wrapper(handle) -> None:
                thread_id = get_ident()
                self._refresh_thread_from_asyncio_handle(thread_id, handle)
                try:
                    return original_handle_run(handle)
                finally:
                    self._refresh_current_thread()

            context_api.attach = attach_wrapper
            context_api.detach = detach_wrapper
            asyncio.events.Handle._run = handle_run_wrapper
            self._original_asyncio_handle_run = original_handle_run
            self._started = True
            self._refresh_current_thread()

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                return
            if self._original_attach is not None:
                context_api.attach = self._original_attach
            if self._original_detach is not None:
                context_api.detach = self._original_detach
            if self._original_asyncio_handle_run is not None:
                asyncio.events.Handle._run = self._original_asyncio_handle_run
            self._span_metadata_by_thread.clear()
            self._started = False

    def reset_after_fork(self) -> None:
        if self._original_attach is not None:
            context_api.attach = self._original_attach
        if self._original_detach is not None:
            context_api.detach = self._original_detach
        if self._original_asyncio_handle_run is not None:
            asyncio.events.Handle._run = self._original_asyncio_handle_run
        self._lock = RLock()
        self._started = False
        self._span_metadata_by_thread = {}
        self._original_attach = None
        self._original_detach = None
        self._original_asyncio_handle_run = None

    def span_context_for_thread(self, thread_id: int) -> SpanContext:
        with self._lock:
            metadata = self._span_metadata_by_thread.get(thread_id)
            if metadata is not None:
                return metadata.span_context
        return INVALID_SPAN_CONTEXT

    def span_metadata_for_thread(self, thread_id: int) -> SpanMetadata | None:
        with self._lock:
            return self._span_metadata_by_thread.get(thread_id)

    def _refresh_current_thread(self) -> None:
        self._set_thread_from_otel_context(
            get_ident(), context_api.get_current()
        )

    def _refresh_thread_from_asyncio_handle(
        self, thread_id: int, handle: asyncio.events.Handle
    ) -> None:
        runtime_context_var = getattr(
            _RUNTIME_CONTEXT, "_current_context", None
        )
        handle_context = getattr(handle, "_context", None)
        if runtime_context_var is None or handle_context is None:
            return
        try:
            otel_context = handle_context.get(runtime_context_var)
        except LookupError:
            return
        self._set_thread_from_otel_context(thread_id, otel_context)

    def _set_thread_from_otel_context(
        self, thread_id: int, otel_context
    ) -> None:
        span = get_current_span(context=otel_context)
        span_context = span.get_span_context()
        with self._lock:
            if span_context.is_valid:
                self._span_metadata_by_thread[thread_id] = (
                    self._build_metadata(
                        span, span_context, self._local_root(otel_context)
                    )
                )
            else:
                self._span_metadata_by_thread.pop(thread_id, None)

    def _local_root(self, otel_context: Context | None) -> Span | None:
        span = get_current_span(context=otel_context)
        span_context = span.get_span_context()
        if not span_context.is_valid or span_context.is_remote:
            return None
        root = context_api.get_value(self._root_key, context=otel_context)
        if root is not None:
            root_context = root.get_span_context()
            if (
                root_context.is_valid
                and root_context.trace_id == span_context.trace_id
            ):
                return root
        parent = getattr(span, "parent", None)
        # If collection began inside an existing local child span, its root
        # cannot be reconstructed from SpanContext alone. Keep it unknown
        # instead of mislabelling that child as the root.
        return span if parent is None or parent.is_remote else None

    def _build_metadata(
        self, span: Span, span_context: SpanContext, root: Span | None = None
    ) -> SpanMetadata:
        trace_type_value = None
        kind = getattr(root, "kind", None)
        if kind is not None:
            trace_type_value = kind.name
        trace_endpoint = getattr(root, "name", None)
        instrumentation_scope = getattr(span, "instrumentation_scope", None)
        class_name = (
            instrumentation_scope.name
            if instrumentation_scope is not None
            else getattr(
                getattr(span, "instrumentation_info", None),
                "name",
                None,
            )
        )
        return SpanMetadata(
            span_context=span_context,
            trace_type=trace_type_value,
            trace_endpoint=trace_endpoint,
            class_name=class_name,
            local_root_span_id=(
                root.get_span_context().span_id if root is not None else None
            ),
        )
