from __future__ import annotations

import asyncio
from threading import Thread, get_ident

import opentelemetry.context as context_api
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    SpanKind,
    TraceFlags,
    set_span_in_context,
)


def test_nested_span_keeps_remote_parent_local_root_and_endpoint() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("request")
    remote = SpanContext(123, 456, is_remote=True, trace_flags=TraceFlags(1))
    parent = set_span_in_context(NonRecordingSpan(remote))
    bridge = ContextBridge()
    bridge.start()
    try:
        with tracer.start_as_current_span(
            "GET", context=parent, kind=SpanKind.SERVER
        ) as root:
            root.update_name("GET /orders/{id}")
            with tracer.start_as_current_span(
                "SELECT", kind=SpanKind.CLIENT
            ) as child:
                metadata = bridge.span_metadata_for_thread(get_ident())
                assert (
                    metadata.span_context.span_id
                    == child.get_span_context().span_id
                )
                assert (
                    metadata.local_root_span_id
                    == root.get_span_context().span_id
                )
                assert metadata.local_root_span_id != remote.span_id
                assert metadata.trace_type == "SERVER"
                assert metadata.trace_endpoint == "GET /orders/{id}"
            metadata = bridge.span_metadata_for_thread(get_ident())
            assert (
                metadata.span_context.span_id
                == root.get_span_context().span_id
            )
        assert bridge.span_metadata_for_thread(get_ident()) is None
    finally:
        bridge.stop()
        provider.shutdown()


def test_local_roots_are_isolated_across_async_tasks_and_copied_threads() -> (
    None
):
    provider = TracerProvider()
    tracer = provider.get_tracer("request")
    bridge = ContextBridge()
    bridge.start()
    observed = []

    async def request(name: str) -> None:
        with tracer.start_as_current_span(
            name, context=context_api.Context(), kind=SpanKind.SERVER
        ) as root:
            with tracer.start_as_current_span(
                "database", kind=SpanKind.CLIENT
            ):
                await asyncio.sleep(0)
                metadata = bridge.span_metadata_for_thread(get_ident())
                assert (
                    metadata.local_root_span_id
                    == root.get_span_context().span_id
                )
                assert metadata.trace_endpoint == name
                copied = context_api.get_current()

                def in_thread() -> None:
                    token = context_api.attach(copied)
                    try:
                        observed.append(
                            bridge.span_metadata_for_thread(get_ident())
                        )
                    finally:
                        context_api.detach(token)

                worker = Thread(target=in_thread)
                worker.start()
                worker.join(timeout=2)
                assert not worker.is_alive()
                assert (
                    observed[-1].local_root_span_id
                    == root.get_span_context().span_id
                )
                assert observed[-1].trace_endpoint == name

    async def exercise() -> None:
        await asyncio.gather(request("first"), request("second"))

    try:
        asyncio.run(exercise())
        assert {value.trace_endpoint for value in observed} == {
            "first",
            "second",
        }
    finally:
        bridge.stop()
        provider.shutdown()


def test_start_inside_existing_child_leaves_unknown_root() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("request")
    with tracer.start_as_current_span("request"):
        with tracer.start_as_current_span("SELECT") as child:
            bridge = ContextBridge()
            bridge.start()
            try:
                metadata = bridge.span_metadata_for_thread(get_ident())
                assert (
                    metadata.span_context.span_id
                    == child.get_span_context().span_id
                )
                assert metadata.local_root_span_id is None
                assert metadata.trace_endpoint is None
            finally:
                bridge.stop()
    provider.shutdown()


def test_new_trace_in_existing_context_gets_its_own_root() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("request")
    bridge = ContextBridge()
    bridge.start()
    try:
        with tracer.start_as_current_span("first") as first:
            with tracer.start_as_current_span(
                "second", context=context_api.Context(), kind=SpanKind.SERVER
            ) as second:
                metadata = bridge.span_metadata_for_thread(get_ident())
                assert (
                    metadata.local_root_span_id
                    == second.get_span_context().span_id
                )
                assert metadata.trace_endpoint == "second"
            assert (
                bridge.span_metadata_for_thread(get_ident()).local_root_span_id
                == first.get_span_context().span_id
            )
    finally:
        bridge.stop()
        provider.shutdown()
