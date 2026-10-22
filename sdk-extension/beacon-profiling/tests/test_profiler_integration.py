from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from time import sleep

from opentelemetry.proto.collector.profiles.v1development.profiles_service_pb2 import (
    ExportProfilesServiceRequest,
)
from opentelemetry.sdk.extension.profiling.collector.exception import (
    HAS_MONITORING,
)
from opentelemetry.sdk.extension.profiling.export.http import (
    OTLPHTTPProfileExporter,
)
from opentelemetry.sdk.extension.profiling.runtime import Profiler
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider


def test_profiler_exports_multiple_profile_types_end_to_end(monkeypatch):
    # This test requires every type in every run; sampling distribution and
    # weighting are checked separately in test_lock_sampling.py.
    monkeypatch.setenv("OTEL_PROFILING_LOCK_SAMPLING_INTERVAL", "1")
    received = {}
    ready = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers["Content-Length"])
            body = self.rfile.read(content_length)
            received["path"] = self.path
            received["request"] = ExportProfilesServiceRequest.FromString(body)
            self.send_response(200)
            self.end_headers()
            ready.set()

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    stack_started = Event()
    stack_release = Event()
    lock_ready = Event()
    stack_span_context = {}
    tracer = TracerProvider().get_tracer("test")

    exporter = OTLPHTTPProfileExporter(
        endpoint=(
            f"http://127.0.0.1:{server.server_address[1]}"
            "/v1development/profiles"
        )
    )
    profiler = Profiler(
        exporter=exporter,
        resource=Resource.create(
            {
                "service.name": "svc",
                "service.version": "1.0.0",
            }
        ),
        sample_interval=3600.0,
        export_interval=3600.0,
        max_frames=32,
        exception_enabled=True,
        exception_sampling_interval=1,
        exception_collect_message=True,
        lock_enabled=True,
        memory_enabled=True,
        memory_interval=0.0,
        memory_top_stats=100,
    )

    def stack_worker() -> None:
        with tracer.start_as_current_span("stack-span") as span:
            stack_span_context["span_context"] = span.get_span_context()
            stack_started.set()
            while not stack_release.is_set():
                pass

    profiler.start()
    stack_thread = Thread(target=stack_worker, name="profile-stack-worker")
    stack_thread.start()

    holder_thread = None
    notifier_thread = None
    allocations = None
    try:
        assert stack_started.wait(timeout=5)

        lock = threading.Lock()
        condition = threading.Condition()

        def holder() -> None:
            lock.acquire()
            try:
                lock_ready.set()
                sleep(0.05)
            finally:
                lock.release()

        holder_thread = Thread(target=holder, name="profile-lock-holder")
        holder_thread.start()
        assert lock_ready.wait(timeout=1)

        condition_waiting = Event()

        def notifier() -> None:
            assert condition_waiting.wait(timeout=1)
            with condition:
                sleep(0.02)
                condition.notify()

        with tracer.start_as_current_span("main-span") as span:
            try:
                raise ValueError("boom")
            except ValueError:
                pass

            allocations = [("x" * 2048) + str(index) for index in range(512)]

            lock.acquire()
            try:
                sleep(0.01)
            finally:
                lock.release()

            with condition:
                notifier_thread = Thread(
                    target=notifier,
                    name="profile-condition-notifier",
                )
                notifier_thread.start()
                condition_waiting.set()
                condition.wait(timeout=1)

            main_span_context = span.get_span_context()

        for _ in range(3):
            profiler.capture_once()
            sleep(0.01)

        profiler.force_flush()
        assert ready.wait(timeout=5)
    finally:
        stack_release.set()
        stack_thread.join(timeout=5)
        if holder_thread is not None:
            holder_thread.join(timeout=5)
        if notifier_thread is not None:
            notifier_thread.join(timeout=5)
        profiler.stop(flush=False)
        server.shutdown()
        server_thread.join(timeout=5)
        server.server_close()

    assert allocations is not None
    assert received["path"] == "/v1development/profiles"

    request = received["request"]
    assert len(request.resource_profiles) == 1
    resource_profiles = request.resource_profiles[0]
    assert len(resource_profiles.scope_profiles) == 1
    profiles = resource_profiles.scope_profiles[0].profiles

    string_table = request.dictionary.string_table
    profile_types = {
        string_table[profile.sample_type.type_strindex] for profile in profiles
    }

    expected_types = {
        "samples",
        "lock.acquire.duration",
        "lock.hold.duration",
        "lock.wait.duration",
        "memory.heap.bytes",
        "memory.heap.objects",
    }
    if HAS_MONITORING:
        expected_types.add("exceptions")
        assert "exception.message" in string_table
    assert profile_types.issuperset(expected_types)
    assert "memory.heap.bytes" in string_table
    assert "memory.heap.objects" in string_table
    assert "test_profiler_integration.py:" in " ".join(string_table)

    attribute_strings = {
        attribute.value.string_value
        for attribute in request.dictionary.attribute_table
        if attribute.value.HasField("string_value")
    }
    if HAS_MONITORING:
        assert "boom" in attribute_strings
    assert "threading.Lock" in attribute_strings
    assert "threading.Condition" in attribute_strings
    assert "process" in attribute_strings
    assert "heap" in attribute_strings
    assert "tracemalloc" in attribute_strings

    link_pairs = {
        (link.trace_id, link.span_id) for link in request.dictionary.link_table
    }
    assert len(link_pairs) >= 3
    assert any(
        link.trace_id == main_span_context.trace_id.to_bytes(16, "big")
        and link.span_id == main_span_context.span_id.to_bytes(8, "big")
        for link in request.dictionary.link_table
    )
    assert any(
        link.trace_id
        == stack_span_context["span_context"].trace_id.to_bytes(16, "big")
        and link.span_id
        == stack_span_context["span_context"].span_id.to_bytes(8, "big")
        for link in request.dictionary.link_table
    )
