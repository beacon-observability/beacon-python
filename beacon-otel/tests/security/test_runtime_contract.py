from __future__ import annotations

import importlib
import threading
from concurrent.futures import ThreadPoolExecutor

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    TraceState,
)


def load_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "true")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "none")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    runtime = importlib.import_module("beacon_security.runtime")
    if getattr(runtime, "_runtime", None) is not None:
        runtime.stop()
    return importlib.reload(runtime)


def test_request_lifecycle_context_and_suppression(monkeypatch, tmp_path):
    runtime = load_runtime(monkeypatch, tmp_path)
    state = runtime.start_request({"method": "GET", "route": "/contract"})
    query = ("_" + "runtime-query")[1:]
    assert runtime.current_state() is None
    try:
        token = runtime.attach_state(state)
        try:
            assert runtime.current_state() is state
            assert (
                runtime.source(query, "http.request.parameter", "q") is query
            )
            assert runtime.current_state() is state
            with runtime.suppress():
                assert runtime.current_state() is None
                assert (
                    runtime.source(
                        ("_" + "suppressed")[1:], "http.request.parameter", "q"
                    )
                    == "suppressed"
                )
            event = runtime.sink(
                "sql_injection",
                "sqlite3.Connection.execute",
                "query",
                query,
                location="runtime-contract",
            )
            assert event is not None
        finally:
            runtime.detach_state(token)
        assert state.pending
    finally:
        runtime.end_request(state)

    assert state.closed
    assert runtime.current_state() is None


def test_runtime_surface_exposes_owned_components(monkeypatch, tmp_path):
    runtime = load_runtime(monkeypatch, tmp_path)
    components = runtime.get_runtime()
    assert hasattr(components, "exporter")
    assert hasattr(components, "inventory")
    assert hasattr(components, "identity")
    assert hasattr(components, "profile")


def test_live_configuration_changes_gate_active_collection(
    monkeypatch, tmp_path
):
    from beacon_security import config

    runtime = load_runtime(monkeypatch, tmp_path)
    state = runtime.start_request({"route": "/live-config"})
    token = runtime.attach_state(state)
    try:
        assert runtime.current_state() is state
        monkeypatch.setenv(
            "BEACON_SECURITY_PYTHON_INCLUDE", " other_app., other_app, . "
        )
        assert config.included("other_app.handlers")
        assert not config.included("security_sample.handlers")
        monkeypatch.setenv(
            "BEACON_SECURITY_PYTHON_EXCLUDE", "other_app.handlers."
        )
        assert not config.included("other_app.handlers")
        monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "")
        assert runtime.current_state() is None
        monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
        assert runtime.current_state() is state
        monkeypatch.setenv("BEACON_SECURITY_ENABLED", "false")
        assert runtime.current_state() is None
        monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
        assert runtime.current_state() is state
        with monkeypatch.context() as probe:

            def unavailable():
                raise RuntimeError("runtime probe unavailable")

            probe.setattr(config, "supported_runtime", unavailable)
            assert runtime.current_state() is None
        assert runtime.current_state() is state
    finally:
        runtime.detach_state(token)
        runtime.end_request(state)
        runtime.stop()


def test_thread_isolation_and_error_close(monkeypatch, tmp_path):
    runtime = load_runtime(monkeypatch, tmp_path)
    observed: list[tuple[object, object]] = []
    errors: list[BaseException] = []

    def worker(index: int):
        state = runtime.start_request({"route": f"/thread/{index}"})
        query = ("_" + f"thread-{index}")[1:]
        token = runtime.attach_state(state)
        try:
            runtime.source(query, "http.request.parameter", "q")
            observed.append((state, runtime.current_state()))
            if index == 1:
                raise RuntimeError("application failure")
        except BaseException as error:
            errors.append(error)
            runtime.end_request(state, error=error)
        else:
            runtime.end_request(state)
        finally:
            runtime.detach_state(token)

    threads = [
        threading.Thread(target=worker, args=(index,)) for index in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(observed) == 3
    assert all(state is current for state, current in observed)
    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)
    assert all(state.closed for state, _ in observed)
    assert runtime.current_state() is None


def test_fresh_otel_context_and_included_executor_preserve_then_clear_request(
    monkeypatch, tmp_path
):
    runtime = load_runtime(monkeypatch, tmp_path)
    state = runtime.start_request({"route": "/context-boundary"})
    token = runtime.attach_state(state)

    # A server may replace the entire OTel Context while retaining the active
    # request.  The remote span must not erase the local request lifetime.
    remote_context = SpanContext(
        trace_id=0x1234567890ABCDEF1234567890ABCDEF,
        span_id=0x1234567890ABCDEF,
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
        trace_state=TraceState(),
    )
    replaced = trace.set_span_in_context(
        NonRecordingSpan(remote_context), otel_context.Context()
    )
    replacement_token = otel_context.attach(replaced)
    try:
        assert runtime.current_state() is state
        assert trace.get_current_span().get_span_context() == remote_context
    finally:
        otel_context.detach(replacement_token)

    # Compile an included application function so the submit call passes
    # through the same AST call boundary as a real instrumented module.  The
    # OTel threading instrumentor carries the request context into the worker.
    from beacon_security.transform import transform

    from opentelemetry.instrumentation.threading import ThreadingInstrumentor

    namespace = {
        "__name__": "security_sample.context_fixture",
        "runtime": runtime,
    }
    source = """
def submit_and_read(executor):
    def worker():
        return runtime.current_state()
    return executor.submit(worker).result()
"""
    tree = transform(source, "context_fixture.py", namespace["__name__"])
    exec(compile(tree, "context_fixture.py", "exec"), namespace)

    instrumentor = ThreadingInstrumentor()
    instrumentor.instrument()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            assert namespace["submit_and_read"](executor) is state

            # End the request before reusing the executor.  A completed
            # background callback must not leave this state in its worker.
            runtime.end_request(state)
            runtime.detach_state(token)
            assert runtime.current_state() is None
            assert (
                executor.submit(lambda: runtime.current_state()).result()
                is None
            )
    finally:
        if instrumentor.is_instrumented_by_opentelemetry:
            instrumentor.uninstrument()
        if not state.closed:
            runtime.end_request(state)
        if runtime.current_state() is state:
            runtime.detach_state(token)


def test_sampling_keeps_evidence_and_existing_span_attributes_without_provider_replacement(
    monkeypatch, tmp_path
):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
    from opentelemetry.sdk.trace.sampling import (
        Decision,
        Sampler,
        SamplingResult,
    )

    class MixedSampler(Sampler):
        def should_sample(
            self, parent_context, trace_id, name, *args, **kwargs
        ):
            if name == "sampled-away-server":
                return SamplingResult(Decision.DROP)
            return SamplingResult(Decision.RECORD_AND_SAMPLE)

        def get_description(self):
            return "qa-mixed-sampler"

    span_exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=MixedSampler(), shutdown_on_exit=False)
    provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider)
    evidence_file = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("BEACON_SECURITY_EVIDENCE_FILE", str(evidence_file))
    runtime = load_runtime(monkeypatch, tmp_path)
    assert trace.get_tracer_provider() is provider
    tracer = provider.get_tracer("beacon-security-qa")
    try:
        from beacon_security.frameworks._common import bind_server_span

        sampled_state = runtime.start_request({"route": "/always-off"})
        sampled_token = runtime.attach_state(sampled_state)
        with tracer.start_as_current_span("sampled-away-server") as span:
            assert span.is_recording() is False
            bind_server_span(sampled_state)
            assert sampled_state.server_span is span
            value = "always-off-query"
            runtime.source(value, "http.request.parameter", "q")
            event = runtime.sink(
                "sql_injection",
                "sqlite3.Connection.execute",
                "template",
                value,
                marks=sampled_state.marks(value),
                location="always-off",
            )
            assert event is not None
        runtime.end_request(sampled_state)
        runtime.detach_state(sampled_token)

        recorded_state = runtime.start_request({"route": "/recorded"})
        recorded_token = runtime.attach_state(recorded_state)
        with tracer.start_as_current_span("recorded-server") as recorded_span:
            bind_server_span(recorded_state)
            value = "recorded-query"
            runtime.source(value, "http.request.parameter", "q")
            assert (
                runtime.sink(
                    "sql_injection",
                    "sqlite3.Connection.execute",
                    "template",
                    value,
                    marks=recorded_state.marks(value),
                    location="recorded",
                )
                is not None
            )
            runtime.end_request(recorded_state)
            assert recorded_span.is_recording() is True
            assert recorded_span.attributes["beacon.security.detected"] is True
            assert (
                recorded_span.attributes["beacon.security.finding_count"] == 1
            )
            assert recorded_span.attributes["beacon.security.finding.ids"]
        runtime.detach_state(recorded_token)

        assert trace.get_tracer_provider() is provider
        assert runtime.get_runtime().exporter.flush(timeout=5.0)
        records = [
            line
            for line in evidence_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert any(
            '"event_name":"beacon.security.finding"' in line
            for line in records
        )
        assert all(
            "always-off-query" not in line and "recorded-query" not in line
            for line in records
        )
    finally:
        if runtime.current_state() is not None:
            runtime.end_request(runtime.current_state())
        runtime.stop()
        provider.shutdown()


def test_one_hundred_concurrent_requests_keep_state_and_sources_isolated(
    monkeypatch, tmp_path
):
    runtime = load_runtime(monkeypatch, tmp_path)
    barrier = threading.Barrier(100, timeout=10)
    observations: list[tuple[int, object, object, int]] = []
    errors: list[BaseException] = []
    observation_lock = threading.Lock()

    def worker(index: int):
        state = runtime.start_request({"route": f"/concurrent/{index}"})
        token = runtime.attach_state(state)
        try:
            barrier.wait()
            value = f"concurrent-query-{index}"
            runtime.source(value, "http.request.parameter", "q")
            with observation_lock:
                observations.append(
                    (index, state, runtime.current_state(), state.source_count)
                )
        except BaseException as error:
            with observation_lock:
                errors.append(error)
        finally:
            runtime.end_request(state)
            runtime.detach_state(token)

    threads = [
        threading.Thread(target=worker, args=(index,)) for index in range(100)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert not errors
    assert len(observations) == 100
    assert len({id(state) for _, state, _, _ in observations}) == 100
    assert all(state is current for _, state, current, _ in observations)
    assert all(source_count == 1 for _, _, _, source_count in observations)
    assert all(state.closed for _, state, _, _ in observations)
    assert runtime.current_state() is None
