from __future__ import annotations

import asyncio
import importlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from beacon_security.frameworks._asgi import _asgi_call_wrapper
from beacon_security.frameworks._common import (
    HTTP_BODY,
    Session,
    WSGIResult,
    asgi_send_wrapper,
    capture_mapping,
)


def _start_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "none")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    runtime = importlib.import_module("beacon_security.runtime")
    if getattr(runtime, "_runtime", None) is not None:
        runtime.stop()
    runtime = importlib.reload(runtime)
    state = runtime.start_request({"route": "/lifecycle"})
    token = runtime.attach_state(state)
    return runtime, state, token


def test_wsgi_resource_close_runs_once_after_iteration_already_finished(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)

    class Resource:
        def __init__(self):
            self.items = iter((b"first", b"second"))
            self.close_calls = 0

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.items)

        def close(self):
            self.close_calls += 1

    resource = Resource()
    session = Session(state, token=token, owner=True, attached=True)
    result = WSGIResult(resource, session)
    try:
        assert list(result) == [b"first", b"second"]
        assert state.closed

        # WSGI servers commonly call close after consuming the iterator.  It
        # remains an application resource operation even when telemetry ended
        # the request at StopIteration.
        result.close()
        result.close()
        assert resource.close_calls == 1
    finally:
        if not state.closed:
            runtime.end_request(state)
        if runtime.current_state() is state:
            runtime.detach_state(token)


def test_asgi_trailers_delay_close_until_final_trailer_and_background_observes_closed(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    session = Session(state, token=token, owner=True, attached=True)
    sent: list[dict] = []
    background_observations: list[bool] = []

    async def send(message):
        sent.append(dict(message))

    async def exercise():
        wrapped = asgi_send_wrapper(send, session)
        await wrapped(
            {"type": "http.response.start", "status": 200, "trailers": True}
        )
        await wrapped(
            {
                "type": "http.response.body",
                "body": b"final",
                "more_body": False,
            }
        )
        assert not state.closed
        await wrapped(
            {
                "type": "http.response.trailers",
                "headers": [],
                "more_trailers": False,
            }
        )
        background = asyncio.create_task(
            _observe_after_final(state, background_observations)
        )
        await background

    async def _observe_after_final(observed_state, observations):
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        observations.append(observed_state.closed)

    try:
        asyncio.run(exercise())
        assert sent[-1]["type"] == "http.response.trailers"
        assert background_observations == [True]
        assert state.closed
    finally:
        if not state.closed:
            runtime.end_request(state)
        if runtime.current_state() is state:
            runtime.detach_state(token)


def test_stopped_runtime_does_not_respawn_for_retained_asgi_wrapper(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    runtime.detach_state(token)
    runtime.end_request(state)
    runtime.stop()
    assert runtime.start_request({"route": "/after-stop"}) is None

    before = {
        (thread.name, thread.ident)
        for thread in threading.enumerate()
        if thread.name.startswith("BeaconSecurity-")
    }
    sent: list[dict] = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 204})
        await send({"type": "http.response.body", "body": b""})
        return "application-result"

    async def send(message):
        sent.append(dict(message))

    async def exercise():
        wrapped = _asgi_call_wrapper(
            app,
            None,
            (
                {"type": "http", "method": "GET", "path": "/after-stop"},
                lambda: {"type": "http.disconnect"},
                send,
            ),
            {},
        )
        return await wrapped

    result = asyncio.run(exercise())
    after = {
        (thread.name, thread.ident)
        for thread in threading.enumerate()
        if thread.name.startswith("BeaconSecurity-")
    }
    assert result == "application-result"
    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    assert after == before


def test_asgi_cancellation_propagates_original_error_and_cleans_request_context(
    monkeypatch, tmp_path
):
    runtime, initial_state, initial_token = _start_runtime(
        monkeypatch, tmp_path
    )
    runtime.detach_state(initial_token)

    from beacon_security.frameworks import _common

    created: list[object] = []
    start_request = runtime.start_request

    def record_start(metadata=None):
        state = start_request(metadata)
        created.append(state)
        return state

    monkeypatch.setattr(runtime, "start_request", record_start)

    class CancelError(BaseException):
        pass

    cancellation = CancelError("client disconnected")
    started = asyncio.Event()
    hold = asyncio.Event()

    async def app(scope, receive, send):
        runtime.source(
            "cancel-query-" + uuid.uuid4().hex,
            "http.request.parameter",
            "q",
            "asgi.cancel",
        )
        started.set()
        try:
            await hold.wait()
        except asyncio.CancelledError:
            raise cancellation

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        return None

    async def exercise():
        wrapped = _asgi_call_wrapper(
            app,
            None,
            (
                {"type": "http", "method": "GET", "path": "/cancel"},
                receive,
                send,
            ),
            {},
        )
        task = asyncio.create_task(wrapped)
        await started.wait()
        assert created and created[0] is not None
        task.cancel()
        with pytest.raises(CancelError) as raised:
            await task
        assert raised.value is cancellation

    try:
        asyncio.run(exercise())
        request_state = created[0]
        assert request_state.closed
        assert request_state.budget.used == 0
        assert not request_state.objects
        assert not request_state.nodes
        assert not request_state.pending
        assert id(request_state) not in _common._registries
        assert runtime.current_state() is None
    finally:
        if runtime.current_state() is initial_state:
            runtime.detach_state(initial_token)
        if not initial_state.closed:
            runtime.end_request(initial_state)
        runtime.stop()


def test_flask_form_reads_cached_body_twice_without_reconsuming_it(
    monkeypatch, tmp_path
):
    runtime, initial_state, initial_token = _start_runtime(
        monkeypatch, tmp_path
    )
    runtime.detach_state(initial_token)
    runtime.end_request(initial_state)

    from beacon_security import frameworks
    from flask import Flask, request

    frameworks.uninstall()
    try:
        assert "flask" in frameworks.install()
        app = Flask(__name__)

        @app.post("/form")
        def form():
            first = request.form.get("query")
            second = request.form.get("query")
            return {
                "first": first,
                "second": second,
                "mapping_cached": request.form is request.form,
            }

        with app.test_client() as client:
            response = client.post(
                "/form",
                data={"query": "repeat-me"},
                content_type="application/x-www-form-urlencoded",
            )

        assert response.status_code == 200
        assert response.get_json() == {
            "first": "repeat-me",
            "second": "repeat-me",
            "mapping_cached": True,
        }
        assert runtime.current_state() is None
    finally:
        frameworks.uninstall()
        runtime.stop()


def test_framework_capture_aggregates_depth_cycle_and_node_budgets(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)

    deep_leaf: dict[str, object] = {}
    deep_value: dict[str, object] = deep_leaf
    for _ in range(12):
        deep_value = {"next": deep_value}
    deep_payload = {"nested": deep_value}

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    try:
        # The configured field limit is deliberately generous for these two
        # carriers so the depth and active-path checks, rather than a shallow
        # field count, determine the outcome.
        monkeypatch.setenv("BEACON_SECURITY_PYTHON_MAX_FIELDS", "256")
        capture_mapping(deep_payload, HTTP_BODY, "framework-budget", "body")
        capture_mapping(cyclic, HTTP_BODY, "framework-budget", "body")

        # Four nodes are enough to exercise the request-local total traversal
        # budget while every individual mapping remains below max-fields.
        monkeypatch.setenv("BEACON_SECURITY_PYTHON_MAX_FIELDS", "4")
        bounded_tree = {
            "left": {"left": {}, "right": {}},
            "right": {"left": {}, "right": {}},
        }
        capture_mapping(bounded_tree, HTTP_BODY, "framework-budget", "body")

        assert "framework.field_depth" in state.gaps
        assert "framework.field_cycle" in state.gaps
        assert "framework.field_traversal_limit" in state.gaps
        assert deep_payload["nested"] is deep_value
        assert deep_value["next"] is not None
        assert cyclic["self"] is cyclic
        assert bounded_tree["left"]["right"] == {}
        assert bounded_tree["right"]["left"] == {}
    finally:
        if runtime.current_state() is state:
            runtime.detach_state(token)
        if not state.closed:
            runtime.end_request(state)
        runtime.stop()


def test_uvicorn_shutdown_flushes_without_changing_result_or_exception(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    runtime.detach_state(token)
    from beacon_security.frameworks import _uvicorn_shutdown

    flush_calls: list[object] = []

    async def flush():
        flush_calls.append(True)

    monkeypatch.setattr(runtime, "aflush", flush)

    async def successful_shutdown(argument):
        return argument

    class ShutdownError(RuntimeError):
        pass

    shutdown_error = ShutdownError("uvicorn re-raised SIGTERM")

    async def failing_shutdown():
        raise shutdown_error

    try:
        assert (
            asyncio.run(
                _uvicorn_shutdown(
                    successful_shutdown, object(), ("result",), {}
                )
            )
            == "result"
        )
        with pytest.raises(ShutdownError) as raised:
            asyncio.run(_uvicorn_shutdown(failing_shutdown, object(), (), {}))
        assert raised.value is shutdown_error
        assert flush_calls == [True, True]
    finally:
        if not state.closed:
            runtime.end_request(state)
        runtime.stop()


@pytest.mark.parametrize("force_flush_mode", ["false", "raises"])
def test_uvicorn_shutdown_flush_failure_preserves_business_outcome_and_invalidates_run(
    monkeypatch, tmp_path, force_flush_mode
):
    expires_at = (
        (datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z")
    )
    control_path = tmp_path / "control.json"
    control_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "revision": "start-flush-failure-run",
                "paused": False,
                "run": {
                    "run_id": "flush-failure-run",
                    "case_id": "flush-failure-case",
                    "rule": "sql_injection",
                    "expires_at": expires_at,
                    "conditions": {
                        "suite": "lifecycle",
                        "fixture": "flush-failure",
                        "expected_requests": 1,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BEACON_SECURITY_CONTROL_FILE", str(control_path))
    runtime, initial_state, initial_token = _start_runtime(
        monkeypatch, tmp_path
    )
    runtime.detach_state(initial_token)
    runtime.end_request(initial_state)
    ledger = runtime.get_runtime().exporter.ledger
    ledger.tick({}, lambda _event: None, force=True)

    request_state = runtime.start_request({"route": "/flush-failure"})
    assert request_state is not None
    request_token = runtime.attach_state(request_state)
    try:
        runtime.source(
            "flush-failure-query",
            "http.request.parameter",
            "q",
            "lifecycle.flush_failure",
        )
        runtime.sink(
            "sql_injection",
            "sqlite3.Connection.execute",
            "query",
            "SELECT value FROM items WHERE id = ?",
            marks=(),
            location="lifecycle.flush_failure",
        )
    finally:
        runtime.detach_state(request_token)
        runtime.end_request(request_state)

    control_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "revision": "stop-flush-failure-run",
                "paused": False,
                "run": None,
            }
        ),
        encoding="utf-8",
    )
    ledger.tick({}, lambda _event: None, force=True)

    run_snapshot = json.loads(
        (tmp_path / "runs.json").read_text(encoding="utf-8")
    )
    run = next(
        item
        for item in run_snapshot["runs"]
        if item["run_id"] == "flush-failure-run"
    )
    # The request has a source and a sink attempt, but the sink receives a
    # fixed parameterized template with no marks.  In the run schema,
    # observations/finding_counts are the matched-findings representation.
    assert run["observations"] == 0
    assert run["finding_counts"] == {}
    assert run["delivery_loss"] == 0
    assert run["incomplete_requests"] == 0

    from beacon_security.frameworks import _uvicorn_shutdown

    import opentelemetry._logs as otel_logs

    class Provider:
        def force_flush(self, timeout_millis):
            if force_flush_mode == "raises":
                raise RuntimeError("forced log flush failure")
            return False

    monkeypatch.setattr(otel_logs, "get_logger_provider", lambda: Provider())
    result = object()

    async def successful_shutdown(*args, **kwargs):
        return result

    class ApplicationError(RuntimeError):
        pass

    application_error = ApplicationError("application shutdown failure")

    async def failing_shutdown(*args, **kwargs):
        raise application_error

    try:
        assert (
            asyncio.run(
                _uvicorn_shutdown(successful_shutdown, object(), (), {})
            )
            is result
        )
        with pytest.raises(ApplicationError) as raised:
            asyncio.run(_uvicorn_shutdown(failing_shutdown, object(), (), {}))
        assert raised.value is application_error

        run_snapshot = json.loads(
            (tmp_path / "runs.json").read_text(encoding="utf-8")
        )
        run = next(
            item
            for item in run_snapshot["runs"]
            if item["run_id"] == "flush-failure-run"
        )
        assert run["status"] == "closed"
        assert run["delivery_loss"] >= 1
        assert run["incomplete_requests"] >= 1
        health = json.loads(
            (tmp_path / "health.json").read_text(encoding="utf-8")
        )
        assert health["delivery_loss"] >= 1
        assert health["status"] == "incomplete"
    finally:
        if not request_state.closed:
            runtime.end_request(request_state)
        if not initial_state.closed:
            runtime.end_request(initial_state)
        runtime.stop()


def test_async_flush_keeps_event_loop_running_when_shared_provider_stalls(
    monkeypatch, tmp_path
):
    import time

    import opentelemetry._logs as otel_logs

    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    runtime.detach_state(token)
    runtime.end_request(state)
    entered, release = threading.Event(), threading.Event()

    class Provider:
        def force_flush(self, timeout_millis):
            entered.set()
            release.wait(5)
            return True

    monkeypatch.setattr(otel_logs, "get_logger_provider", lambda: Provider())
    exporter = runtime.get_runtime().exporter
    try:
        exporter.start_flush(time.monotonic() + 1)
        assert entered.wait(2)
        workers = {
            t.ident
            for t in threading.enumerate()
            if t.name == "BeaconSecurity-flush"
        }

        async def exercise():
            ticks = 0
            task = asyncio.create_task(runtime.aflush(timeout=0.03))
            while not task.done():
                ticks += 1
                await asyncio.sleep(0.002)
            assert await task is False
            assert ticks > 2

        start = time.monotonic()
        asyncio.run(exercise())
        assert time.monotonic() - start < 0.3
        assert {
            t.ident
            for t in threading.enumerate()
            if t.name == "BeaconSecurity-flush"
        }.issubset(workers)
        assert exporter._flush_worker.is_alive()
        assert exporter.ledger.health({})["delivery_loss"] > 0
    finally:
        release.set()
        runtime.stop()
