from __future__ import annotations

import uuid

import pytest
from beacon_security.frameworks import _asgi
from beacon_security.frameworks._common import _drop_registry, _registry
from beacon_security.patching import Patches
from test_transform_behavior import start_runtime


@pytest.mark.parametrize(
    "method", ["items", "values", "getlist", "get", "__getitem__"]
)
def test_native_header_results_are_the_actual_marked_objects(
    monkeypatch, tmp_path, method: str
) -> None:
    requests = pytest.importorskip("starlette.requests")
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    state.request["transport"] = "asgi"
    _registry(state, create=True)
    patches = Patches()
    _asgi.install(patches, set())
    value = "header-" + uuid.uuid4().hex
    try:
        request = requests.Request(
            {"type": "http", "headers": [(b"x-query", value.encode())]}
        )
        headers = request.headers
        assert state.source_count == 0
        if method == "items":
            native = headers.items()
            assert type(native) is list and type(native[0]) is tuple
            observed = native[0][1]
        elif method == "values":
            native = headers.values()
            assert type(native) is list
            observed = native[0]
        elif method == "getlist":
            native = headers.getlist("x-query")
            assert type(native) is list
            observed = native[0]
        else:
            observed = getattr(headers, method)("x-query")
        assert observed == value
        marks = state.marks(observed)
        assert marks
        assert state.sources[marks[0].source_id]["name"] == "header.x-query"
        runtime.sink("sql_injection", "cursor.execute", "template", observed)
        assert len(state.pending) == 1
    finally:
        patches.restore()
        _drop_registry(state)
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


def test_header_walk_is_bounded_and_does_not_mark_unregistered_carriers(
    monkeypatch, tmp_path
) -> None:
    requests = pytest.importorskip("starlette.requests")
    datastructures = pytest.importorskip("starlette.datastructures")
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    state.request["transport"] = "asgi"
    _registry(state, create=True)
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_MAX_FIELDS", "2")
    patches = Patches()
    _asgi.install(patches, set())
    raw = [
        (f"x-key-{index}".encode(), f"value-{index}-long".encode())
        for index in range(5)
    ]
    try:
        independent = datastructures.Headers(raw=raw)
        assert not any(state.marks(value) for value in independent.values())
        assert state.source_count == 0
        request = requests.Request({"type": "http", "headers": raw})
        first = request.headers.items()
        assert len(first) == 5
        assert state.marks(first[0][1]) and state.marks(first[1][1])
        assert not state.marks(first[2][1])
        assert "framework.field_limit" in state.gaps
        second = request.headers.items()
        assert second[0][1] is not first[0][1]
        assert state.marks(second[0][1]) and state.marks(first[0][1])
    finally:
        patches.restore()
        _drop_registry(state)
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


def test_header_observation_failure_preserves_the_native_result(
    monkeypatch, tmp_path
) -> None:
    requests = pytest.importorskip("starlette.requests")
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    _registry(state, create=True)
    patches = Patches()
    _asgi.install(patches, set())

    def fail(*args, **kwargs):
        raise RuntimeError("observer failed")

    monkeypatch.setattr(_asgi, "source", fail)
    try:
        request = requests.Request(
            {"type": "http", "headers": [(b"x-query", b"business-value")]}
        )
        assert request.headers.items() == [("x-query", "business-value")]
        assert "framework.header_iteration" in state.gaps
    finally:
        patches.restore()
        _drop_registry(state)
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()
