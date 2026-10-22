from __future__ import annotations

import asyncio
import json
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from beacon_security import ast_hooks
from beacon_security.frameworks import _asgi
from beacon_security.frameworks._common import (
    _drop_registry,
    _registry,
    asgi_receive_wrapper,
)
from beacon_security.patching import Patches
from beacon_security.state import SecurityState
from beacon_security.tracking import ByteBudget
from test_transform_behavior import start_runtime


def test_raw_body_cannot_exhaust_parsed_json_field_budget() -> None:
    body = json.dumps(
        {"payload": "x" * 530000, "id": "id-" + uuid.uuid4().hex}
    ).encode()
    parsed = json.loads(body)
    state = SecurityState()
    try:
        state.capture(body, "http.request.body", "body")
        state.capture(parsed, "http.request.body", "body")
        assert not state.marks(body)
        assert state.marks(parsed["payload"]) and state.marks(parsed["id"])
        assert "raw_body_buffer_budget" in state.gaps
        assert not state.tracking_exhausted
        assert not state.truncated
        assert state.retained_bytes <= state.max_bytes
    finally:
        state.close()


@pytest.mark.parametrize("chunk_size", [100000, 600000])
def test_actual_asgi_json_buffers_leave_business_detection_active(
    monkeypatch, tmp_path, chunk_size: int
) -> None:
    requests = pytest.importorskip("starlette.requests")
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    _registry(state, create=True)
    patches = Patches()
    _asgi.install(patches, set())
    body = json.dumps({"payload": "x" * 530000, "id": "1 OR 1=1"}).encode()
    chunks = [
        body[index : index + chunk_size]
        for index in range(0, len(body), chunk_size)
    ]
    index = 0

    async def receive():
        nonlocal index
        chunk = chunks[index]
        index += 1
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(chunks),
        }

    async def exercise() -> None:
        request = requests.Request(
            {"type": "http", "headers": []},
            receive=asgi_receive_wrapper(receive),
        )
        parsed = await request.json()
        assert state.marks(parsed["id"])
        retained = state.retained_bytes
        assert await request.json() is parsed
        assert state.retained_bytes == retained
        query = ast_hooks.binary(
            "SELECT * FROM t WHERE id=", parsed["id"], "Add", "body-test"
        )
        runtime.sink("sql_injection", "cursor.execute", "template", query)
        assert state.pending[0]["attack_evidence"]["status"] == "suspected"
        assert not state.tracking_exhausted
        assert state._body_buffer_bytes <= state.max_body_buffer_bytes
        assert state.retained_bytes <= state.max_bytes
        assert "raw_body_buffer_budget" in state.gaps

    try:
        asyncio.run(exercise())
    finally:
        patches.restore()
        _drop_registry(state)
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


def test_raw_buffers_are_charged_once_and_released_with_request() -> None:
    state = SecurityState()
    body = ("body-" + uuid.uuid4().hex).encode()
    for _ in range(3):
        state.capture(body, "http.request.body", "body")
    assert len(state._body_buffer_objects) == 1
    assert state._body_buffer_bytes == state.retained_bytes
    assert state.marks(body)
    state.put(body, ())
    assert state._body_buffer_bytes == 0
    assert not state._body_buffer_objects
    state.close()
    assert state.budget.used == 0


def test_many_tiny_chunks_leave_object_capacity_for_fields(
    monkeypatch,
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_MAX_OBJECTS", "16")
    state = SecurityState()
    try:
        for index in range(16):
            state.capture(
                f"chunk-{index}-value".encode(), "http.request.body", "body"
            )
        assert len(state._body_buffer_objects) == 4
        field = "business-" + uuid.uuid4().hex
        state.capture({"id": field}, "http.request.body", "body")
        assert state.marks(field)
        assert not state.tracking_exhausted
    finally:
        state.close()


def test_concurrent_body_reservations_keep_process_limit(monkeypatch) -> None:
    monkeypatch.setenv("BEACON_SECURITY_MAX_TRACKED_BYTES", "1024")
    budget = ByteBudget()
    budget.maximum = 4096

    def capture(index: int):
        state = SecurityState(budget=budget)
        state.capture(
            ("buffer-" + str(index) * 80).encode(), "http.request.body", "body"
        )
        state.capture(
            {"field": "v" * 350 + str(index)}, "http.request.body", "body"
        )
        return state

    with ThreadPoolExecutor(max_workers=4) as executor:
        states = list(executor.map(capture, range(12)))
    try:
        assert budget.used <= budget.maximum
        assert any(state.tracking_exhausted for state in states)
        assert all(state.retained_bytes <= state.max_bytes for state in states)
    finally:
        for state in states:
            state.close()
    assert budget.used == 0
