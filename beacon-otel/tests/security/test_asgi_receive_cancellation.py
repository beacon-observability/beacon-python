from __future__ import annotations

import asyncio
import uuid

import pytest
from beacon_security.frameworks._common import Session, asgi_receive_wrapper
from test_framework_lifecycle_contract import _start_runtime


@pytest.mark.parametrize("backend", ["asyncio", "trio"])
def test_disconnect_probe_keeps_detection_active(
    monkeypatch, tmp_path, backend: str
) -> None:
    anyio = pytest.importorskip("anyio")
    if backend == "trio":
        pytest.importorskip("trio")
    requests = pytest.importorskip("starlette.requests")
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    session = Session(state, token=token)

    async def receive():
        await anyio.sleep_forever()

    async def exercise() -> None:
        request = requests.Request(
            {"type": "http"},
            receive=asgi_receive_wrapper(receive, session),
        )
        assert await request.is_disconnected() is False
        assert not session.finished
        assert not state.closed
        query = "SELECT " + uuid.uuid4().hex
        runtime.source(query, "http.request.parameter", "q")
        runtime.sink("sql_injection", "cursor.execute", "template", query)
        assert len(state.pending) == 1

    try:
        anyio.run(exercise, backend=backend)
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


def test_receive_timeout_does_not_end_request(monkeypatch, tmp_path) -> None:
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    session = Session(state, token=token)

    async def receive():
        await asyncio.Event().wait()

    async def exercise() -> None:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(
                asgi_receive_wrapper(receive, session)(), timeout=0.01
            )
        assert not state.closed
        assert not session.finished
        assert runtime.current_state() is state

    try:
        asyncio.run(exercise())
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


@pytest.mark.parametrize("failure", [False, True])
def test_actual_disconnect_or_receive_failure_finishes_once(
    monkeypatch, tmp_path, failure: bool
) -> None:
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    session = Session(state, token=token)
    error = OSError("receive failed")
    endings = []
    end_request = runtime.end_request

    def record_end(observed, error=None):
        endings.append(error)
        return end_request(observed, error=error)

    monkeypatch.setattr(runtime, "end_request", record_end)

    async def receive():
        if failure:
            raise error
        return {"type": "http.disconnect"}

    async def exercise() -> None:
        wrapped = asgi_receive_wrapper(receive, session)
        for _ in range(2):
            if failure:
                with pytest.raises(OSError) as raised:
                    await wrapped()
                assert raised.value is error
            else:
                assert await wrapped() == {"type": "http.disconnect"}
        assert state.closed and session.finished
        assert endings == [error if failure else None]

    try:
        asyncio.run(exercise())
    finally:
        runtime.detach_state(token)
        runtime.stop()
