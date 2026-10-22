from __future__ import annotations

import os
import uuid

import pytest
from beacon_security.patching import Patches
from beacon_security.sinks.filesystem import _fspath_wrapper
from test_transform_behavior import start_runtime


@pytest.mark.parametrize("binary", [False, True])
def test_identity_fspath_preserves_budget_and_later_sink(
    monkeypatch, tmp_path, binary: bool
) -> None:
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    value = "/tmp/controlled-" + uuid.uuid4().hex
    if binary:
        value = value.encode()
    runtime.source(value, "http.request.parameter", "path")
    marks = state.marks(value)
    assert marks
    before = len(state.nodes)
    patches = Patches()
    patches.wrap(os, "fspath", _fspath_wrapper)
    try:
        for _ in range(state.max_nodes + 1):
            assert os.fspath(value) is value
        assert len(state.nodes) == before
        assert state.marks(value) == marks
        runtime.sink("path_traversal", "open", "read", value)
        assert len(state.pending) == 1
        assert "propagation_node_limit" not in state.gaps
    finally:
        patches.restore()
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


def test_pathlike_to_new_string_still_propagates(
    monkeypatch, tmp_path
) -> None:
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    value = "/tmp/controlled-" + uuid.uuid4().hex
    runtime.source(value, "http.request.parameter", "path")

    class Carrier:
        def __fspath__(self) -> str:
            return value.encode().decode()

    carrier = Carrier()
    state.propagate(carrier, (value,), "pathlike", exact=True)
    before = len(state.nodes)
    patches = Patches()
    patches.wrap(os, "fspath", _fspath_wrapper)
    try:
        result = os.fspath(carrier)
        assert result == value and result is not value
        assert len(state.nodes) == before + 1
        marks = state.marks(result)
        assert marks and all(mark.exact for mark in marks)
        runtime.sink("path_traversal", "open", "read", result)
        assert len(state.pending) == 1
    finally:
        patches.restore()
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()
