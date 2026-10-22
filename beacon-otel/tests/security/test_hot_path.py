from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from beacon_security import ast_hooks, config, propagation, runtime
from test_transform_behavior import execute_transformed, start_runtime


def test_current_state_uses_startup_gate_and_dynamic_pause_run(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "true")
    current, state, token = start_runtime(monkeypatch, tmp_path)
    ledger = current._runtime.exporter.ledger
    try:
        with monkeypatch.context() as patch:
            owner = threading.get_ident()

            def off_thread_only(function):
                def guarded(*args, **kwargs):
                    if threading.get_ident() == owner:
                        raise AssertionError("hot path probed configuration")
                    return function(*args, **kwargs)

                return guarded

            patch.setattr(config, "text", off_thread_only(config.text))
            patch.setattr(
                config,
                "supported_runtime",
                off_thread_only(config.supported_runtime),
            )
            for _ in range(1000):
                assert runtime.current_state() is state
                assert ledger.enabled()
        for revision, paused in (("paused", True), ("resumed", False)):
            ledger.control.write_text(
                json.dumps({"revision": revision, "paused": paused})
            )
            ledger.tick({}, lambda event: None, force=True)
            assert ledger.enabled() is not paused
            assert (runtime.current_state() is state) is not paused
        run = {
            "run_id": "hot-path-run",
            "case_id": "hot-path",
            "rule": "sql_injection",
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
            "conditions": {
                "suite": "regression",
                "fixture": "hot-path",
                "expected_requests": 1,
            },
        }
        ledger.control.write_text(json.dumps({"revision": "run", "run": run}))
        ledger.tick({}, lambda event: None, force=True)
        new_state = runtime.start_request({"route": "/new"})
        try:
            assert new_state.run["run_id"] == run["run_id"]
        finally:
            runtime.end_request(new_state)
        # Environment configuration belongs to this runtime's startup snapshot.
        monkeypatch.setenv("BEACON_SECURITY_ENABLED", "false")
        assert ledger.enabled()
        from beacon_security.ledger import RuntimeLedger

        fresh = RuntimeLedger({}, "fresh", tmp_path / "fresh")
        assert not fresh.enabled()
    finally:
        current.end_request(state)
        current.detach_state(token)


def test_no_request_dispatch_returns_original_without_partial(monkeypatch):
    from functools import partial

    calls = []

    def callback(value):
        calls.append(value)
        return value

    with runtime.suppress():
        for function in (callback, partial(callback, 7), len):
            for awaited in (False, True):
                assert (
                    ast_hooks.call_target(function, "fixture", awaited)
                    is function
                )
        fixture = execute_transformed(
            """
def ordered(factory, argument):
    return factory()(argument())
""",
            runtime,
        )

        def factory():
            calls.append("function")
            return callback

        def argument():
            calls.append("argument")
            return 42

        assert fixture["ordered"](factory, argument) == 42
    assert calls == ["function", "argument", 42]


def test_clean_calls_skip_argument_scan_without_skipping_sink_hooks(
    monkeypatch, tmp_path
):
    from beacon_security import sinks

    current, state, token = start_runtime(monkeypatch, tmp_path)
    try:
        marks = Mock(wraps=state.marks)
        monkeypatch.setattr(state, "marks", marks)
        before = Mock(return_value=None)
        monkeypatch.setattr(sinks, "call_before", before)
        payload = {str(i): [i] for i in range(512)}

        def clean(value):
            return 42

        for _ in range(100):
            assert ast_hooks.call_target(clean, "fixture")(payload) == 42
        marks.assert_not_called()
        assert before.call_count == 100
        value = "".join(("controlled", "-value"))
        state.source(value, "http.request.parameter", "q")
        assert propagation.input_marks(state, ({"q": value},))
        propagation.input_marks(state, ({str(i): i for i in range(200)},))
        assert "call_container_limit" in state.gaps
    finally:
        current.end_request(state)
        current.detach_state(token)


def test_join_discovers_sources_lazily_and_keeps_contexts_separate(
    monkeypatch, tmp_path
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    try:
        fixture = execute_transformed(
            """
def joined(parts):
    return "|".join(parts)
async def inspect_context():
    import asyncio
    await asyncio.sleep(0)
    return runtime.current_state()
""",
            runtime,
        )

        def parts():
            value = "".join(("lazy", "-source"))
            state.source(value, "http.request.parameter", "q")
            yield value

        assert not state.objects
        result = fixture["joined"](parts())
        assert result == "lazy-source" and state.marks(result)

        async def check():
            async def without_state():
                with runtime.suppress():
                    return await fixture["inspect_context"]()

            return await asyncio.gather(
                fixture["inspect_context"](), without_state()
            )

        assert asyncio.run(check()) == [state, None]
    finally:
        current.end_request(state)
        current.detach_state(token)
