from __future__ import annotations

import asyncio
import threading

import pytest

import opentelemetry.context as context_api
from opentelemetry.sdk.extension.profiling.collector.lock import (
    ThreadingLockCollector,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.extension.profiling.runtime import Profiler


def test_retained_proxy_does_not_record_after_stop_or_retain_buffer() -> None:
    collector = ThreadingLockCollector(ContextBridge(), sampling_interval=1)
    original = threading.Lock
    collector.start()
    lock = threading.Lock()
    with lock:
        pass
    collector.stop()
    assert threading.Lock is original
    assert collector.capture() == []
    for _ in range(100):
        with lock:
            pass
    assert collector.capture() == []
    collector.start()
    try:
        with lock:
            pass
        assert len(collector.capture()) == 2
    finally:
        collector.stop()


def test_stop_discards_an_append_in_progress(monkeypatch) -> None:
    collector = ThreadingLockCollector(ContextBridge(), sampling_interval=1)
    collector.start()
    lock = threading.Lock()
    original = collector._context_bridge.span_metadata_for_thread

    def stop_while_building_sample(thread_id):
        collector.stop()
        return original(thread_id)

    monkeypatch.setattr(
        collector._context_bridge,
        "span_metadata_for_thread",
        stop_while_building_sample,
    )
    try:
        with lock:
            pass
        assert collector.capture() == []
    finally:
        collector.stop()


def test_inflight_acquire_cannot_record_into_restarted_session(
    monkeypatch,
) -> None:
    collector = ThreadingLockCollector(ContextBridge(), sampling_interval=1)
    collector.start()
    lock = threading.Lock()
    metadata = collector._context_bridge.span_metadata_for_thread
    restarted = False

    def restart(thread_id):
        nonlocal restarted
        if not restarted:
            restarted = True
            collector.stop()
            collector.start()
        return metadata(thread_id)

    monkeypatch.setattr(
        collector._context_bridge, "span_metadata_for_thread", restart
    )
    try:
        with lock:
            pass
        assert collector.capture() == []
        with lock:
            pass
        assert len(collector.capture()) == 2
    finally:
        collector.stop()


class _Exporter:
    def __init__(self) -> None:
        self.closed = False

    def export(self, payload) -> None:
        pass

    def shutdown(self) -> None:
        self.closed = True


@pytest.mark.parametrize("stage", ["flush", "join", "shutdown"])
def test_failed_stop_restores_hooks_and_releases_active_instance(
    monkeypatch, stage: str
) -> None:
    exporter = _Exporter()
    profiler = Profiler(
        exporter=exporter,
        lock_enabled=True,
        memory_enabled=False,
        sample_interval=3600,
    )
    attach = context_api.attach
    handle_run = asyncio.events.Handle._run
    original_lock = threading.Lock
    error = RuntimeError("stop stage failed")
    profiler.start()

    def fail() -> None:
        raise error

    if stage == "flush":
        monkeypatch.setattr(profiler, "flush", fail)
    elif stage == "join":
        join = profiler._scheduler.join

        def join_and_fail() -> None:
            join()
            fail()

        monkeypatch.setattr(profiler._scheduler, "join", join_and_fail)
    else:
        monkeypatch.setattr(exporter, "shutdown", fail)
    with pytest.raises(RuntimeError) as raised:
        profiler.stop()
    assert raised.value is error
    assert not profiler._started
    assert Profiler._active_instance is None
    assert context_api.attach is attach
    assert asyncio.events.Handle._run is handle_run
    assert threading.Lock is original_lock
    assert profiler._active_collectors == []
    assert not profiler._atexit_registered
    if stage != "shutdown":
        assert exporter.closed
    profiler.stop()
    # A failed flush must not prevent a new profiler from taking ownership.
    replacement = Profiler(exporter=_Exporter(), sample_interval=3600)
    try:
        replacement.start()
        assert replacement._started
    finally:
        replacement.stop(flush=False)
