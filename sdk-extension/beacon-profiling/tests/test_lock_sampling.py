from __future__ import annotations

import asyncio
import threading
from unittest.mock import Mock

import pytest

from opentelemetry.sdk.extension.profiling.collector import lock as locks
from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedFrame,
    CapturedSample,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.extension.profiling.model.pprof_builder import (
    CompatiblePprofProfileBuilder,
)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_short_pairs_share_one_decision_before_stack_and_trace_lookup(
    monkeypatch, asynchronous: bool
) -> None:
    collector_class = (
        locks.AsyncioLockCollector
        if asynchronous
        else locks.ThreadingLockCollector
    )
    bridge = ContextBridge()
    collector = collector_class(
        bridge, sampling_interval=10, min_duration_ns=1000000
    )
    choices = iter([1] * 9 + [0])
    monkeypatch.setattr(
        collector._random, "randrange", lambda maximum: next(choices)
    )
    frame_capture = Mock(
        return_value=(CapturedFrame("business", "app.py", 1),)
    )
    monkeypatch.setattr(locks, "_capture_current_frames", frame_capture)
    metadata = Mock(return_value=None)
    monkeypatch.setattr(bridge, "span_metadata_for_thread", metadata)
    tick = 0

    def clock() -> int:
        nonlocal tick
        tick += 10
        return tick

    monkeypatch.setattr(locks, "monotonic_ns", clock)
    collector.start()
    try:
        if asynchronous:

            async def exercise():
                primitive = asyncio.Lock()
                for _ in range(10):
                    async with primitive:
                        pass

            asyncio.run(exercise())
        else:
            primitive = threading.Lock()
            for _ in range(10):
                with primitive:
                    pass
        samples = collector.capture()
        assert len(samples) == 2
        assert [sample.period for sample in samples] == [10, 10]
        assert [sample.value for sample in samples] == [10, 10]
        assert frame_capture.call_count == metadata.call_count == 2
        assert all(
            any(
                attr.key == "lock.sampling.interval" and attr.value == 10
                for attr in sample.attributes
            )
            for sample in samples
        )
    finally:
        collector.stop()


def test_slow_hold_is_recorded_when_short_acquire_was_not_sampled(
    monkeypatch,
) -> None:
    collector = locks.ThreadingLockCollector(
        ContextBridge(), sampling_interval=100, min_duration_ns=1000000
    )
    monkeypatch.setattr(collector._random, "randrange", lambda maximum: 1)
    ticks = iter((100, 110, 1000110))
    monkeypatch.setattr(locks, "monotonic_ns", lambda: next(ticks))
    collector.start()
    try:
        with threading.Lock():
            pass
        samples = collector.capture()
        assert len(samples) == 1
        assert samples[0].sample_type == "lock.hold.duration"
        assert samples[0].value == 1000000
        assert samples[0].period == 1
    finally:
        collector.stop()


def test_normalized_paths_are_cached_with_a_finite_bound(monkeypatch) -> None:
    collector = locks.ThreadingLockCollector(
        ContextBridge(), sampling_interval=1
    )
    collector.start()
    try:
        primitive = threading.Lock()
        with primitive:
            pass
        realpath = Mock(wraps=locks.os.path.realpath)
        monkeypatch.setattr(locks.os.path, "realpath", realpath)
        for _ in range(10):
            with primitive:
                pass
        assert realpath.call_count == 0
        assert locks._normalize_path.cache_info().maxsize == 4096
    finally:
        collector.stop()


@pytest.mark.parametrize(
    "kind",
    ["lock.acquire.duration", "lock.wait.duration", "lock.hold.duration"],
)
def test_compatible_pprof_exposes_weighted_lock_estimates(kind: str) -> None:
    sample = CapturedSample(
        100, 1, "worker", (), value=7, sample_type=kind, period=10
    )
    values = CompatiblePprofProfileBuilder()._compat_values(sample, 1000)
    offset = 6 if kind == "lock.hold.duration" else 4
    assert values[offset] == 10
    assert values[offset + 1] == 70


def test_default_sampling_and_full_slow_path_are_explicit(monkeypatch) -> None:
    monkeypatch.delenv("OTEL_PROFILING_LOCK_SAMPLING_INTERVAL", raising=False)
    monkeypatch.delenv("OTEL_PROFILING_LOCK_MIN_DURATION_NS", raising=False)
    collector = locks.ThreadingLockCollector(ContextBridge())
    assert collector._sampling_interval == 100
    assert collector._min_duration_ns == 1000000
    collector.start()
    try:
        assert collector.sample_period(1000000) == 1
    finally:
        collector.stop()


@pytest.mark.parametrize("interval,duration", [(0, 1), (-1, 1), (1, -1)])
def test_invalid_sampling_configuration_is_rejected(
    interval: int, duration: int
) -> None:
    with pytest.raises(ValueError):
        locks.ThreadingLockCollector(
            ContextBridge(),
            sampling_interval=interval,
            min_duration_ns=duration,
        )
