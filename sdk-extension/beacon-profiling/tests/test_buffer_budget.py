from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedAttribute,
    CapturedSample,
    captured_frame,
)
from opentelemetry.sdk.extension.profiling.collector.buffering import (
    SampleBudget,
    SampleBuffer,
    internal_work,
    suppress_collection,
)
from opentelemetry.sdk.extension.profiling.collector.exception import (
    HAS_MONITORING,
    ExceptionCollector,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.extension.profiling.runtime import Profiler


def _sample(index: int = 0, attributes=()) -> CapturedSample:
    return CapturedSample(
        100 + index,
        1,
        "worker",
        (captured_frame("business", "app.py", 42),),
        trace_id=123,
        span_id=456,
        cpu_time_ns=7 + index,
        attributes=attributes,
    )


def test_one_budget_caps_all_producer_buffers_and_releases_on_drain() -> None:
    budget = SampleBudget(max_samples=2, max_bytes=16384)
    first, second = SampleBuffer(budget), SampleBuffer(budget)
    a, b = _sample(), _sample(1)
    first.append(a)
    second.append(b)
    second.append(_sample(2))
    assert budget.snapshot()["used_samples"] == 2
    assert budget.snapshot()["dropped_samples"] == 1
    assert budget.snapshot()["used_bytes"] <= 16384
    assert first.drain() == [a]
    assert second.drain() == [b]
    assert budget.snapshot()["used_bytes"] == 0
    assert budget.snapshot()["used_samples"] == 0
    assert a.timestamp_unix_nano == 100 and b.cpu_time_ns == 8
    assert a.span_id == b.span_id == 456


def test_byte_limit_and_unsupported_metadata_do_not_call_user_size_hooks() -> (
    None
):
    class Unsafe:
        def __sizeof__(self):
            pytest.fail("must not run user hooks")

    budget = SampleBudget(max_samples=100, max_bytes=16384)
    buffer = SampleBuffer(budget)
    buffer.append(
        _sample(attributes=(CapturedAttribute("huge", "x" * 20000),))
    )
    buffer.append(_sample(attributes=(CapturedAttribute("unsafe", Unsafe()),)))
    buffer.append(_sample())
    assert len(buffer) == 1
    assert budget.snapshot()["dropped_samples"] == 2
    buffer.clear()
    assert budget.snapshot()["used_bytes"] == 0


def test_local_capture_error_releases_already_buffered_samples() -> None:
    budget = SampleBudget(max_samples=10, max_bytes=16384)
    with pytest.raises(RuntimeError), SampleBuffer(budget) as buffer:
        buffer.append(_sample())
        raise RuntimeError("capture failed")
    assert budget.snapshot()["used_samples"] == 0


def test_concurrent_buffers_share_one_atomic_limit() -> None:
    budget = SampleBudget(max_samples=50, max_bytes=65536)

    def produce(index: int):
        buffer = SampleBuffer(budget)
        for offset in range(100):
            buffer.append(_sample(index * 100 + offset))
        return buffer

    with ThreadPoolExecutor(max_workers=4) as executor:
        buffers = list(executor.map(produce, range(4)))
    snapshot = budget.snapshot()
    assert sum(len(buffer) for buffer in buffers) <= 50
    assert snapshot["used_bytes"] <= 65536
    assert snapshot["used_samples"] + snapshot["dropped_samples"] == 400
    for buffer in buffers:
        buffer.clear()
    assert budget.snapshot()["used_bytes"] == 0


class _Exporter:
    def __init__(self) -> None:
        self.requests = []

    def export(self, payload) -> None:
        self.requests.append(payload)

    def shutdown(self) -> None:
        pass


def test_profiler_drops_are_visible_and_next_window_recovers(caplog) -> None:
    exporter = _Exporter()
    profiler = Profiler(
        exporter=exporter, max_buffer_samples=2, max_buffer_bytes=16384
    )

    class Collector:
        def capture(self):
            assert internal_work()
            return [_sample(index) for index in range(4)]

    profiler._capture_collectors([Collector()])
    assert profiler.buffer_statistics["used_samples"] == 2
    assert profiler.buffer_statistics["dropped_samples"] == 2
    profiler.flush()
    assert "Dropped 2 profile samples" in caplog.text
    assert profiler.buffer_statistics["used_samples"] == 0
    profiler._capture_collectors([Collector()])
    profiler.flush()
    assert len(exporter.requests) == 2
    profile = (
        exporter.requests[0].resource_profiles[0].scope_profiles[0].profiles[0]
    )
    assert list(profile.samples[0].timestamps_unix_nano) == [100, 101]
    assert list(profile.samples[0].values) == [1, 1]
    assert not internal_work()


def test_zero_memory_interval_has_positive_scheduler_cadence() -> None:
    profiler = Profiler(
        exporter=_Exporter(),
        memory_enabled=True,
        memory_interval=0,
        export_interval=7,
    )
    assert profiler._memory_collector._capture_interval == 0
    assert profiler._memory_scheduler._sample_interval == 7


@pytest.mark.skipif(not HAS_MONITORING, reason="requires sys.monitoring")
def test_profiler_internal_work_is_excluded_from_exception_sampling() -> None:
    collector = ExceptionCollector(
        ContextBridge(), sampling_interval=1, collect_message=True
    )
    collector.start()
    try:
        with suppress_collection():
            try:
                raise ValueError("internal-only")
            except ValueError:
                pass
        try:
            raise ValueError("business-only")
        except ValueError:
            pass
        messages = {
            attribute.value
            for sample in collector.capture()
            for attribute in sample.attributes
            if attribute.key == "exception.message"
        }
        assert "business-only" in messages
        assert "internal-only" not in messages
    finally:
        collector.stop()


def test_stack_frames_are_reused_but_sample_metadata_is_not() -> None:
    first, second = _sample(), _sample(1)
    assert first.frames[0] is second.frames[0]
    assert first is not second
    assert first.timestamp_unix_nano != second.timestamp_unix_nano
    assert first.cpu_time_ns != second.cpu_time_ns


def test_profiler_collectors_share_budget_and_fork_reset_is_empty() -> None:
    profiler = Profiler(
        exporter=_Exporter(), lock_enabled=True, exception_enabled=True
    )
    assert all(
        collector._sample_budget is profiler._sample_budget
        for collector in profiler._collectors
    )
    profiler._samples.append(_sample())
    profiler._after_fork_in_child()
    assert profiler.buffer_statistics["used_samples"] == 0
    assert profiler.buffer_statistics["used_bytes"] == 0


def test_old_buffer_cannot_release_a_new_fork_generation() -> None:
    budget = SampleBudget(max_samples=2, max_bytes=16384)
    previous = SampleBuffer(budget)
    previous.append(_sample())
    budget.reset_after_fork()
    current = SampleBuffer(budget)
    current.append(_sample(1))
    previous.clear()
    assert budget.snapshot()["used_samples"] == 1
    current.clear()
    assert budget.snapshot()["used_bytes"] == 0


def test_repeated_real_stack_capture_stays_within_budget() -> None:
    done = threading.Event()
    ready = threading.Barrier(9)

    def worker(depth: int) -> None:
        if depth:
            worker(depth - 1)
        else:
            ready.wait()
            done.wait()

    threads = [threading.Thread(target=worker, args=(25,)) for _ in range(8)]
    for thread in threads:
        thread.start()
    ready.wait()
    profiler = Profiler(
        exporter=_Exporter(),
        include_trace_context=False,
        max_buffer_samples=64,
        max_buffer_bytes=262144,
    )
    profiler._active_collectors = [profiler._collectors[0]]
    try:
        for _ in range(200):
            profiler.capture_once()
        stats = profiler.buffer_statistics
        assert stats["used_samples"] <= 64
        assert stats["used_bytes"] <= 262144
        assert stats["dropped_samples"] > 0
        profiler.flush()
        assert profiler.buffer_statistics["used_samples"] == 0
        profiler.capture_once()
        assert profiler.buffer_statistics["used_samples"] > 0
    finally:
        profiler._clear_samples()
        done.set()
        for thread in threads:
            thread.join(timeout=2)
        assert not any(thread.is_alive() for thread in threads)
