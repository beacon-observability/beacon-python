from __future__ import annotations

import asyncio
from collections import Counter

import pytest

from opentelemetry.sdk.extension.profiling.collector import lock as locks
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge


@pytest.mark.parametrize(
    "collector_class,name",
    [
        (locks.AsyncioLockCollector, "Lock"),
        (locks.AsyncioSemaphoreCollector, "Semaphore"),
        (locks.AsyncioBoundedSemaphoreCollector, "BoundedSemaphore"),
        (locks.AsyncioConditionCollector, "Condition"),
    ],
)
@pytest.mark.parametrize("context_manager", [False, True])
def test_async_acquisition_and_hold_are_measured_once(
    monkeypatch, collector_class, name: str, context_manager: bool
) -> None:
    async def exercise() -> None:
        collector = collector_class(ContextBridge())
        collector.start()
        try:
            primitive = getattr(asyncio, name)()
            ticks = iter((100, 130, 180))
            monkeypatch.setattr(locks, "monotonic_ns", lambda: next(ticks))
            if context_manager:
                async with primitive as value:
                    assert value is None
            else:
                assert await primitive.acquire()
                primitive.release()
            samples = collector.capture()
            assert Counter(sample.sample_type for sample in samples) == {
                "lock.acquire.duration": 1,
                "lock.hold.duration": 1,
            }
            assert [sample.value for sample in samples] == [30, 50]
        finally:
            collector.stop()

    asyncio.run(exercise())


def test_cancelled_async_with_has_no_completed_acquire_sample() -> None:
    async def exercise() -> None:
        collector = locks.AsyncioLockCollector(ContextBridge())
        collector.start()
        try:
            primitive = asyncio.Lock()
            await primitive.acquire()
            collector.capture()

            async def waiter() -> None:
                async with primitive:
                    pytest.fail("cancelled waiter acquired the lock")

            task = asyncio.create_task(waiter())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert collector.capture() == []
            primitive.release()
            collector.capture()
            async with primitive:
                pass
            samples = collector.capture()
            assert len(samples) == 2
        finally:
            collector.stop()

    asyncio.run(exercise())


def test_body_exception_keeps_native_async_context_manager_cleanup() -> None:
    error = RuntimeError("business failure")

    async def exercise() -> None:
        collector = locks.AsyncioLockCollector(ContextBridge())
        collector.start()
        try:
            primitive = asyncio.Lock()
            with pytest.raises(RuntimeError) as raised:
                async with primitive:
                    raise error
            assert raised.value is error
            assert not primitive.locked()
            assert len(collector.capture()) == 2
        finally:
            collector.stop()

    asyncio.run(exercise())
