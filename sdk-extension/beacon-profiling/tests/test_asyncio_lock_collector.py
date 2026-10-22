import asyncio
import threading

from opentelemetry.sdk.extension.profiling.collector.lock import (
    AsyncioBoundedSemaphoreCollector,
    AsyncioConditionCollector,
    AsyncioLockCollector,
    AsyncioSemaphoreCollector,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.trace import TracerProvider


def test_asyncio_collectors_patch_and_restore_classes():
    lock_collector = AsyncioLockCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    semaphore_collector = AsyncioSemaphoreCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    bounded_collector = AsyncioBoundedSemaphoreCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    condition_collector = AsyncioConditionCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    original_lock_class = asyncio.Lock
    original_semaphore_class = asyncio.Semaphore
    original_bounded_semaphore_class = asyncio.BoundedSemaphore
    original_condition_class = asyncio.Condition

    lock_collector.start()
    semaphore_collector.start()
    bounded_collector.start()
    condition_collector.start()
    try:
        assert asyncio.Lock is not original_lock_class
        assert asyncio.Semaphore is not original_semaphore_class
        assert asyncio.BoundedSemaphore is not original_bounded_semaphore_class
        assert asyncio.Condition is not original_condition_class
        assert asyncio.locks.Lock is asyncio.Lock
        assert asyncio.locks.Semaphore is asyncio.Semaphore
        assert asyncio.locks.BoundedSemaphore is asyncio.BoundedSemaphore
        assert asyncio.locks.Condition is asyncio.Condition
        lock = asyncio.Lock()
        semaphore = asyncio.Semaphore()
        bounded_semaphore = asyncio.BoundedSemaphore()
        condition = asyncio.Condition()
        assert isinstance(lock, original_lock_class)
        assert isinstance(semaphore, original_semaphore_class)
        assert isinstance(bounded_semaphore, original_bounded_semaphore_class)
        assert isinstance(condition, original_condition_class)
    finally:
        condition_collector.stop()
        bounded_collector.stop()
        semaphore_collector.stop()
        lock_collector.stop()

    assert asyncio.Lock is original_lock_class
    assert asyncio.Semaphore is original_semaphore_class
    assert asyncio.BoundedSemaphore is original_bounded_semaphore_class
    assert asyncio.Condition is original_condition_class
    assert asyncio.locks.Lock is original_lock_class
    assert asyncio.locks.Semaphore is original_semaphore_class
    assert asyncio.locks.BoundedSemaphore is original_bounded_semaphore_class
    assert asyncio.locks.Condition is original_condition_class


def test_asyncio_lock_collector_captures_wait_and_hold_duration():
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = AsyncioLockCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    try:
        main_thread_id, span_context = asyncio.run(
            _exercise_asyncio_lock(tracer)
        )
        samples = collector.capture()
    finally:
        collector.stop()
        bridge.stop()

    acquire_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.acquire.duration",
        lock_kind="asyncio.Lock",
    )
    hold_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.hold.duration",
        lock_kind="asyncio.Lock",
    )

    assert acquire_samples
    assert hold_samples

    acquire_sample = acquire_samples[-1]
    hold_sample = hold_samples[-1]
    acquire_attributes = {
        attribute.key: attribute.value
        for attribute in acquire_sample.attributes
    }

    assert acquire_sample.value > 0
    assert hold_sample.value > 0
    assert acquire_sample.trace_id == span_context.trace_id
    assert acquire_sample.span_id == span_context.span_id
    assert acquire_sample.frames[0].function == "_exercise_asyncio_lock"
    assert acquire_attributes["lock.kind"] == "asyncio.Lock"
    assert str(acquire_attributes["lock.name"]).startswith(
        "test_asyncio_lock_collector.py:"
    )


def test_asyncio_semaphore_collector_captures_wait_and_hold_duration():
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = AsyncioSemaphoreCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    try:
        main_thread_id, span_context = asyncio.run(
            _exercise_asyncio_semaphore(tracer)
        )
        samples = collector.capture()
    finally:
        collector.stop()
        bridge.stop()

    acquire_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.acquire.duration",
        lock_kind="asyncio.Semaphore",
    )
    hold_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.hold.duration",
        lock_kind="asyncio.Semaphore",
    )

    assert acquire_samples
    assert hold_samples

    acquire_sample = acquire_samples[-1]
    hold_sample = hold_samples[-1]
    acquire_attributes = {
        attribute.key: attribute.value
        for attribute in acquire_sample.attributes
    }

    assert acquire_sample.value > 0
    assert hold_sample.value > 0
    assert acquire_sample.trace_id == span_context.trace_id
    assert acquire_sample.span_id == span_context.span_id
    assert acquire_sample.frames[0].function == "_exercise_asyncio_semaphore"
    assert acquire_attributes["lock.kind"] == "asyncio.Semaphore"
    assert str(acquire_attributes["lock.name"]).startswith(
        "test_asyncio_lock_collector.py:"
    )


def test_asyncio_condition_collector_captures_wait_duration():
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = AsyncioConditionCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    try:
        main_thread_id, span_context = asyncio.run(
            _exercise_asyncio_condition(tracer)
        )
        samples = collector.capture()
    finally:
        collector.stop()
        bridge.stop()

    wait_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.wait.duration",
        lock_kind="asyncio.Condition",
    )

    assert wait_samples

    wait_sample = wait_samples[-1]
    wait_attributes = {
        attribute.key: attribute.value for attribute in wait_sample.attributes
    }

    assert wait_sample.value > 0
    assert wait_sample.trace_id == span_context.trace_id
    assert wait_sample.span_id == span_context.span_id
    assert wait_sample.frames[0].function == "_exercise_asyncio_condition"
    assert wait_attributes["lock.kind"] == "asyncio.Condition"
    assert str(wait_attributes["lock.name"]).startswith(
        "test_asyncio_lock_collector.py:"
    )


async def _exercise_asyncio_lock(tracer):
    ready = asyncio.Event()
    lock = asyncio.Lock()

    async def worker() -> None:
        await lock.acquire()
        try:
            ready.set()
            await asyncio.sleep(0.05)
        finally:
            lock.release()

    task = asyncio.create_task(worker())
    await ready.wait()

    with tracer.start_as_current_span("span") as span:
        await lock.acquire()
        try:
            await asyncio.sleep(0.01)
        finally:
            lock.release()

    await task
    return threading.get_ident(), span.get_span_context()


async def _exercise_asyncio_semaphore(tracer):
    ready = asyncio.Event()
    semaphore = asyncio.Semaphore(1)

    async def worker() -> None:
        await semaphore.acquire()
        try:
            ready.set()
            await asyncio.sleep(0.05)
        finally:
            semaphore.release()

    task = asyncio.create_task(worker())
    await ready.wait()

    with tracer.start_as_current_span("span") as span:
        await semaphore.acquire()
        try:
            await asyncio.sleep(0.01)
        finally:
            semaphore.release()

    await task
    return threading.get_ident(), span.get_span_context()


async def _exercise_asyncio_condition(tracer):
    waiting = asyncio.Event()
    condition = asyncio.Condition()

    async def notifier() -> None:
        await waiting.wait()
        async with condition:
            await asyncio.sleep(0.02)
            condition.notify()

    task = asyncio.create_task(notifier())

    with tracer.start_as_current_span("span") as span:
        async with condition:
            waiting.set()
            await condition.wait()

    await task
    return threading.get_ident(), span.get_span_context()


def _select_samples(
    samples,
    *,
    thread_id: int,
    sample_type: str,
    lock_kind: str,
):
    return [
        sample
        for sample in samples
        if sample.thread_id == thread_id
        and sample.sample_type == sample_type
        and any(
            attribute.key == "lock.kind" and attribute.value == lock_kind
            for attribute in sample.attributes
        )
        and any(
            attribute.key == "lock.name"
            and str(attribute.value).startswith(
                "test_asyncio_lock_collector.py:"
            )
            for attribute in sample.attributes
        )
    ]
