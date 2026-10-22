import threading
from time import sleep

from opentelemetry.sdk.extension.profiling.collector.lock import (
    ThreadingBoundedSemaphoreCollector,
    ThreadingConditionCollector,
    ThreadingLockCollector,
    ThreadingRLockCollector,
    ThreadingSemaphoreCollector,
)
from opentelemetry.sdk.extension.profiling.context_bridge import ContextBridge
from opentelemetry.sdk.trace import TracerProvider


def test_threading_lock_collector_patches_and_restores_lock_factory():
    collector = ThreadingLockCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    original_lock_factory = threading.Lock

    collector.start()
    try:
        assert threading.Lock is not original_lock_factory
        profiled_lock = threading.Lock()
        assert type(profiled_lock).__name__ == "_ProfiledPrimitiveProxy"
    finally:
        collector.stop()

    assert threading.Lock is original_lock_factory


def test_threading_rlock_collector_patches_and_restores_lock_factory():
    collector = ThreadingRLockCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    original_lock_factory = threading.RLock

    collector.start()
    try:
        assert threading.RLock is not original_lock_factory
        profiled_lock = threading.RLock()
        assert type(profiled_lock).__name__ == "_ProfiledPrimitiveProxy"
    finally:
        collector.stop()

    assert threading.RLock is original_lock_factory


def test_threading_semaphore_collectors_patch_and_restore_classes():
    semaphore_collector = ThreadingSemaphoreCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    bounded_collector = ThreadingBoundedSemaphoreCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    original_semaphore_class = threading.Semaphore
    original_bounded_semaphore_class = threading.BoundedSemaphore

    semaphore_collector.start()
    bounded_collector.start()
    try:
        assert threading.Semaphore is not original_semaphore_class
        assert (
            threading.BoundedSemaphore is not original_bounded_semaphore_class
        )
        semaphore = threading.Semaphore(1)
        bounded_semaphore = threading.BoundedSemaphore(1)
        assert isinstance(semaphore, original_semaphore_class)
        assert isinstance(bounded_semaphore, original_bounded_semaphore_class)
    finally:
        bounded_collector.stop()
        semaphore_collector.stop()

    assert threading.Semaphore is original_semaphore_class
    assert threading.BoundedSemaphore is original_bounded_semaphore_class


def test_threading_condition_collector_patches_and_restores_class():
    collector = ThreadingConditionCollector(
        context_bridge=ContextBridge(), sampling_interval=1
    )
    original_condition_class = threading.Condition

    collector.start()
    try:
        assert threading.Condition is not original_condition_class
        condition = threading.Condition()
        assert isinstance(condition, original_condition_class)
    finally:
        collector.stop()

    assert threading.Condition is original_condition_class


def test_threading_lock_collector_captures_wait_and_hold_duration():
    ready = threading.Event()
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = ThreadingLockCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    worker = None
    try:
        lock = threading.Lock()

        def worker_fn() -> None:
            lock.acquire()
            try:
                ready.set()
                sleep(0.05)
            finally:
                lock.release()

        worker = threading.Thread(target=worker_fn, name="worker-lock-holder")
        worker.start()
        assert ready.wait(timeout=1)

        main_thread_id = threading.get_ident()
        with tracer.start_as_current_span("span") as span:
            lock.acquire()
            try:
                sleep(0.01)
            finally:
                lock.release()

        worker.join(timeout=1)
        assert not worker.is_alive()
        samples = collector.capture()
    finally:
        if worker is not None and worker.is_alive():
            worker.join(timeout=1)
        collector.stop()
        bridge.stop()

    acquire_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.acquire.duration",
        lock_kind="threading.Lock",
    )
    hold_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.hold.duration",
        lock_kind="threading.Lock",
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
    assert acquire_sample.trace_id == span.get_span_context().trace_id
    assert acquire_sample.span_id == span.get_span_context().span_id
    assert acquire_sample.frames[0].function == (
        "test_threading_lock_collector_captures_wait_and_hold_duration"
    )
    assert acquire_attributes["lock.kind"] == "threading.Lock"
    assert str(acquire_attributes["lock.name"]).startswith(
        "test_lock_collector.py:"
    )


def test_threading_rlock_collector_captures_wait_and_hold_duration():
    ready = threading.Event()
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = ThreadingRLockCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    worker = None
    try:
        lock = threading.RLock()

        def worker_fn() -> None:
            lock.acquire()
            try:
                ready.set()
                sleep(0.05)
            finally:
                lock.release()

        worker = threading.Thread(target=worker_fn, name="worker-rlock-holder")
        worker.start()
        assert ready.wait(timeout=1)

        main_thread_id = threading.get_ident()
        with tracer.start_as_current_span("span") as span:
            lock.acquire()
            try:
                sleep(0.01)
            finally:
                lock.release()

        worker.join(timeout=1)
        assert not worker.is_alive()
        samples = collector.capture()
    finally:
        if worker is not None and worker.is_alive():
            worker.join(timeout=1)
        collector.stop()
        bridge.stop()

    acquire_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.acquire.duration",
        lock_kind="threading.RLock",
    )
    hold_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.hold.duration",
        lock_kind="threading.RLock",
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
    assert acquire_sample.trace_id == span.get_span_context().trace_id
    assert acquire_sample.span_id == span.get_span_context().span_id
    assert acquire_sample.frames[0].function == (
        "test_threading_rlock_collector_captures_wait_and_hold_duration"
    )
    assert acquire_attributes["lock.kind"] == "threading.RLock"
    assert str(acquire_attributes["lock.name"]).startswith(
        "test_lock_collector.py:"
    )


def test_threading_semaphore_collector_captures_wait_and_hold_duration():
    ready = threading.Event()
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = ThreadingSemaphoreCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    worker = None
    try:
        semaphore = threading.Semaphore(1)

        def worker_fn() -> None:
            semaphore.acquire()
            try:
                ready.set()
                sleep(0.05)
            finally:
                semaphore.release()

        worker = threading.Thread(
            target=worker_fn, name="worker-semaphore-holder"
        )
        worker.start()
        assert ready.wait(timeout=1)

        main_thread_id = threading.get_ident()
        with tracer.start_as_current_span("span") as span:
            semaphore.acquire()
            try:
                sleep(0.01)
            finally:
                semaphore.release()

        worker.join(timeout=1)
        assert not worker.is_alive()
        samples = collector.capture()
    finally:
        if worker is not None and worker.is_alive():
            worker.join(timeout=1)
        collector.stop()
        bridge.stop()

    acquire_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.acquire.duration",
        lock_kind="threading.Semaphore",
    )
    hold_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.hold.duration",
        lock_kind="threading.Semaphore",
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
    assert acquire_sample.trace_id == span.get_span_context().trace_id
    assert acquire_sample.span_id == span.get_span_context().span_id
    assert acquire_sample.frames[0].function == (
        "test_threading_semaphore_collector_captures_wait_and_hold_duration"
    )
    assert acquire_attributes["lock.kind"] == "threading.Semaphore"
    assert str(acquire_attributes["lock.name"]).startswith(
        "test_lock_collector.py:"
    )


def test_threading_condition_collector_captures_wait_and_hold_duration():
    ready = threading.Event()
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = ThreadingConditionCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    worker = None
    try:
        condition = threading.Condition()

        def worker_fn() -> None:
            condition.acquire()
            try:
                ready.set()
                sleep(0.05)
            finally:
                condition.release()

        worker = threading.Thread(
            target=worker_fn, name="worker-condition-holder"
        )
        worker.start()
        assert ready.wait(timeout=1)

        main_thread_id = threading.get_ident()
        with tracer.start_as_current_span("span") as span:
            condition.acquire()
            try:
                sleep(0.01)
            finally:
                condition.release()

        worker.join(timeout=1)
        assert not worker.is_alive()
        samples = collector.capture()
    finally:
        if worker is not None and worker.is_alive():
            worker.join(timeout=1)
        collector.stop()
        bridge.stop()

    acquire_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.acquire.duration",
        lock_kind="threading.Condition",
    )
    hold_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.hold.duration",
        lock_kind="threading.Condition",
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
    assert acquire_sample.trace_id == span.get_span_context().trace_id
    assert acquire_sample.span_id == span.get_span_context().span_id
    assert acquire_sample.frames[0].function == (
        "test_threading_condition_collector_captures_wait_and_hold_duration"
    )
    assert acquire_attributes["lock.kind"] == "threading.Condition"
    assert str(acquire_attributes["lock.name"]).startswith(
        "test_lock_collector.py:"
    )


def test_threading_condition_collector_captures_wait_duration():
    waiting = threading.Event()
    bridge = ContextBridge()
    tracer = TracerProvider().get_tracer("test")
    collector = ThreadingConditionCollector(
        context_bridge=bridge,
        sampling_interval=1,
        max_frames=32,
    )

    bridge.start()
    collector.start()
    notifier = None
    try:
        condition = threading.Condition()

        def notifier_fn() -> None:
            assert waiting.wait(timeout=1)
            with condition:
                sleep(0.02)
                condition.notify()

        notifier = threading.Thread(
            target=notifier_fn, name="worker-condition-notifier"
        )

        main_thread_id = threading.get_ident()
        with tracer.start_as_current_span("span") as span:
            with condition:
                notifier.start()
                waiting.set()
                condition.wait(timeout=1)

        notifier.join(timeout=1)
        assert not notifier.is_alive()
        samples = collector.capture()
    finally:
        if notifier is not None and notifier.is_alive():
            notifier.join(timeout=1)
        collector.stop()
        bridge.stop()

    wait_samples = _select_samples(
        samples,
        thread_id=main_thread_id,
        sample_type="lock.wait.duration",
        lock_kind="threading.Condition",
    )

    assert wait_samples

    wait_sample = wait_samples[-1]
    wait_attributes = {
        attribute.key: attribute.value for attribute in wait_sample.attributes
    }

    assert wait_sample.value > 0
    assert wait_sample.trace_id == span.get_span_context().trace_id
    assert wait_sample.span_id == span.get_span_context().span_id
    assert wait_sample.frames[0].function == (
        "test_threading_condition_collector_captures_wait_duration"
    )
    assert wait_attributes["lock.kind"] == "threading.Condition"
    assert str(wait_attributes["lock.name"]).startswith(
        "test_lock_collector.py:"
    )


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
            and str(attribute.value).startswith("test_lock_collector.py:")
            for attribute in sample.attributes
        )
    ]
