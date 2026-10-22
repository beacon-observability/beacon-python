from __future__ import annotations

import queue
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from beacon_security import exporter as module
from beacon_security.exporter import Exporter

RUN_CHANNEL = Exporter._run_channel


def event(index, priority=0, size=100):
    return {
        "event_name": "beacon.security.collection.incomplete"
        if priority == 1
        else "beacon.security.finding",
        "attack_evidence": {
            "status": "suspected" if priority == 2 else "no_evidence"
        },
        "finding_id": "shared-finding",
        "occurrence_id": f"request-{index}",
        "evidence_id": f"request-{index}",
        "trace_id": f"{index + 1:032x}",
        "server_span_id": f"{index + 1:016x}",
        "size": size,
    }


@pytest.fixture
def paused_exporter(monkeypatch, tmp_path):
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "false")
    monkeypatch.setenv("BEACON_SECURITY_EXPORT_QUEUE_SIZE", "16")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    monkeypatch.setattr(Exporter, "_run_channel", lambda *_: None)
    monkeypatch.setattr(Exporter, "_monitor_loop", lambda *_: None)
    exporter = Exporter({}, "priority", tmp_path)
    try:
        yield exporter
    finally:
        exporter.close(timeout=0.5)


def drain(exporter, monkeypatch, after=None):
    """Run the real channel synchronously, injecting arrivals after API emits."""
    emitted = []
    get = exporter._security_queue.get

    def until_empty(*args, **kwargs):
        if exporter._security_queue.empty():
            exporter._running = False
            raise queue.Empty
        return get(*args, **kwargs)

    def capture(body, record, context):
        emitted.append((record, body, context))
        if after is not None:
            after(len(emitted))

    monkeypatch.setattr(exporter._security_queue, "get", until_empty)
    monkeypatch.setattr(exporter, "_emit_otel", capture)
    with monkeypatch.context() as clock_patch:
        if module.time is time:

            class SameWindow:
                def monotonic(self):
                    return 10.25

                def __getattr__(self, name):
                    return getattr(time, name)

            clock_patch.setattr(module, "time", SameWindow())
        RUN_CHANNEL(exporter, exporter._security_queue, "security")
    assert exporter.flush(timeout=0)
    assert exporter._security_queue.unfinished_tasks == 0
    return emitted


def test_full_queue_evicts_lower_priority_preserving_context_and_counts(
    paused_exporter,
):
    exporter = paused_exporter
    exporter._security_queue.maxsize = 3
    originals = [event(index) for index in range(3)]
    for record in originals:
        exporter.emit(record)
    exporter.emit(event(3, 1))
    exporter.emit(event(4, 2))
    exporter.emit(event(5))
    assert exporter._security_queue.qsize() == 3
    assert exporter._security_queue.unfinished_tasks == 3
    assert not exporter.flush(timeout=0)
    entries = []
    while not exporter._security_queue.empty():
        entries.append(exporter._security_queue.get_nowait())
        exporter._security_queue.task_done()
    assert [entry.event["occurrence_id"] for entry in entries] == [
        "request-4",
        "request-3",
        "request-2",
    ]
    from opentelemetry.trace import get_current_span

    for entry in entries:
        context = get_current_span(entry.span_context).get_span_context()
        assert context.trace_id == int(entry.event["trace_id"], 16)
        assert context.span_id == int(entry.event["server_span_id"], 16)
    counters = exporter.delivery()["counters"]
    assert counters["security.priority_evicted"] == 2
    assert counters["security.queue_full"] == 1
    assert exporter.delivery()["security_dropped"] == 3
    assert exporter.flush(timeout=0)
    assert all("source" not in original for original in originals)


def test_lower_or_equal_priority_cannot_replace_attack_evidence(
    paused_exporter,
):
    exporter = paused_exporter
    exporter._security_queue.maxsize = 1
    exporter.emit(event(1, 2))
    exporter.emit(event(2, 2))
    exporter.emit(event(3, 1))
    entry = exporter._security_queue.get_nowait()
    exporter._security_queue.task_done()
    assert entry.event["occurrence_id"] == "request-1"
    assert exporter.delivery()["counters"]["security.queue_full"] == 2


def test_late_attacks_and_coverage_survive_spent_ordinary_event_budget(
    paused_exporter, monkeypatch
):
    exporter = paused_exporter
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_EVENTS_PER_SECOND", "10"
    )
    for index in range(8):
        exporter.emit(event(index))

    def late(count):
        if count == 6:
            exporter.emit(event(100, 2))
            exporter.emit(event(101, 1))

    emitted = drain(exporter, monkeypatch, late)
    ids = [record["occurrence_id"] for record, _, _ in emitted]
    assert ids == [f"request-{i}" for i in range(6)] + [
        "request-100",
        "request-101",
    ]
    assert len(emitted) <= 10 and len(set(ids)) == len(ids)
    assert exporter.delivery()["counters"]["security.budget_exceeded"] == 2


def test_byte_reserves_and_oversized_rejection_keep_total_bound(
    paused_exporter, monkeypatch
):
    exporter = paused_exporter
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_BYTES_PER_SECOND", "1000"
    )
    monkeypatch.setattr(
        exporter,
        "_encode_record_result",
        lambda record: (b"x" * record["size"], False),
    )
    for index in range(8):
        exporter.emit(event(index))

    def late(count):
        if count == 6:
            exporter.emit(event(99, 2, size=1001))
            exporter.emit(event(100, 2, size=200))
            exporter.emit(event(101, 1, size=200))

    emitted = drain(exporter, monkeypatch, late)
    assert sum(len(body.encode()) for _, body, _ in emitted) == 1000
    assert [record["occurrence_id"] for record, _, _ in emitted][-2:] == [
        "request-100",
        "request-101",
    ]
    assert exporter.delivery()["counters"]["security.budget_exceeded"] == 3
    assert (
        exporter.delivery()["counters"]["security.priority_2.budget_exceeded"]
        == 1
    )


def test_budget_resets_on_next_second(paused_exporter, monkeypatch):
    exporter = paused_exporter
    second = [10]

    class Clock:
        def monotonic(self):
            return second[0]

        def __getattr__(self, name):
            return getattr(time, name)

    monkeypatch.setattr(module, "time", Clock())
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_EVENTS_PER_SECOND", "5"
    )
    for index in range(6):
        exporter.emit(event(index))

    def next_window(count):
        if count == 3:
            second[0] += 1

    assert len(drain(exporter, monkeypatch, next_window)) == 6


def test_concurrent_producers_remain_bounded_and_flush_accounting_is_exact(
    paused_exporter,
):
    exporter = paused_exporter
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda index: exporter.emit(
                    event(index, 2 if index % 5 == 0 else 0)
                ),
                range(200),
            )
        )
    retained = exporter._security_queue.qsize()
    assert retained == 16
    assert exporter._security_queue.unfinished_tasks == retained
    assert exporter.delivery()["security_dropped"] == 200 - retained
    entries = []
    while not exporter._security_queue.empty():
        entries.append(exporter._security_queue.get_nowait())
        exporter._security_queue.task_done()
    assert all(
        entry.event["attack_evidence"]["status"] == "suspected"
        for entry in entries
    )
    assert len({entry.event["occurrence_id"] for entry in entries}) == retained
    assert exporter.flush(timeout=0)


def test_eviction_invalidates_verification_run_of_the_discarded_event(
    paused_exporter, monkeypatch
):
    from unittest.mock import Mock

    exporter = paused_exporter
    exporter._security_queue.maxsize = 1
    lost = event(1)
    lost["run"] = {"run_id": "ordinary-run"}
    record_loss = Mock(wraps=exporter.ledger.record_delivery_loss)
    monkeypatch.setattr(exporter.ledger, "record_delivery_loss", record_loss)
    exporter.emit(lost)
    exporter.emit(event(2, 2))
    assert record_loss.call_count == 1
    assert record_loss.call_args.args[0]["run"] == lost["run"]
    assert record_loss.call_args.args[0]["occurrence_id"] == "request-1"


def test_real_json_byte_budget_preserves_late_priority_records(
    paused_exporter, monkeypatch
):
    exporter = paused_exporter
    for index in range(1000, 1008):
        exporter.emit(event(index))
    first = exporter._security_queue.queue[0][0]
    size = len(exporter._encode_record(first.event))
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_BYTES_PER_SECOND", str(size * 10)
    )
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_EVENTS_PER_SECOND", "1000"
    )

    def late(count):
        if count == 6:
            exporter.emit(event(2000, 2))
            exporter.emit(event(2001, 1))

    emitted = drain(exporter, monkeypatch, late)
    assert len(emitted) == 8
    assert sum(len(body.encode()) for _, body, _ in emitted) <= size * 10
    assert [record["occurrence_id"] for record, _, _ in emitted][-2:] == [
        "request-2000",
        "request-2001",
    ]
    assert exporter.delivery()["counters"]["security.budget_exceeded"] == 2


def test_tiny_budget_reserves_priority_slots_without_exceeding_limit(
    paused_exporter, monkeypatch
):
    exporter = paused_exporter
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_EVENTS_PER_SECOND", "2"
    )
    exporter.emit(event(1))
    exporter.emit(event(2, 2))
    exporter.emit(event(3, 1))
    emitted = drain(exporter, monkeypatch)
    assert [record["occurrence_id"] for record, _, _ in emitted] == [
        "request-2",
        "request-3",
    ]
    assert exporter.delivery()["counters"]["security.budget_exceeded"] == 1


def test_loss_diagnostics_share_the_hard_total_budget(
    paused_exporter, monkeypatch
):
    exporter = paused_exporter
    monkeypatch.setenv(
        "BEACON_SECURITY_EXPORT_SECURITY_EVENTS_PER_SECOND", "10"
    )
    for index in range(12):
        record = event(index, 1)
        record["event_name"] = "beacon.security.export.dropped"
        exporter.emit(record)
    emitted = drain(exporter, monkeypatch)
    assert len(emitted) == 8
    assert exporter.delivery()["counters"]["security.budget_exceeded"] == 4
