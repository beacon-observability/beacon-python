"""Runtime-level product contracts for Python Beacon integration.

These tests use the real exporter, SDK log provider, ledger, and canonical CLI
boundaries.  They intentionally do not claim an external Collector ACK.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from beacon_otel.version import __version__


def test_snapshot_freezes_rows_without_blocking_collection_or_losing_updates(
    monkeypatch, tmp_path
):
    _configure_exporter_env(monkeypatch, tmp_path)
    from beacon_security.ledger import RuntimeLedger
    from beacon_security.state import SecurityState

    ledger = RuntimeLedger(_identity(), "qa-profile", tmp_path)
    completed = threading.Event()

    def check_gate():
        if ledger.enabled():
            completed.set()

    with ledger._lock:
        gate = threading.Thread(target=check_gate)
        gate.start()
        gate_available = completed.wait(1)
    gate.join(2)
    assert gate_available

    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    (tmp_path / "control.json").write_text(
        json.dumps(
            {
                "revision": "snapshot-run",
                "run": {
                    "run_id": "snapshot-run",
                    "case_id": "snapshot",
                    "rule": "sql_injection",
                    "expires_at": expires,
                    "conditions": {
                        "suite": "qa",
                        "fixture": "snapshot",
                        "expected_requests": 3,
                    },
                },
            }
        )
    )
    ledger.tick({}, lambda _event: None, force=True)
    assert not ledger.health({})["control_error"]

    def request():
        state = SecurityState(_identity())
        ledger.begin(state)
        state.source_signatures["http.request.parameter|q"] = 1
        state.pending.append(
            {
                "finding_id": "snapshot-finding",
                "evidence_id": "snapshot-evidence",
                "event_name": "beacon.security.finding",
                "rule": "sql_injection",
                "sources": [
                    {"id": "s1", "type": "http.request.parameter", "name": "q"}
                ],
                "propagation": [{"id": 1, "operation": "source"}],
            }
        )
        ledger.end(state)
        state.close()

    entered, release = threading.Event(), threading.Event()
    write = ledger._write_snapshot
    writes = []

    def blocked_write(name, value):
        writes.append(name)
        if name == "findings.json" and not entered.is_set():
            entered.set()
            if not release.wait(3):
                raise TimeoutError("snapshot test timed out")
        write(name, value)

    monkeypatch.setattr(ledger, "_write_snapshot", blocked_write)
    request()
    worker = threading.Thread(
        target=lambda: ledger.tick({}, lambda _event: None, force=True)
    )
    worker.start()
    try:
        assert entered.wait(2)
        request()
    finally:
        release.set()
        worker.join(4)
    assert not worker.is_alive()
    assert (
        json.loads((tmp_path / "findings.json").read_text())["findings"][0][
            "occurrences"
        ]
        == 1
    )
    run = json.loads((tmp_path / "runs.json").read_text())["runs"][0]
    for field in (
        "source_signatures",
        "risk_source_signatures",
        "finding_counts",
    ):
        assert list(run[field].values()) == [1]
    ledger.tick({}, lambda _event: None, force=True)
    assert (
        json.loads((tmp_path / "findings.json").read_text())["findings"][0][
            "occurrences"
        ]
        == 2
    )
    run = json.loads((tmp_path / "runs.json").read_text())["runs"][0]
    for field in (
        "source_signatures",
        "risk_source_signatures",
        "finding_counts",
    ):
        assert list(run[field].values()) == [2]
    count = writes.count("findings.json")
    ledger.tick({}, lambda _event: None, force=True)
    assert writes.count("findings.json") == count
    request()
    fail_once = True

    def failing_write(name, value):
        nonlocal fail_once
        if name == "findings.json" and fail_once:
            fail_once = False
            raise OSError("snapshot write failed")
        write(name, value)

    monkeypatch.setattr(ledger, "_write_snapshot", failing_write)
    ledger.tick({}, lambda _event: None, force=True)
    assert (
        json.loads((tmp_path / "findings.json").read_text())["findings"][0][
            "occurrences"
        ]
        == 2
    )
    ledger.tick({}, lambda _event: None, force=True)
    assert (
        json.loads((tmp_path / "findings.json").read_text())["findings"][0][
            "occurrences"
        ]
        == 3
    )


def test_repeated_findings_preserve_samples_counts_and_new_run_details(
    monkeypatch, tmp_path
):
    from beacon_security import ledger as ledger_module
    from beacon_security.ledger import RuntimeLedger
    from beacon_security.state import SecurityState

    _configure_exporter_env(monkeypatch, tmp_path)
    clock = [ledger_module._now_millis()]
    monkeypatch.setattr(ledger_module, "_now_millis", lambda: clock[0])
    ledger = RuntimeLedger(_identity(), "sample-profile", tmp_path)

    def request(label):
        state = SecurityState(
            _identity(), metadata={"method": "GET", "route": "/" + label}
        )
        ledger.begin(state)
        state.trace_id = label
        value = "query-" + label
        state.source(value, "http.request.parameter", "q")
        event = state.sink(
            "sql_injection",
            "sqlite3.Connection.execute",
            "query",
            value,
            location="sample-site",
        )
        event["trace_id"] = "a" * 32 if label == "first" else "b" * 32
        result = ledger.end(state)
        assert event["sources"] and event["propagation"] and event["ranges"]
        state.close()
        return event, result

    first, emitted = request("first")
    assert (
        len(emitted) == 1 and emitted[0]["propagation"] == first["propagation"]
    )
    clock[0] += 1000
    repeated, emitted = request("repeated")
    assert emitted == []
    ledger.tick({}, lambda _: None, force=True)
    finding = _read_json(tmp_path / "findings.json")["findings"][0]
    assert finding["occurrences"] == 2 and finding["last_trace_id"] == "b" * 32
    assert finding["representative"]["evidence_id"] == first["evidence_id"]
    assert finding["representative"]["propagation"] == first["propagation"]

    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    (tmp_path / "control.json").write_text(
        json.dumps(
            {
                "revision": "new-run",
                "run": {
                    "run_id": "new-run",
                    "case_id": "samples",
                    "rule": "sql_injection",
                    "expires_at": expires,
                    "conditions": {
                        "suite": "qa",
                        "fixture": "samples",
                        "expected_requests": 2,
                    },
                },
            }
        )
    )
    ledger.tick({}, lambda _: None, force=True)
    third, emitted = request("new-run")
    assert (
        len(emitted) == 1 and emitted[0]["propagation"] == third["propagation"]
    )
    request("in-run")
    ledger.tick({}, lambda _: None, force=True)
    run = _read_json(tmp_path / "runs.json")["runs"][0]
    assert run["requests"] == 2 and run["observations"] == 2
    assert list(run["risk_source_signatures"].values()) == [2]
    clock[0] += 301_000
    last, emitted = request("after-interval")
    assert (
        len(emitted) == 1 and emitted[0]["propagation"] == last["propagation"]
    )


def test_run_counter_budget_is_shared_across_runs_and_keeps_existing_counts(
    monkeypatch, tmp_path
):
    _configure_exporter_env(
        monkeypatch, tmp_path, BEACON_SECURITY_RUNS_MAX_BYTES=700
    )
    from beacon_security.ledger import RuntimeLedger
    from beacon_security.state import SecurityState

    ledger = RuntimeLedger(_identity(), "qa-profile", tmp_path)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def control(run_id):
        (tmp_path / "control.json").write_text(
            json.dumps(
                {
                    "revision": run_id or "stop",
                    "run": {
                        "run_id": run_id,
                        "case_id": "budget",
                        "rule": "sql_injection",
                        "expires_at": expires,
                        "conditions": {
                            "suite": "qa",
                            "fixture": "budget",
                            "expected_requests": 1,
                        },
                    }
                    if run_id
                    else None,
                }
            )
        )
        ledger.tick({}, lambda _: None, force=True)
        assert not ledger.health({})["control_error"]

    def request(key):
        state = SecurityState(_identity())
        ledger.begin(state)
        state.source_signatures["http.request.parameter|" + key] = 1
        state.pending.append(
            {
                "event_name": "beacon.security.finding",
                "finding_id": "finding-" + key,
                "evidence_id": "evidence-" + key,
                "rule": "sql_injection",
                "sources": [
                    {"id": "s1", "type": "http.request.parameter", "name": key}
                ],
            }
        )
        return state

    control("first")
    first = request("a")
    ledger.end(first)
    first.close()
    pending = request("a")
    control("second")
    second = request("b")
    ledger.end(second)
    second.close()
    ledger.end(pending)
    pending.close()
    control(None)
    runs = {
        run["run_id"]: run
        for run in json.loads((tmp_path / "runs.json").read_text())["runs"]
    }
    for field in (
        "source_signatures",
        "risk_source_signatures",
        "finding_counts",
    ):
        assert list(runs["first"][field].values()) == [2]
        assert not runs["second"][field]
    assert runs["second"]["incomplete_requests"] >= 3
    assert runs["second"]["delivery_loss"] >= 3
    health = json.loads((tmp_path / "health.json").read_text())
    assert health["status"] == "incomplete"
    assert health["counts"]["run_counter_capacity_dropped"] == 3
    assert 0 < health["retention"]["run_counter_bytes_estimated"] <= 700


def _configure_exporter_env(monkeypatch, tmp_path, **values):
    defaults = {
        "BEACON_SECURITY_ENABLED": "true",
        "BEACON_SECURITY_PYTHON_INCLUDE": "security_sample",
        "BEACON_SECURITY_PYTHON_EXCLUDE": "",
        "BEACON_SECURITY_OUTPUT": str(tmp_path),
        "BEACON_SECURITY_EVIDENCE_FILE": str(tmp_path / "evidence.jsonl"),
        "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED": "true",
        "OTEL_LOGS_EXPORTER": "none",
    }
    defaults.update({key: str(value) for key, value in values.items()})
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)


def _identity():
    return {
        "application_id": "qa-product-app",
        "instance_id": "qa-product-instance",
        "service": {"service.name": "qa-product"},
        "code": {
            "repository": "beacon_security/qa",
            "commit": "qa-working-tree",
            "build_id": "python-beacon-qa",
        },
        "runtime": {"language": "python"},
    }


def _read_jsonl(path: Path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_exporter_separates_sbom_log_sources_through_normal_and_truncated_delivery(
    monkeypatch, tmp_path
):
    from beacon_security.exporter import Exporter

    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import (
        InMemoryLogRecordExporter,
        SimpleLogRecordProcessor,
    )

    _configure_exporter_env(monkeypatch, tmp_path)
    logs = InMemoryLogRecordExporter()
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(logs))
    exporter = Exporter(_identity(), "source-routing", tmp_path)
    exporter._otel_logger = provider.get_logger(
        "io.beacon.security", __version__
    )
    try:
        for max_bytes in (65536, 256, 128):
            exporter._max_bytes = max_bytes
            for event_name, source in (
                ("beacon.security.finding", "beacon_security"),
                ("beacon.security.sbom.snapshot", "beacon_security_sbom"),
                ("beacon.security.sbom.health", "beacon_security_sbom"),
                ("beacon.security.sbom.update_failed", "beacon_security_sbom"),
                (
                    "beacon.security.sbom.export.dropped",
                    "beacon_security_sbom",
                ),
            ):
                logs.clear()
                exporter.emit(
                    {
                        "event_name": event_name,
                        "source": "caller-override",
                        "sbom_id": "source-test",
                        "payload": "x" * 4096,
                    }
                )
                assert exporter.flush(timeout=5.0)
                records = logs.get_finished_logs()
                assert len(records) == 1
                log = records[0].log_record
                body = json.loads(log.body)
                assert log.attributes["source"] == body["source"] == source
                assert (
                    log.event_name
                    == log.attributes["event.name"]
                    == body["event_name"]
                )
                assert len(log.body.encode("utf-8")) <= max_bytes
                if max_bytes == 65536:
                    assert body["event_name"] == event_name
                else:
                    assert (
                        body["event_name"]
                        == "beacon.security.export.truncated"
                    )
                    assert body.get("original_event") == (
                        event_name if max_bytes == 256 else None
                    )
    finally:
        exporter.close()
        provider.shutdown()


def test_exporter_reuses_existing_otel_provider_and_bridges_enqueued_trace_context(
    monkeypatch, tmp_path
):
    """A queued record keeps the span context after the application span closes."""

    _configure_exporter_env(monkeypatch, tmp_path)
    from beacon_security.exporter import Exporter

    from opentelemetry._logs import set_logger_provider
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import (
        InMemoryLogRecordExporter,
        SimpleLogRecordProcessor,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    log_exporter = InMemoryLogRecordExporter()
    logger_provider = LoggerProvider(
        resource=Resource.create({"service.name": "qa-product"})
    )
    logger_provider.add_log_record_processor(
        SimpleLogRecordProcessor(log_exporter)
    )
    set_logger_provider(logger_provider)
    tracer_provider = TracerProvider()
    tracer = tracer_provider.get_tracer("qa-product")
    exporter = Exporter(_identity(), "qa-profile", tmp_path)
    try:
        existing_logger = logger_provider.get_logger(
            "io.beacon.security", __version__
        )
        assert exporter._otel_logger is existing_logger

        with tracer.start_as_current_span("product-contract") as span:
            span_context = span.get_span_context()
            exporter.emit(
                {
                    "schema_version": 1,
                    "event_name": "beacon.security.finding",
                    "evidence_id": "ev-product-context",
                    "trace_id": format(span_context.trace_id, "032x"),
                    "server_span_id": format(span_context.span_id, "016x"),
                },
                span_context=span_context,
                evidence=True,
            )

        assert exporter.flush(timeout=5.0)
        records = log_exporter.get_finished_logs()
        matching = [
            record
            for record in records
            if json.loads(str(getattr(record, "log_record", record).body)).get(
                "evidence_id"
            )
            == "ev-product-context"
        ]
        assert len(matching) == 1
        log_record = getattr(matching[0], "log_record", matching[0])
        body = json.loads(str(log_record.body))
        assert body["schema_version"] == 1
        assert body["source"] == "beacon_security"
        assert "severity_text" not in body
        assert "severity_number" not in body
        assert "scope" not in body
        assert log_record.severity_text == "INFO"
        severity_number = log_record.severity_number
        assert int(getattr(severity_number, "value", severity_number)) == 9
        scope = matching[0].instrumentation_scope
        assert scope.name == "io.beacon.security"
        assert scope.version == __version__
        assert log_record.trace_id == span_context.trace_id
        assert log_record.span_id == span_context.span_id
        assert (
            _read_jsonl(tmp_path / "evidence.jsonl")[0]["evidence_id"]
            == "ev-product-context"
        )
    finally:
        exporter.close()
        tracer_provider.shutdown()
        logger_provider.shutdown()


def test_security_and_sbom_queues_are_independent_and_fail_open_on_full_queue(
    monkeypatch, tmp_path
):
    """A full channel does not block or redirect records into the other channel."""

    _configure_exporter_env(
        monkeypatch,
        tmp_path,
        BEACON_SECURITY_EXPORT_QUEUE_SIZE=1,
        BEACON_SECURITY_EXPORT_SBOM_QUEUE_SIZE=1,
    )
    from beacon_security.exporter import Exporter

    # Hold both queues so the test observes the bounded caller-side contract,
    # while still using Exporter.emit/_loss/queue.Full itself.
    monkeypatch.setattr(Exporter, "_run_channel", lambda self, *_args: None)
    exporter = Exporter(_identity(), "qa-profile", tmp_path)
    try:
        exporter.emit(
            {
                "event_name": "beacon.security.finding",
                "evidence_id": "security-1",
            }
        )
        exporter.emit(
            {
                "event_name": "beacon.security.finding",
                "evidence_id": "security-2",
            }
        )
        exporter.emit(
            {
                "event_name": "beacon.security.sbom.snapshot",
                "sbom_id": "sbom-1",
            }
        )
        exporter.emit(
            {
                "event_name": "beacon.security.sbom.snapshot",
                "sbom_id": "sbom-2",
            }
        )

        delivery = exporter.delivery()
        assert delivery["security_queue_depth"] == 1
        assert delivery["sbom_queue_depth"] == 1
        assert delivery["security_dropped"] == 1
        assert delivery["sbom_dropped"] == 1
        assert delivery["counters"]["security.queue_full"] == 1
        assert delivery["counters"]["sbom.queue_full"] == 1
    finally:
        exporter.close()


def test_jsonl_rotation_and_otel_failure_keep_local_evidence_fail_open(
    monkeypatch, tmp_path
):
    """OTel API failure is visible in delivery counters but does not erase JSONL evidence."""

    _configure_exporter_env(
        monkeypatch,
        tmp_path,
        BEACON_SECURITY_EVIDENCE_FILE_MAX_BYTES=260,
        BEACON_SECURITY_EVIDENCE_FILE_BACKUPS=2,
        BEACON_SECURITY_EVIDENCE_MAX_BYTES=4096,
    )
    from beacon_security.exporter import Exporter

    exporter = Exporter(_identity(), "qa-profile", tmp_path)
    monkeypatch.setattr(
        exporter,
        "_emit_otel",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("qa-otel-failure")),
    )
    try:
        for index in range(6):
            exporter.emit(
                {
                    "schema_version": 1,
                    "event_name": "beacon.security.finding",
                    "evidence_id": f"ev-rotation-{index}",
                    "payload": "x" * 180,
                },
                evidence=True,
            )
        assert exporter.flush(timeout=5.0)
        delivery = exporter.delivery()
        assert delivery["counters"]["security.otel_api_failed"] == 6
        assert delivery["counters"]["beacon.security.file_written"] == 6
    finally:
        exporter.close()

    files = sorted(tmp_path.glob("evidence.jsonl*"))
    assert len(files) >= 2
    records = [record for path in files for record in _read_jsonl(path)]
    assert len(records) >= 3
    assert all(
        record["event_name"] == "beacon.security.finding" for record in records
    )


def test_sbom_budget_waits_without_losing_snapshots_or_blocking_security(
    monkeypatch, tmp_path
):
    from beacon_security.exporter import Exporter

    _configure_exporter_env(
        monkeypatch, tmp_path, BEACON_SECURITY_EXPORT_SBOM_EVENTS_PER_SECOND=1
    )
    exporter = Exporter(_identity(), "deferred", tmp_path)
    emitted, security_delivered = [], threading.Event()

    def capture(body, event, context):
        emitted.append(event)
        if event.get("evidence_id") == "during-sbom-deferral":
            security_delivered.set()

    monkeypatch.setattr(exporter, "_emit_otel", capture)
    try:
        for index in range(3):
            exporter.emit(
                {
                    "event_name": "beacon.security.sbom.snapshot",
                    "sbom_id": "deferred",
                    "revision": index,
                    "dependencies": [{"name": "package", "version": "1.0"}],
                }
            )
        exporter.emit(
            {
                "event_name": "beacon.security.finding",
                "evidence_id": "during-sbom-deferral",
            }
        )
        assert security_delivered.wait(1)
        assert exporter.flush(timeout=4)
        assert [
            event["revision"]
            for event in emitted
            if event.get("sbom_id") == "deferred"
        ] == [0, 1, 2]
        delivery = exporter.delivery()
        assert delivery["sbom_dropped"] == delivery["security_dropped"] == 0
        assert delivery["counters"]["sbom.budget_deferred"] > 0
    finally:
        exporter.close()


def test_delivery_loss_marks_a_real_run_incomplete_for_negative_verification(
    monkeypatch, tmp_path
):
    """A run carrying delivery loss cannot support a negative verification."""

    _configure_exporter_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "BEACON_SECURITY_CONTROL_FILE", str(tmp_path / "control.json")
    )
    from beacon_security.ledger import RuntimeLedger
    from beacon_security.state import SecurityState

    identity = _identity()
    ledger = RuntimeLedger(identity, "qa-profile", tmp_path)
    expires = (
        (datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z")
    )
    control = {
        "schema_version": 1,
        "revision": "start-run",
        "paused": False,
        "run": {
            "run_id": "loss-run",
            "case_id": "loss-case",
            "rule": "sql_injection",
            "expires_at": expires,
            "conditions": {
                "suite": "qa",
                "fixture": "loss",
                "expected_requests": 1,
            },
        },
    }
    (tmp_path / "control.json").write_text(
        json.dumps(control), encoding="utf-8"
    )
    ledger.tick({}, lambda _event: None, force=True)

    request_metadata = {
        "method": "GET",
        "route": "/loss/:id",
        "route_status": "matched",
        "status_code": 200,
        "started_at": "2026-09-08T04:00:00.000Z",
        "ended_at": "2026-09-08T04:00:00.125Z",
        "framework": "asgi",
        "transport": "http",
        "error_type": "",
    }
    state = SecurityState(identity, metadata=request_metadata)
    ledger.begin(state)
    value = "loss-query-" + uuid_for_test()
    state.source(value, "http.request.parameter", "q", "qa#loss")
    event = state.sink(
        "sql_injection",
        "sqlite3.Connection.execute",
        "query",
        value,
        marks=(),
        location="qa#loss",
    )
    state.gap("qa_delivery_loss")
    events = ledger.end(state)
    assert event is None and events
    assert events[0]["request"] == request_metadata
    ledger.record_delivery_loss(events[0])

    control["revision"] = "stop-run"
    control["run"] = None
    (tmp_path / "control.json").write_text(
        json.dumps(control), encoding="utf-8"
    )
    ledger.tick({}, lambda _event: None, force=True)
    run = next(
        item
        for item in _read_json(tmp_path / "runs.json")["runs"]
        if item["run_id"] == "loss-run"
    )
    assert run["last_request"] == request_metadata
    assert run["status"] == "closed"
    assert run["delivery_loss"] == 1
    assert run["incomplete_requests"] >= 1

    baseline = dict(run)
    baseline["run_id"] = "baseline"
    baseline["delivery_loss"] = 0
    baseline["incomplete_requests"] = 0
    candidate = dict(run)
    (tmp_path / "baseline.json").write_text(
        json.dumps(baseline), encoding="utf-8"
    )
    (tmp_path / "candidate.json").write_text(
        json.dumps(candidate), encoding="utf-8"
    )
    cli = Path(__file__).resolve().parent / "fixtures" / "securityctl.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(cli),
            "verify",
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--candidate",
            str(tmp_path / "candidate.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 3
    assert json.loads(completed.stdout)["outcome"] == "inconclusive"


def test_request_fields_are_retained_across_event_finding_and_run(
    monkeypatch, tmp_path
):
    """One observed request keeps the same descriptive context in all snapshots."""

    _configure_exporter_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "BEACON_SECURITY_CONTROL_FILE", str(tmp_path / "control.json")
    )
    from beacon_security.ledger import RuntimeLedger
    from beacon_security.state import SecurityState

    identity = _identity()
    ledger = RuntimeLedger(identity, "qa-profile", tmp_path)
    request = {
        "method": "GET",
        "route": "/shape/:id",
        "route_status": "matched",
        "status_code": 201,
        "started_at": "2026-09-08T04:00:00.000Z",
        "ended_at": "2026-09-08T04:00:00.125Z",
        "framework": "asgi",
        "transport": "http",
        "error_type": "",
    }
    expires = (
        (datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z")
    )
    control = {
        "schema_version": 1,
        "revision": "shape-start",
        "paused": False,
        "run": {
            "run_id": "shape-run",
            "case_id": "shape-case",
            "rule": "sql_injection",
            "expires_at": expires,
            "conditions": {
                "suite": "qa",
                "fixture": "shape",
                "expected_requests": 1,
            },
        },
    }
    (tmp_path / "control.json").write_text(
        json.dumps(control), encoding="utf-8"
    )
    ledger.tick({}, lambda _event: None, force=True)

    state = SecurityState(identity, metadata=request)
    ledger.begin(state)
    query = "shape-query-" + uuid_for_test()
    state.source(query, "http.request.parameter", "q", "qa#shape")
    state.sink(
        "sql_injection",
        "sqlite3.Connection.execute",
        "query",
        query,
        location="qa#shape",
    )
    events = ledger.end(state)
    assert events and events[0]["request"] == request

    control["revision"] = "shape-stop"
    control["run"] = None
    (tmp_path / "control.json").write_text(
        json.dumps(control), encoding="utf-8"
    )
    ledger.tick({}, lambda _event: None, force=True)
    finding = next(
        item
        for item in _read_json(tmp_path / "findings.json")["findings"]
        if item["finding_id"] == events[0]["finding_id"]
    )
    run = next(
        item
        for item in _read_json(tmp_path / "runs.json")["runs"]
        if item["run_id"] == "shape-run"
    )
    expected_fields = {
        "method",
        "route",
        "route_status",
        "status_code",
        "started_at",
        "ended_at",
        "framework",
        "transport",
        "error_type",
    }
    for value in (
        events[0]["request"],
        finding["request"],
        run["last_request"],
    ):
        assert set(value) == expected_fields
        assert value == request


def uuid_for_test() -> str:
    # Keep this helper local to avoid importing uuid in every exporter test.
    import uuid

    return uuid.uuid4().hex


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_shutdown_deadlines_cover_monitor_snapshot_and_writer_close(
    monkeypatch, tmp_path
):
    import os
    import time
    from types import SimpleNamespace

    from beacon_security import runtime
    from beacon_security.exporter import Exporter
    from beacon_security.ledger import RuntimeLedger

    _configure_exporter_env(monkeypatch, tmp_path)
    entered, release = threading.Event(), threading.Event()
    write = RuntimeLedger._write_snapshot

    def blocked_write(self, name, value):
        if name == "findings.json" and not entered.is_set():
            entered.set()
            release.wait(5)
        write(self, name, value)

    monkeypatch.setattr(RuntimeLedger, "_write_snapshot", blocked_write)
    exporter = Exporter(_identity(), "deadline", tmp_path)
    workers = {
        t.ident
        for t in threading.enumerate()
        if t.name == "BeaconSecurity-flush"
    }
    monkeypatch.setattr(
        runtime,
        "_runtime",
        SimpleNamespace(exporter=exporter, closed=False, pid=os.getpid()),
    )
    try:
        assert entered.wait(2)
        with exporter.ledger._lock:
            exporter.ledger._runs["blocked"] = {
                "run_id": "blocked",
                "status": "closed",
                "requests": 1,
            }
            exporter.ledger._runs_revision += 1
        start = time.monotonic()
        assert runtime.flush(timeout=0.02) is False
        assert time.monotonic() - start < 0.3
        for _ in range(3):
            runtime.flush(timeout=0.005)
        assert {
            t.ident
            for t in threading.enumerate()
            if t.name == "BeaconSecurity-flush"
        }.issubset(workers)
        assert exporter._flush_worker.is_alive()
        assert exporter.ledger._runs["blocked"]["incomplete_requests"] > 0
    finally:
        release.set()
        exporter.close(timeout=1)
    saved = json.loads((tmp_path / "runs.json").read_text())["runs"][0]
    assert saved["delivery_loss"] > 0

    closing, closed = threading.Event(), threading.Event()
    other = Exporter(_identity(), "writer-deadline", tmp_path / "writer")

    class BlockedWriter:
        def close(self):
            closing.set()
            closed.wait(5)

    other._writer = BlockedWriter()
    try:
        start = time.monotonic()
        other.close(timeout=0.02)
        assert time.monotonic() - start < 0.3
        assert closing.wait(1)
    finally:
        closed.set()
        other.close(timeout=1)


def test_natural_process_exit_drains_without_creating_threads_in_atexit(
    monkeypatch, tmp_path
):
    import os

    _configure_exporter_env(monkeypatch, tmp_path)
    source = """
import sys, threading
from beacon_security import runtime
import opentelemetry._logs as logs
current = runtime.start([])
current.exporter._monitor_stop.set()
current.exporter._monitor.join(1)
class Provider:
    def force_flush(self, timeout_millis):
        print("provider-flush", flush=True)
        if sys.argv[1] == "blocked":
            threading.Event().wait()
        return True
logs.get_logger_provider = lambda: Provider()
current.exporter.ledger._runs["exit"] = {"run_id": "exit", "status": "closed", "requests": 1}
current.exporter.ledger._runs_revision += 1
"""
    for mode in ("normal", "blocked"):
        output = tmp_path / mode
        result = subprocess.run(
            [sys.executable, "-c", source, mode],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "BEACON_SECURITY_SBOM_ENABLED": "false",
                "BEACON_SECURITY_OUTPUT": str(output),
            },
            timeout=4,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == ["provider-flush"], result.stderr
        assert "Exception ignored in atexit callback" not in result.stderr
        assert (
            json.loads((output / "runs.json").read_text())["runs"][0][
                "requests"
            ]
            == 1
        )
