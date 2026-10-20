# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from beacon_security.ledger import RuntimeLedger
from beacon_security.state import SecurityState

IDENTITY = {
    "application_id": "occurrence-app",
    "instance_id": "occurrence-instance",
}


def configure(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "false")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")


def occurrence(
    ledger: RuntimeLedger, index: int, location: str = "query"
) -> dict:
    state = SecurityState(IDENTITY)
    ledger.begin(state)
    state.trace_id = f"{index:032x}" if index else ""
    state.server_span_id = f"{index:016x}" if index else ""
    value = ("_" + f"input-{index}")[1:]
    state.source(value, "http.request.parameter", "q")
    try:
        event = state.sink(
            "sql_injection", "db.execute", "template", value, location=location
        )
        assert event is not None
        assert (
            state.sink(
                "sql_injection",
                "db.execute",
                "template",
                value,
                location=location,
            )
            is None
        )
        assert len(state.pending) == 1
        result = ledger.end(state)
        assert len(result) == 1
        assert event["sources"]  # Sampling must not mutate request accounting.
        return result[0]
    finally:
        state.close()


def test_distinct_requests_keep_ids_counts_and_missing_trace(
    monkeypatch, tmp_path
) -> None:
    configure(monkeypatch, tmp_path)
    ledger = RuntimeLedger(IDENTITY, "occurrences", tmp_path)
    events = [occurrence(ledger, index) for index in (1, 2, 0)]
    assert len({event["finding_id"] for event in events}) == 1
    assert len({event["occurrence_id"] for event in events}) == 3
    assert [event["occurrences_total"] for event in events] == [1, 2, 3]
    assert [event["trace_id"] for event in events] == [
        f"{1:032x}",
        f"{2:032x}",
        "",
    ]
    assert [event["evidence_sampled"] for event in events] == [
        True,
        False,
        False,
    ]
    for event in events[1:]:
        assert event["occurrence_id"] == event["evidence_id"]
        assert event["aggregation_status"] == "tracked"
        assert event["truncation_reason"] == "evidence_sampled_out"
        assert all(
            event[field] == []
            for field in ("sources", "propagation", "ranges", "stack")
        )


def test_aggregation_saturation_preserves_occurrence(
    monkeypatch, tmp_path
) -> None:
    configure(monkeypatch, tmp_path)
    ledger = RuntimeLedger(IDENTITY, "capacity", tmp_path)
    ledger._max_findings = 1
    occurrence(ledger, 1)
    event = occurrence(ledger, 2, "another-query")
    assert event["aggregation_status"] == "capacity_exceeded"
    assert event["evidence_sample_reason"] == "finding_capacity"
    assert event["evidence_sampled"] is False
    assert "occurrences_total" not in event
    assert event["trace_id"] == f"{2:032x}"
    assert ledger.health({})["counts"]["finding_capacity_dropped"] == 1


def test_concurrent_requests_are_independent(monkeypatch, tmp_path) -> None:
    configure(monkeypatch, tmp_path)
    ledger = RuntimeLedger(IDENTITY, "concurrency", tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        events = list(
            pool.map(lambda index: occurrence(ledger, index), range(1, 13))
        )
    assert len({event["occurrence_id"] for event in events}) == 12
    assert {event["occurrences_total"] for event in events} == set(
        range(1, 13)
    )
    assert [event["trace_id"] for event in events] == [
        f"{index:032x}" for index in range(1, 13)
    ]


def test_lightweight_occurrences_reach_otlp_http(
    monkeypatch, tmp_path
) -> None:
    from beacon_security.exporter import Exporter

    from opentelemetry.exporter.otlp.proto.http._log_exporter import (
        OTLPLogExporter,
    )
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
        ExportLogsServiceRequest,
    )
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor

    configure(monkeypatch, tmp_path)
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            request = ExportLogsServiceRequest()
            request.ParseFromString(
                self.rfile.read(int(self.headers["Content-Length"]))
            )
            received.extend(
                log
                for resource in request.resource_logs
                for scope in resource.scope_logs
                for log in scope.log_records
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    provider = LoggerProvider(shutdown_on_exit=False)
    provider.add_log_record_processor(
        SimpleLogRecordProcessor(
            OTLPLogExporter(
                endpoint=f"http://127.0.0.1:{server.server_port}/v1/logs",
                timeout=2,
            )
        )
    )
    exporter = Exporter(IDENTITY, "otlp-occurrences", tmp_path)
    exporter._otel_logger = provider.get_logger("io.beacon.security")
    try:
        for index in (1, 2, 3):
            exporter.emit(occurrence(exporter.ledger, index), evidence=True)
        assert exporter.flush(timeout=5)
        findings = [
            (log, json.loads(log.body.string_value))
            for log in received
            if json.loads(log.body.string_value).get("event_name")
            == "beacon.security.finding"
        ]
        assert len(findings) == 3
        assert len({event["finding_id"] for _, event in findings}) == 1
        assert len({event["occurrence_id"] for _, event in findings}) == 3
        assert [event["evidence_sampled"] for _, event in findings] == [
            True,
            False,
            False,
        ]
        assert [log.trace_id.hex() for log, _ in findings] == [
            f"{index:032x}" for index in (1, 2, 3)
        ]
        for _, event in findings:
            assert event["trace_availability"] == "not_guaranteed_by_trace_id"
    finally:
        exporter.close()
        provider.shutdown()
        server.shutdown()
        server.server_close()
        thread.join(2)
