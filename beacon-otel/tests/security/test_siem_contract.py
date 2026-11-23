from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from beacon_security import siem
from beacon_security._sbom_events import dependency_snapshot
from beacon_security.exporter import Exporter
from jsonschema import Draft202012Validator, FormatChecker

FIXTURES = Path(__file__).parent / "fixtures" / "spec"
VALIDATOR = Draft202012Validator(
    json.loads(
        (Path(siem.__file__).with_name("siem-v1.schema.json")).read_text()
    ),
    format_checker=FormatChecker(),
)
VECTORS = json.loads((FIXTURES / "siem-v1.json").read_text())["vectors"]
IDENTITY = {
    "instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268",
    "service": {"service.name": "orders", "tenant.id": "configured-tenant"},
}


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_shared_vectors_without_unavailable_request_enrichment(
    vector: dict[str, Any],
) -> None:
    raw = (FIXTURES / vector["input"]).read_text(encoding="utf-8")
    expected = json.loads(
        (FIXTURES / vector["expected"]).read_text(encoding="utf-8")
    )
    # Runtime has no trusted per-request principal, tenant binding or client IP.
    if vector["context"]:
        expected.update(tenant_id="configured-tenant", actor="", ip="")
    result = siem.project(raw, vector["resource"])
    assert {key: result[key] for key in expected} == expected
    assert result["instance_id"] == json.loads(raw)["instance_id"]
    for key in ("trace_id", "span_id"):
        if key in json.loads(raw):
            assert result[key] == json.loads(raw)[key]
    VALIDATOR.validate(result)
    assert set(result) == set(expected) | (
        set(json.loads(raw)) & set(siem.CORRELATION_FIELDS)
    )
    assert result["message"] == raw
    assert (
        siem.project(raw, vector["resource"])["event_id"] == result["event_id"]
    )


def test_raw_preservation_unicode_escaping_and_absent_identity() -> None:
    body = json.loads((FIXTURES / "examples/finding-v2.json").read_text())
    body["attack_evidence"] = {
        "status": "suspected",
        "reason": '中文 "quoted"\nline',
    }
    raw = json.dumps(body, ensure_ascii=False, indent=2) + "\n"
    result = siem.project(raw, {})
    assert result["message"] == raw
    assert result["outcome"] == "unknown"
    assert result["tenant_id"] == "default"
    assert result["service"] == result["actor"] == result["ip"] == ""
    VALIDATOR.validate(result)


def test_export_boundary_and_final_byte_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED", "true")
    monkeypatch.setenv(
        "BEACON_SECURITY_EVIDENCE_FILE", str(tmp_path / "events.jsonl")
    )
    body = json.loads((FIXTURES / "examples/finding-v2.json").read_text())
    logged = []
    exporter = Exporter(IDENTITY, "test", tmp_path)
    monkeypatch.setattr(
        exporter, "_emit_otel", lambda raw, *_: logged.append(raw)
    )
    try:
        exporter.emit(body, evidence=True)
        assert exporter.flush(5)
        assert len(logged) == 1
        result = json.loads(logged[0])
        VALIDATOR.validate(result)
        assert result["service"] == "orders"
        assert result["tenant_id"] == "configured-tenant"
        raw = result["message"]
        assert json.loads(raw)["finding_id"] == body["finding_id"]
        # v2 fits, but the lossless SIEM envelope does not: explicit rejection.
        exporter._max_bytes = len(raw.encode("utf-8"))
        exporter.emit(body, evidence=True)
        assert exporter.flush(5)
        assert len(logged) == 1
        assert exporter.delivery()["counters"]["security.failed"] == 1
        assert (tmp_path / "events.jsonl").read_text().splitlines() == logged
    finally:
        exporter.close()


def test_inventory_multipart_uses_final_envelope_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_EVIDENCE_MAX_BYTES", "1500")
    records = [
        {
            "type": "library",
            "name": '依赖"' + str(i),
            "version": "1",
            "properties": [
                {"name": "beacon:security:sbom:loaded", "value": "true"}
            ],
        }
        for i in range(30)
    ]
    events = dependency_snapshot(
        {"started_at": "2026-11-02T00:00:00Z", "uptime_ms": 1000},
        records,
        IDENTITY,
    )
    assert len(events) > 1
    assert sum(len(event["dependencies"]) for event in events) == len(records)
    assert len(
        {row["name"] for event in events for row in event["dependencies"]}
    ) == len(records)
    ids = set()
    for index, event in enumerate(events):
        assert event["part_index"] == index
        assert event["part_count"] == len(events)
        raw = json.dumps(
            event, ensure_ascii=False, separators=(",", ":")
        ).encode()
        encoded = siem.encode(raw, IDENTITY)
        assert len(encoded) <= 1500
        result = json.loads(encoded)
        VALIDATOR.validate(result)
        ids.add(result["event_id"])
    assert len(ids) == len(events)


def test_real_otel_http_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from opentelemetry.exporter.otlp.proto.http._log_exporter import (
        OTLPLogExporter,
    )
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
        ExportLogsServiceRequest,
    )
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
    from opentelemetry.sdk.resources import Resource

    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received.append(
                self.rfile.read(int(self.headers["Content-Length"]))
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Receiver)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    provider = LoggerProvider(resource=Resource.create(IDENTITY["service"]))
    provider.add_log_record_processor(
        SimpleLogRecordProcessor(
            OTLPLogExporter(
                endpoint=f"http://127.0.0.1:{server.server_port}/v1/logs",
                timeout=2,
            )
        )
    )
    monkeypatch.setenv("BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED", "true")
    exporter = Exporter(IDENTITY, "transport", tmp_path)
    exporter._otel_logger = provider.get_logger("io.beacon.security")
    try:
        event = json.loads((FIXTURES / "examples/finding-v2.json").read_text())
        exporter.emit(event)
        assert exporter.flush(5)
        assert len(received) == 1
        request = ExportLogsServiceRequest.FromString(received[0])
        resource_logs = request.resource_logs[0]
        scope_logs = resource_logs.scope_logs[0]
        record = scope_logs.log_records[0]
        assert scope_logs.scope.name == "io.beacon.security"
        assert record.severity_number == 9
        result = json.loads(record.body.string_value)
        VALIDATOR.validate(result)
        assert result["event_id"] == event["occurrence_id"]
        assert result["trace_id"] == event["trace_id"]
        assert result["span_id"] == event["span_id"]
        assert record.span_id.hex() == result["span_id"]
        assert "server_span_id" not in result
        assert "current_span_id" not in result
        assert "server_span_id" not in json.loads(result["message"])
        assert "current_span_id" not in json.loads(result["message"])
        assert result["instance_id"] == event["instance_id"]
        assert record.trace_id.hex() == event["trace_id"]
        assert {a.key: a.value.string_value for a in record.attributes}[
            "source"
        ] == "beacon_security"
    finally:
        exporter.close()
        provider.shutdown()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_profile_retains_default_no_evidence_filter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(
        "BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED", raising=False
    )
    exporter = Exporter(IDENTITY, "filter", tmp_path)
    logged = []
    monkeypatch.setattr(
        exporter, "_emit_otel", lambda *args: logged.append(args)
    )
    try:
        event = json.loads((FIXTURES / "examples/finding-v2.json").read_text())
        assert event["attack_evidence"]["status"] == "no_evidence"
        exporter.emit(event)
        assert exporter.flush(5)
        assert logged == []
        assert exporter.delivery()["dropped"] == 0
        assert exporter.delivery()["counters"].get("security.queued", 0) == 0
    finally:
        exporter.close()


def test_truncated_v2_is_preserved_without_second_truncation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_EVIDENCE_MAX_BYTES", "4500")
    event = json.loads((FIXTURES / "examples/finding-v2.json").read_text())
    event["stack"] = [{"function": "x" * 10000}]
    exporter = Exporter(IDENTITY, "truncated", tmp_path)
    logged: list[str] = []
    monkeypatch.setattr(
        exporter, "_emit_otel", lambda raw, *_: logged.append(raw)
    )
    try:
        exporter.emit(event)
        assert exporter.flush(5)
        assert len(logged) == 1
        envelope = json.loads(logged[0])
        VALIDATOR.validate(envelope)
        body = json.loads(envelope["message"])
        assert body["truncated"] is True
        assert body["evidence_sampled"] is False
        assert body["truncation_reason"] == "record_byte_limit"
        assert "stack" not in body
        assert len(logged[0].encode()) <= 4500
    finally:
        exporter.close()


def test_detected_span_takes_precedence_over_request_context() -> None:
    from opentelemetry.trace import SpanContext, TraceFlags, TraceState

    request_context = SpanContext(
        trace_id=1,
        span_id=2,
        is_remote=False,
        trace_flags=TraceFlags(1),
        trace_state=TraceState(),
    )
    event = {"trace_id": f"{1:032x}", "span_id": f"{3:016x}", "trace_flags": 1}
    context = Exporter._otel_context(request_context, event)
    from opentelemetry.trace import get_current_span

    detected = get_current_span(context).get_span_context()
    assert detected.trace_id == 1
    assert detected.span_id == 3
    assert int(detected.trace_flags) == 1


def test_missing_span_does_not_fabricate_export_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED", "true")
    event = json.loads((FIXTURES / "examples/finding-v2.json").read_text())
    event.pop("span_id")
    logged: list[str] = []
    exporter = Exporter(IDENTITY, "missing-span", tmp_path)
    monkeypatch.setattr(
        exporter, "_emit_otel", lambda raw, *_: logged.append(raw)
    )
    try:
        exporter.emit(event)
        assert exporter.flush(5)
        assert len(logged) == 1
        body = json.loads(logged[0])
        VALIDATOR.validate(body)
        assert "span_id" not in body
        assert "server_span_id" not in body
        assert "current_span_id" not in body
        payload = json.loads(body["message"])
        assert "span_id" not in payload
        assert "server_span_id" not in payload
        assert "current_span_id" not in payload
    finally:
        exporter.close()
