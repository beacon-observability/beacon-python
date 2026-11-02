# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json

import pytest
from beacon_security.exporter import Exporter
from beacon_security.state import SecurityState

IDENTITY = {
    "application_id": "export-policy",
    "instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268",
}
KEY = "BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED"


@pytest.mark.parametrize("setting", [None, "false", "invalid", "true"])
def test_export_policy_covers_otel_jsonl_and_queue_budgets(
    monkeypatch, tmp_path, setting
):
    monkeypatch.delenv(KEY, raising=False)
    if setting is not None:
        monkeypatch.setenv(KEY, setting)
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    evidence = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("BEACON_SECURITY_EVIDENCE_FILE", str(evidence))
    logged = []
    exporter = Exporter(IDENTITY, "export-policy", tmp_path)
    monkeypatch.setattr(
        exporter,
        "_emit_otel",
        lambda _body, event, _context: logged.append(event),
    )
    try:
        for status in ("no_evidence", "unknown", "suspected"):
            exporter.emit(
                {
                    "event_name": "beacon.security.finding",
                    "occurrence_id": status,
                    "finding_id": "finding-" + "a" * 64,
                    "fingerprint_version": 1,
                    "rule": "sql_injection",
                    "attack_evidence": {"status": status, "reason": "test"},
                },
                evidence=True,
            )
        exporter.emit(
            {
                "event_name": "beacon.security.sbom.inventory",
                "started_at": "2026-11-02T00:00:00Z",
                "uptime_ms": 1000,
                "dependencies": [],
            }
        )
        assert exporter.flush(timeout=5)
    finally:
        exporter.close()
    expected = {"unknown", "suspected"}
    if setting == "true":
        expected.add("no_evidence")
    assert {
        e["occurrence_id"] for e in logged if "occurrence_id" in e
    } == expected
    assert len(logged) == len(expected) + 1
    records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert {e["occurrence_id"] for e in records} == expected
    assert exporter.delivery()["counters"]["security.queued"] == len(expected)
    assert exporter.delivery()["dropped"] == 0


@pytest.mark.parametrize(
    "fragment, status",
    [("`unsupported`", "unknown"), ("1 OR 1=1", "suspected")],
)
def test_filtered_observation_does_not_prevent_same_request_upgrade(
    monkeypatch, tmp_path, fragment, status
):
    monkeypatch.delenv(KEY, raising=False)
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    exporter = Exporter(IDENTITY, "export-upgrade", tmp_path)
    logged = []
    monkeypatch.setattr(
        exporter,
        "_emit_otel",
        lambda _body, event, _context: logged.append(event),
    )
    state = SecurityState(IDENTITY)
    exporter.ledger.begin(state)
    try:

        def detect(value):
            value = ("_" + value)[1:]
            state.source(value, "http.request.parameter", "id")
            return state.sink(
                "sql_injection",
                "db.execute",
                "template",
                value,
                location="app:query",
            )

        first = detect("12")
        assert first["attack_evidence"]["status"] == "no_evidence"
        exporter.emit(first)
        assert exporter.delivery()["counters"].get("security.queued", 0) == 0
        upgrade = detect(fragment)
        assert upgrade["attack_evidence"]["status"] == status
        assert upgrade["occurrence_id"] == first["occurrence_id"]
        for event in exporter.ledger.end(state):
            exporter.emit(event)
        assert exporter.flush(timeout=5)
        assert [e["attack_evidence"]["status"] for e in logged] == [status]
    finally:
        state.close()
        exporter.close()
