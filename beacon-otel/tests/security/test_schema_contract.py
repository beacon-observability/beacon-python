from __future__ import annotations

import json
from pathlib import Path

from beacon_security.schema import (
    FINGERPRINT_VERSION,
    PRODUCT,
    SCHEMA_VERSION,
    event_record,
    finding_fingerprint,
    sink_fields,
)
from beacon_security.telemetry import project_event
from jsonschema import Draft202012Validator, FormatChecker

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "spec"
VECTORS = json.loads((FIXTURES / "fingerprint-v1.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((FIXTURES / "beacon-security-event-v2.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
IDENTITY = {
    "application_id": ("app-dc6b8b0dc435531262eedacdf8fe51bd619964caa0e12bb4c29477448fdda8ae"),
    "instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268",
    "service": {"service.name": "orders"},
    "code": {
        "repository": "",
        "commit": "",
        "build_id": "",
        "service_version": "",
    },
    "runtime": {
        "language": "python",
        "implementation": "cpython",
        "version": "3.13.0",
        "os": "linux",
        "architecture": "x64",
        "details": {},
    },
    "identity_status": "configured",
}


def _validate(event: dict) -> None:
    VALIDATOR.validate(event)


def test_pins_beacon_security_schema_version_2_and_fingerprint_version_1() -> None:
    assert SCHEMA_VERSION == 2
    assert FINGERPRINT_VERSION == 1
    assert PRODUCT == "io.beacon.security"
    assert VECTORS["fingerprint_version"] == 1
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_passes_every_shared_fingerprint_v1_vector() -> None:
    for vector in VECTORS["vectors"]:
        value = vector["input"]
        assert (
            finding_fingerprint(
                value["application_id"],
                value["language"],
                value["rule"],
                value["sink"],
                value["source_signatures"],
            )
            == vector["expected"]
        ), vector["name"]


def test_normalizes_sink_aliases_to_canonical_dimensions() -> None:
    assert sink_fields(
        "path_traversal",
        "source",
        "pathlib.Path.read_text",
        "/srv/files.py:10",
    ) == {
        "function": "pathlib.Path.read_text",
        "role": "file_path",
        "location": "/srv/files.py:10",
        "operation": "read",
        "path_role": "source",
        "input_part": "",
    }


def test_emits_only_compact_v2_finding_and_inventory() -> None:
    finding = project_event(
        event_record(
            {
                "event_name": "beacon.security.finding",
                "occurrence_id": "ev-python-test",
                "finding_id": "finding-" + "a" * 64,
                "fingerprint_version": 1,
                "rule": "sql_injection",
                "assessment": "candidate_risk",
                "validation": "unvalidated",
                "severity": "unassigned",
                "confidence": "modeled_flow",
                "execution_observation": "invocation_attempt",
                "precision": "exact",
                "trace_id": "",
                "server_span_id": "",
                "current_span_id": "",
                "trace_flags": 0,
                "sources": [],
                "propagation": [],
                "ranges": [],
                "sink": sink_fields(
                    "sql_injection",
                    "sql_template",
                    "sqlite3.Cursor.execute",
                    "/srv/orders.py:20",
                ),
                "truncated": False,
                "coverage": "modeled_calls_only",
                "coverage_gaps": [],
                "request": {},
                "component": {"name": "unknown-version", "version": "", "hash": "abc"},
                "stack": [],
                "evidence_sampled": True,
                "collection_complete": True,
            },
            IDENTITY,
        )
    )
    assert finding["schema_version"] == 2
    assert finding["source"] == "beacon_security"
    assert finding["event_name"] == "beacon.security.finding"
    assert "application_id" not in finding
    assert "runtime" not in finding
    assert "evidence_id" not in finding
    assert finding["component"] == {"name": "unknown-version", "version": "", "hash": "abc"}
    _validate(finding)

    snapshot = project_event(
        event_record(
            {
                "event_name": "beacon.security.sbom.inventory",
                "started_at": "2026-10-29T00:00:00.000Z",
                "uptime_ms": 1000,
                "dependencies": [],
            },
            IDENTITY,
        )
    )
    assert snapshot["schema_version"] == 2
    assert snapshot["source"] == "beacon_security_sbom"
    assert snapshot["event_name"] == "beacon.security.sbom.inventory"
    _validate(snapshot)
    assert project_event({"event_name": "beacon.security.sbom.health"}) is None
