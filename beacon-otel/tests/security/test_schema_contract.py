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
from jsonschema import Draft202012Validator, FormatChecker

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "spec"
VECTORS = json.loads(
    (FIXTURES / "fingerprint-v1.json").read_text(encoding="utf-8")
)
SCHEMA = json.loads(
    (FIXTURES / "beacon-security-event-v1.schema.json").read_text(
        encoding="utf-8"
    )
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
IDENTITY = {
    "application_id": (
        "app-dc6b8b0dc435531262eedacdf8fe51bd619964caa0e12bb4c29477448fdda8ae"
    ),
    "instance_id": "python-test-instance",
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


def test_pins_beacon_security_schema_and_fingerprint_version_1() -> None:
    assert SCHEMA_VERSION == 1
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


def test_emits_beacon_v1_finding_and_sbom_envelopes() -> None:
    finding = event_record(
        {
            "event_name": "beacon.security.finding",
            "evidence_id": "ev-python-test",
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
            "component": {},
            "stack": [],
        },
        IDENTITY,
    )
    assert finding["schema_version"] == 1
    assert finding["source"] == "beacon_security"
    assert finding["event_name"] == "beacon.security.finding"
    assert finding["application_id"] == IDENTITY["application_id"]
    assert finding["runtime"]["language"] == "python"
    _validate(finding)

    snapshot = event_record(
        {
            "event_name": "beacon.security.sbom.snapshot",
            "sbom_id": "urn:uuid:python-test",
            "revision": 1,
            "release_id": "release-python-test",
            "status": "current",
            "completeness": "incomplete",
            "reasons": ["runtime_dependency_graph_incomplete"],
            "component_count": 0,
            "part_index": 0,
            "part_count": 1,
            "dependencies": [],
        },
        IDENTITY,
    )
    assert snapshot["schema_version"] == 1
    assert snapshot["source"] == "beacon_security_sbom"
    assert snapshot["event_name"] == "beacon.security.sbom.snapshot"
    _validate(snapshot)
