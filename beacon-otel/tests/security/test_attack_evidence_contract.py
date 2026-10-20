# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from beacon_security import attack_evidence, config
from beacon_security.ledger import RuntimeLedger
from beacon_security.state import SecurityState
from beacon_security.tracking import Mark

CASES = json.loads(
    (Path(__file__).parent / "fixtures/attack-analysis.json").read_text()
)
IDENTITY = {"application_id": "attack-app", "instance_id": "attack-instance"}


@pytest.fixture(autouse=True)
def enable_selector(monkeypatch) -> None:
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")


def mark(text: str, source: str) -> Mark:
    start = text.index(source)
    return Mark("source", 1, start, start + len(source))


@pytest.mark.parametrize("case", CASES["sql"])
def test_sql_evidence_uses_context_not_keywords(
    monkeypatch, case: dict
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    result = attack_evidence.analyze(
        "sql_injection",
        "sql_template",
        case["text"],
        [mark(case["text"], case["input"])],
    )
    assert result["status"] == case["status"]
    assert result["outcome"] == "not_assessed"
    assert case["text"] not in json.dumps(result)


@pytest.mark.parametrize("case", CASES["shell"])
def test_posix_shell_context_preserves_quoting(case: dict) -> None:
    result = attack_evidence.analyze(
        "command_injection",
        "shell_script",
        case["text"],
        [mark(case["text"], case["input"])],
        "sh",
    )
    assert result["status"] == case["status"]
    assert result["outcome"] == "not_assessed"


def test_missing_configuration_imprecision_and_budgets_preserve_uncertainty(
    monkeypatch,
) -> None:
    query = "SELECT 'guest'"
    taint = mark(query, "guest")
    monkeypatch.delenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", raising=False)
    assert (
        attack_evidence.analyze(
            "sql_injection", "sql_template", query, [taint]
        )["reason"]
        == "sql_dialect_unsupported"
    )
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    for changed in (
        replace(taint, exact=False),
        replace(taint, end=None),
        replace(taint, unit="byte"),
        replace(taint, start=-1),
    ):
        assert (
            attack_evidence.analyze(
                "sql_injection", "sql_template", query, [changed]
            )["reason"]
            == "taint_imprecise"
        )
    for value, marks in (("x" * 8193, [taint]), (query, [taint] * 65)):
        assert (
            attack_evidence.analyze(
                "sql_injection", "sql_template", value, marks
            )["reason"]
            == "analysis_budget"
        )
    assert (
        attack_evidence.analyze(
            "command_injection",
            "shell_script",
            "echo guest",
            [taint],
            "cmd.exe",
        )["reason"]
        == "shell_dialect_unsupported"
    )
    assert (
        attack_evidence.analyze(
            "sql_injection", "sql_template", b"SELECT 'guest'", [taint]
        )["status"]
        == "unknown"
    )
    for rule, role in (
        ("ssrf", "destination_address"),
        ("path_traversal", "file_path"),
        ("command_execution", "executable"),
    ):
        assert (
            attack_evidence.analyze(rule, role, "guest", [taint])["status"]
            == "unknown"
        )
    assert (
        attack_evidence.analyze(
            "command_execution", "argument", "guest", [taint]
        )["status"]
        == "no_evidence"
    )
    assert (
        attack_evidence.analyze(
            "http_request_input", "path_or_query", "guest", [taint]
        )["status"]
        == "no_evidence"
    )
    before = config.profile()
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "unknown")
    assert config.profile() != before


def detect(state: SecurityState, fragment: str) -> dict | None:
    query = "SELECT * FROM users WHERE id=" + fragment
    state.source(query, "http.request.parameter", "q")
    original = state.marks(query)[0]
    marks = (replace(original, start=query.index(fragment)),)
    return state.sink(
        "sql_injection",
        "db.execute",
        "template",
        query,
        marks=marks,
        location="query",
    )


def test_same_request_upgrades_keep_identity_and_count_once(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "false")
    ledger = RuntimeLedger(IDENTITY, "attack", tmp_path)
    state = SecurityState(IDENTITY)
    ledger.begin(state)
    try:
        first = detect(state, "12")
        assert first["attack_evidence"]["status"] == "no_evidence"
        unknown = detect(state, "customer_id")
        assert unknown["attack_evidence"]["status"] == "unknown"
        assert detect(state, "14") is None
        upgrade = detect(state, "1 OR 1=1")
        assert upgrade["attack_evidence"]["status"] == "suspected"
        assert {
            first["evidence_id"],
            unknown["evidence_id"],
            upgrade["evidence_id"],
        } == {first["evidence_id"]}
        assert len(state.pending) == 1
        assert detect(state, "16") is None
        event = ledger.end(state)[0]
        assert event["occurrences_total"] == 1
        finding = ledger._findings[event["finding_id"]]
        assert finding["attack_evidence_counts"] == {
            "unknown": 0,
            "no_evidence": 0,
            "suspected": 1,
        }
    finally:
        state.close()


def test_request_evidence_and_representative_are_independent(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    monkeypatch.setenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "false")
    ledger = RuntimeLedger(IDENTITY, "attack", tmp_path)
    events = []
    for index, fragment in enumerate(
        ("12", "1 OR 1=1", "14", "customer_id"), 1
    ):
        state = SecurityState(IDENTITY)
        ledger.begin(state)
        state.trace_id = f"{index:032x}"
        try:
            detect(state, fragment)
            events.append(ledger.end(state)[0])
        finally:
            state.close()
    assert [event["attack_evidence"]["status"] for event in events] == [
        "no_evidence",
        "suspected",
        "no_evidence",
        "unknown",
    ]
    assert [event["evidence_sampled"] for event in events] == [
        True,
        True,
        False,
        False,
    ]
    assert events[1]["evidence_sample_reason"] == "evidence_upgrade"
    assert len({event["finding_id"] for event in events}) == 1
    assert len({event["evidence_id"] for event in events}) == 4
    finding = ledger._findings[events[0]["finding_id"]]
    assert finding["attack_evidence_counts"] == {
        "unknown": 1,
        "no_evidence": 2,
        "suspected": 1,
    }
    assert finding["representative"]["trace_id"] == events[1]["trace_id"]
    assert finding["last_trace_id"] == events[-1]["trace_id"]
    assert finding["strongest_attack_evidence"]["status"] == "suspected"
    assert all(
        event["attack_evidence"]["outcome"] == "not_assessed"
        for event in events
    )


def test_shell_binding_uses_actual_executable() -> None:
    from beacon_security.sinks.process import _shell_dialect

    assert _shell_dialect(["/bin/sh", "-c", "echo guest"], False, None) == "sh"
    assert (
        _shell_dialect(["/bin/sh", "-c", "echo guest"], False, "/bin/fish")
        == "fish"
    )
    assert _shell_dialect("echo guest", True, "/bin/bash") == "bash"
    assert _shell_dialect("echo guest", None, None) == "unknown"


def test_live_sqlite_separates_bound_values_from_dynamic_templates(
    monkeypatch, tmp_path
) -> None:
    from test_sql_native_contract import _execute_transformed, _start_runtime

    monkeypatch.setenv("BEACON_SECURITY_ANALYSIS_SQL_DIALECT", "ansi")
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    namespace = _execute_transformed(
        """
import sqlite3

def queries(value):
    connection = sqlite3.connect(":memory:")
    try:
        bound = connection.execute("SELECT ?", (value,)).fetchone()[0]
        dynamic = "SELECT 1 WHERE 1=" + value
        result = connection.execute(dynamic).fetchone()[0]
        return bound, result
    finally:
        connection.close()
""",
        "attack_sqlite_fixture.py",
        runtime,
    )
    value = ("_" + "1 OR 1=1")[1:]
    try:
        runtime.source(value, "http.request.parameter", "q")
        assert namespace["queries"](value) == (value, 1)
        events = [
            event
            for event in state.pending
            if event["rule"] == "sql_injection"
        ]
        assert len(events) == 1
        assert events[0]["attack_evidence"]["status"] == "suspected"
        assert events[0]["attack_evidence"]["outcome"] == "not_assessed"
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()
