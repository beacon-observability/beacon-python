from __future__ import annotations

import importlib
import sqlite3

from beacon_security.transform import transform


def _start_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "none")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    runtime = importlib.import_module("beacon_security.runtime")
    if getattr(runtime, "_runtime", None) is not None:
        runtime.stop()
    runtime = importlib.reload(runtime)
    state = runtime.start_request({"route": "/sqlite-native"})
    token = runtime.attach_state(state)
    return runtime, state, token


def _execute_transformed(source_text, filename, runtime):
    tree = transform(source_text, filename, "security_sample.sqlite_native")
    namespace = {
        "__name__": "security_sample.sqlite_native",
        "__file__": filename,
        "runtime": runtime,
    }
    exec(compile(tree, filename, "exec"), namespace)
    return namespace


def test_sqlite_native_connection_cursor_types_and_chained_execute(
    monkeypatch, tmp_path
):
    """Native sqlite calls must be observed without changing DB-API result types."""

    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    first_query = "".join(("select", " 1"))
    second_query = "".join(("select", " 1"))
    assert first_query == second_query
    assert first_query is not second_query
    runtime.source(first_query, "http.request.parameter", "q1")
    runtime.source(second_query, "http.request.parameter", "q2")

    namespace = _execute_transformed(
        """
import sqlite3

def execute_chain(left, right):
    connection = sqlite3.connect(":memory:")
    chained_cursor = connection.execute(left).execute(right)
    return connection, chained_cursor
""",
        "sqlite_native_fixture.py",
        runtime,
    )
    connection = None
    try:
        connection, chained_cursor = namespace["execute_chain"](
            first_query, second_query
        )
        assert type(connection) is sqlite3.Connection
        assert type(chained_cursor) is sqlite3.Cursor

        observed = [
            event
            for event in state.pending
            if event["rule"] == "sql_injection"
        ]
        observed_functions = {event["sink"]["function"] for event in observed}
        assert "sqlite3.Connection.execute" in observed_functions
        assert "sqlite3.Cursor.execute" in observed_functions
        observed_signatures = {
            f"{source['type']}|{source['name']}"
            for event in observed
            for source in event["sources"]
        }
        assert {
            "http.request.parameter|q1",
            "http.request.parameter|q2",
        }.issubset(observed_signatures)
    finally:
        if connection is not None:
            connection.close()
        runtime.end_request(state)
        runtime.detach_state(token)
