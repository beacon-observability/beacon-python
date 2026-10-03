#!/usr/bin/env python3
"""Run controlled client-contract proofs for the Python v0.2.0 instrumentor.

The runner uses only loopback HTTP and read-only SQL.  PostgreSQL and MySQL
cases are reported as ``unverified`` unless the caller supplies task-owned
connection settings; no existing database is discovered or modified.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import http.server
import importlib
import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
if str(FIXTURES_ROOT) not in sys.path:
    sys.path.insert(0, str(FIXTURES_ROOT))


class Unverified(RuntimeError):
    """A proof whose external prerequisite was deliberately not supplied."""


class _LoopbackHandler(http.server.BaseHTTPRequestHandler):
    response = b"beacon-security-client-qa"

    def do_GET(self):  # noqa: N802 - stdlib handler API
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.response)))
        self.end_headers()
        self.wfile.write(self.response)

    def log_message(self, _format, *_args):
        return


@contextlib.contextmanager
def loopback_server():
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), _LoopbackHandler
    )
    thread = threading.Thread(
        target=server.serve_forever, name="client-qa-http", daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return type(value).__name__


def _event_snapshot(state) -> list[dict[str, Any]]:
    # State.close() deliberately releases evidence.  Copy the JSON-shaped
    # events before end_request so the report can classify the actual call.
    return copy.deepcopy(list(state.pending))


def _snapshot(state) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "beacon_security",
        "events": _event_snapshot(state),
        "source_signatures": dict(state.source_signatures),
        "risk_source_signatures": dict(state.risk_source_signatures),
        "sink_counts": dict(state.sink_counts),
        "gaps": sorted(state.gaps),
        "truncated": bool(state.truncated),
    }


class Harness:
    def __init__(self, output: Path):
        self.output = output
        self.runtime = None
        self.sinks = None
        self.adapters: list[str] = []

    def start(self) -> None:
        from beacon_security import runtime, sinks

        # A pytest process can have loaded another contract module first.  The
        # explicit restore/reload keeps this runner's lifecycle deterministic.
        with contextlib.suppress(BaseException):
            sinks.uninstall()
        if getattr(runtime, "_runtime", None) is not None:
            with contextlib.suppress(BaseException):
                runtime.stop()
        self.runtime = importlib.reload(runtime)
        with contextlib.suppress(BaseException):
            sinks.uninstall()
        self.sinks = sinks
        self.adapters = list(sinks.install())
        self.runtime.start(self.adapters)

    def close(self) -> None:
        if self.runtime is not None:
            with contextlib.suppress(BaseException):
                self.runtime.stop()
        if self.sinks is not None:
            with contextlib.suppress(BaseException):
                self.sinks.uninstall()

    @contextlib.contextmanager
    def state(self, route: str):
        state = self.runtime.start_request({"method": "GET", "route": route})
        if state is None:
            raise Unverified("runtime did not start a configured request")
        token = self.runtime.attach_state(state)
        error = None
        try:
            yield state
        except BaseException as caught:
            error = caught
            raise
        finally:
            if not state.closed:
                self.runtime.end_request(state, error=error)
            self.runtime.detach_state(token)


def _taint_component(
    runtime,
    state,
    carrier: str,
    source_value: str,
    name: str,
    start: int,
    end: int,
) -> str:
    """Attach a bounded source range to a carrier without string searching."""

    source = runtime.source(source_value, "http.request.parameter", name)
    marks = state.marks(source)
    if not marks:
        raise AssertionError("source mark was not retained")
    derived = state.derive(
        marks, "client_qa.component", shift=start, start=0, end=end, exact=True
    )
    state.put(carrier, derived)
    return carrier


def _taint_full(runtime, value: str, name: str) -> str:
    return runtime.source(value, "http.request.parameter", name)


def _events(
    snapshot: dict[str, Any], rule: str | None = None
) -> list[dict[str, Any]]:
    events = snapshot["events"]
    return [
        event for event in events if rule is None or event.get("rule") == rule
    ]


def _assert_no_raw(event: dict[str, Any], secret: str) -> None:
    encoded = json.dumps(event, sort_keys=True)
    assert secret not in encoded


def _http_result(
    snapshot: dict[str, Any], body: bytes, secret: str, *, expect_ssrf: bool
) -> dict[str, Any]:
    assert body == _LoopbackHandler.response
    ssrf = _events(snapshot, "ssrf")
    request_input = _events(snapshot, "http_request_input")
    if expect_ssrf:
        assert any(
            event["sink"]["role"] == "destination_address" for event in ssrf
        )
    else:
        assert not ssrf
    if not expect_ssrf:
        assert request_input
    for event in ssrf + request_input:
        _assert_no_raw(event, secret)
    return {
        "ssrf_events": len(ssrf),
        "http_request_input_events": len(request_input),
        "response_body_untainted": True,
    }


def _assert_response_body_untainted(state, body: bytes) -> None:
    assert body == _LoopbackHandler.response
    assert not state.marks(body)


def _run_http_requests(harness: Harness, base: str) -> dict[str, Any]:
    import requests

    runtime = harness.runtime
    with harness.state("/client-qa/requests") as state:
        query = "qa-requests-" + uuid.uuid4().hex
        url = f"{base}/fixed?q={query}"
        _taint_component(
            runtime,
            state,
            url,
            query,
            "requests.query",
            url.index(query),
            len(query),
        )
        request = requests.Request("GET", url)
        with requests.Session() as session:
            prepared = session.prepare_request(request)
            assert not state.pending
            response = session.send(prepared, timeout=5)
            body = response.content
            _assert_response_body_untainted(state, body)
        fixed = _snapshot(state)
    details = _http_result(fixed, body, query, expect_ssrf=False)

    with harness.state("/client-qa/requests-polluted-host") as state:
        polluted = _taint_full(runtime, f"{base}/polluted", "requests.host")
        with requests.Session() as session:
            response = session.get(polluted, timeout=5)
            body = response.content
            _assert_response_body_untainted(state, body)
        positive = _snapshot(state)
    details["polluted_host"] = _http_result(
        positive, body, polluted, expect_ssrf=True
    )
    return details


def _run_httpx_sync(harness: Harness, base: str) -> dict[str, Any]:
    import httpx

    runtime = harness.runtime
    with harness.state("/client-qa/httpx-sync") as state:
        query = "qa-httpx-sync-" + uuid.uuid4().hex
        with httpx.Client(trust_env=False, timeout=5) as client:
            request = client.build_request(
                "GET",
                f"{base}/fixed",
                params={
                    "q": runtime.source(
                        query, "http.request.parameter", "httpx.sync.query"
                    )
                },
            )
            assert not state.pending
            response = client.send(request)
            body = response.content
            _assert_response_body_untainted(state, body)
        snapshot = _snapshot(state)
    return _http_result(snapshot, body, query, expect_ssrf=False)


def _run_httpx_async(harness: Harness, base: str) -> dict[str, Any]:
    import httpx

    runtime = harness.runtime

    async def exercise():
        query = "qa-httpx-async-" + uuid.uuid4().hex
        async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
            request = client.build_request(
                "GET",
                f"{base}/fixed",
                params={
                    "q": runtime.source(
                        query, "http.request.parameter", "httpx.async.query"
                    )
                },
            )
            assert not harness.runtime.current_state().pending
            response = await client.send(request)
            body = response.content
            _assert_response_body_untainted(
                harness.runtime.current_state(), body
            )
            return query, body

    with harness.state("/client-qa/httpx-async") as state:
        query, body = asyncio.run(exercise())
        snapshot = _snapshot(state)
    return _http_result(snapshot, body, query, expect_ssrf=False)


def _run_aiohttp(harness: Harness, base: str) -> dict[str, Any]:
    import aiohttp

    runtime = harness.runtime

    async def exercise():
        construction_query = "qa-aiohttp-construction-" + uuid.uuid4().hex
        query = "qa-aiohttp-" + uuid.uuid4().hex
        async with aiohttp.ClientSession() as session:
            # Constructing a carrier is intentionally not an outbound sink.
            from yarl import URL

            carrier = aiohttp.ClientRequest(
                "GET",
                URL(f"{base}/constructed"),
                params={
                    "q": runtime.source(
                        construction_query,
                        "http.request.parameter",
                        "aiohttp.construct.query",
                    )
                },
            )
            assert carrier is not None
            assert not harness.runtime.current_state().pending
            async with session.get(
                f"{base}/fixed",
                params={
                    "q": runtime.source(
                        query, "http.request.parameter", "aiohttp.query"
                    )
                },
            ) as response:
                body = await response.read()
                _assert_response_body_untainted(
                    harness.runtime.current_state(), body
                )
        return query, body

    with harness.state("/client-qa/aiohttp") as state:
        query, body = asyncio.run(exercise())
        snapshot = _snapshot(state)
    return _http_result(snapshot, body, query, expect_ssrf=False)


def _run_urllib(harness: Harness, base: str) -> dict[str, Any]:
    from urllib import request as urllib_request

    runtime = harness.runtime
    with harness.state("/client-qa/urllib") as state:
        query = "qa-urllib-" + uuid.uuid4().hex
        url = f"{base}/fixed?q={query}"
        _taint_component(
            runtime,
            state,
            url,
            query,
            "urllib.query",
            url.index(query),
            len(query),
        )
        carrier = urllib_request.Request(url)
        assert not state.pending
        with urllib_request.urlopen(carrier, timeout=5) as response:
            body = response.read()
        _assert_response_body_untainted(state, body)
        snapshot = _snapshot(state)
    return _http_result(snapshot, body, query, expect_ssrf=False)


def _run_http_observer_fail_open(
    harness: Harness, base: str
) -> dict[str, Any]:
    import requests
    from beacon_security.sinks import http as http_sinks

    original = http_sinks._report_http

    def broken(*_args, **_kwargs):
        raise RuntimeError("controlled observer failure")

    try:
        http_sinks._report_http = broken
        with harness.state("/client-qa/http-observer-failure") as state:
            with requests.Session() as session:
                response = session.get(base + "/observer", timeout=5)
                body = response.content
            _assert_response_body_untainted(state, body)
    finally:
        http_sinks._report_http = original
    assert response.status_code == 200
    assert body == _LoopbackHandler.response
    return {"business_result": "preserved", "observer_error": "isolated"}


def _run_http_subclass(harness: Harness, base: str) -> dict[str, Any]:
    import requests

    class DerivedSession(requests.Session):
        def send(self, request, **kwargs):
            return super().send(request, **kwargs)

    with harness.state("/client-qa/http-subclass") as state:
        with DerivedSession() as session:
            response = session.get(base + "/subclass", timeout=5)
            body = response.content
        _assert_response_body_untainted(state, body)
        snapshot = _snapshot(state)
    assert response.status_code == 200
    assert body == _LoopbackHandler.response
    assert _events(snapshot, "ssrf") == []
    return {"business_result": "preserved", "override": "executed_once"}


def _run_process_and_filesystem(harness: Harness) -> dict[str, Any]:
    from pathlib import Path

    runtime = harness.runtime
    with harness.state("/client-qa/process-filesystem") as state:
        executable = runtime.source(
            "/usr/bin/true", "http.request.parameter", "process.executable"
        )
        argument = runtime.source(
            "client-qa-argument", "http.request.parameter", "process.argument"
        )
        result = subprocess.run(
            [executable, argument],
            shell=False,
            check=True,
            capture_output=True,
        )
        assert type(result) is subprocess.CompletedProcess
        child = subprocess.Popen(
            [executable],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        child_out, child_err = child.communicate(timeout=5)
        assert child.returncode == 0 and child_out == b"" and child_err == b""
        shell_command = runtime.source(
            "/bin/true", "http.request.parameter", "process.shell_script"
        )
        assert os.system(shell_command) == 0

        with tempfile.TemporaryDirectory(
            prefix="beacon-security-client-"
        ) as directory:
            path_text = runtime.source(
                str(Path(directory) / "source.txt"),
                "http.request.parameter",
                "filesystem.path",
            )
            source_path = Path(path_text)
            # Path construction is a carrier boundary for this direct runner;
            # attach the source through the shared API rather than inspecting
            # path text in the sink.
            state.propagate(
                source_path, (path_text,), "client_qa.Path", exact=True
            )
            write_result = source_path.write_text(
                "safe-client-qa", encoding="utf-8"
            )
            read_result = source_path.read_text(encoding="utf-8")
            target = Path(directory) / "renamed.txt"
            renamed = source_path.rename(target)
            fixed_remove_result = renamed.unlink()
            assert fixed_remove_result is None
            fixed_target_before_delete = _snapshot(state)
            assert not any(
                event["sink"]["operation"] == "delete"
                and any(
                    source["name"] == "filesystem.path"
                    for source in event["sources"]
                )
                for event in _events(
                    fixed_target_before_delete, "path_traversal"
                )
            )

            delete_path_text = runtime.source(
                str(Path(directory) / "delete.txt"),
                "http.request.parameter",
                "filesystem.delete.path",
            )
            delete_path = Path(delete_path_text)
            state.propagate(
                delete_path, (delete_path_text,), "client_qa.Path", exact=True
            )
            delete_path.write_text("safe-delete", encoding="utf-8")
            remove_result = delete_path.unlink()
            snapshot = _snapshot(state)
        snapshot = _snapshot(state)

    assert type(write_result) is int
    assert type(read_result) is str and read_result == "safe-client-qa"
    assert type(renamed) is type(target)
    assert remove_result is None
    roles = {
        event["sink"]["role"]
        for event in _events(snapshot, "command_execution")
    }
    assert {"executable", "argument"}.issubset(roles)
    assert any(
        event["sink"]["role"] == "shell_script"
        for event in _events(snapshot, "command_injection")
    )
    path_events = _events(snapshot, "path_traversal")
    path_roles = {event["sink"]["operation"] for event in path_events}
    assert {"read", "write", "rename", "delete"}.issubset(path_roles)
    assert any(
        event["sink"]["operation"] == "delete"
        and event["sink"]["role"] == "file_path"
        and event["sink"]["path_role"] == "target"
        and any(
            source["name"] == "filesystem.delete.path"
            for source in event["sources"]
        )
        for event in path_events
    )
    assert not any(
        event["sink"]["operation"] == "delete"
        and any(
            source["name"] == "filesystem.path" for source in event["sources"]
        )
        for event in path_events
    )
    return {
        "command_roles": sorted(roles),
        "filesystem_roles": sorted(path_roles),
        "return_types": "preserved",
    }


def _run_process_observer_fail_open(harness: Harness) -> dict[str, Any]:
    import beacon_security.sinks.process as process_sinks

    original = process_sinks._report_command

    def broken(*_args, **_kwargs):
        raise RuntimeError("controlled observer failure")

    try:
        process_sinks._report_command = broken
        with harness.state("/client-qa/process-observer-failure"):
            result = subprocess.run(["/usr/bin/true"], shell=False, check=True)
    finally:
        process_sinks._report_command = original
    assert (
        type(result) is subprocess.CompletedProcess and result.returncode == 0
    )
    return {"business_result": "preserved", "observer_error": "isolated"}


def _run_sqlalchemy(harness: Harness) -> dict[str, Any]:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from sqlalchemy.sql import text as sql_text

    runtime = harness.runtime
    engine = create_engine("sqlite:///:memory:")
    try:
        with harness.state("/client-qa/sqlalchemy") as state:
            with engine.connect() as connection:
                query = runtime.source(
                    "SELECT 1 /* connection */",
                    "http.request.parameter",
                    "sqlalchemy.connection.text",
                )
                assert connection.execute(text(query)).scalar_one() == 1
                alias_query = runtime.source(
                    "SELECT 1 /* sqlalchemy.sql alias */",
                    "http.request.parameter",
                    "sqlalchemy.sql.text",
                )
                assert (
                    connection.execute(sql_text(alias_query)).scalar_one() == 1
                )
                driver_query = runtime.source(
                    "SELECT 1 /* driver */",
                    "http.request.parameter",
                    "sqlalchemy.driver.text",
                )
                assert (
                    connection.exec_driver_sql(driver_query).scalar_one() == 1
                )
                before = len(state.pending)
                bound = runtime.source(
                    "".join(("12", "345")),
                    "http.request.parameter",
                    "sqlalchemy.bound.parameter",
                )
                assert (
                    connection.execute(
                        text("SELECT :value"), {"value": bound}
                    ).scalar_one()
                    == "12345"
                )
                assert len(state.pending) == before
            with Session(engine) as session:
                session_query = runtime.source(
                    "SELECT 1 /* session */",
                    "http.request.parameter",
                    "sqlalchemy.session.text",
                )
                assert session.execute(text(session_query)).scalar_one() == 1
            snapshot = _snapshot(state)
    finally:
        engine.dispose()
    functions = {
        event["sink"]["function"]
        for event in _events(snapshot, "sql_injection")
    }
    assert "sqlalchemy.Connection.execute" in functions
    assert "sqlalchemy.Connection.exec_driver_sql" in functions
    assert "sqlalchemy.Session.execute" in functions
    source_names = {
        source["name"]
        for event in _events(snapshot, "sql_injection")
        for source in event["sources"]
    }
    assert "sqlalchemy.sql.text" in source_names
    assert all(
        "sqlalchemy.bound.parameter"
        not in {source["name"] for source in event["sources"]}
        for event in _events(snapshot, "sql_injection")
    )
    return {
        "functions": sorted(functions),
        "text_alias": "sqlalchemy.sql.text",
        "parameterized_negative": "no_template_finding",
    }


def _run_django(harness: Harness) -> dict[str, Any]:
    from django.conf import settings

    if settings.configured:
        raise Unverified(
            "Django settings were already configured by another process component"
        )
    settings.configure(
        DEBUG=False,
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        INSTALLED_APPS=[],
        SECRET_KEY="client-qa",
    )
    import django

    django.setup()
    from django.db import connection, models
    from django.db.models.expressions import RawSQL

    class ClientQARow(models.Model):
        id = models.IntegerField(primary_key=True)

        class Meta:
            app_label = "client_qa"

    runtime = harness.runtime
    with harness.state("/client-qa/django") as state:
        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(ClientQARow)
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO {ClientQARow._meta.db_table} (id) VALUES (1)"
                )
            raw_query = runtime.source(
                f"SELECT id FROM {ClientQARow._meta.db_table}",
                "http.request.parameter",
                "django.raw.query",
            )
            before = len(state.pending)
            queryset = ClientQARow.objects.raw(raw_query)
            assert len(state.pending) == before
            assert [row.id for row in queryset] == [1]
            rawsql_text = runtime.source(
                "".join(("id", " + 0")),
                "http.request.parameter",
                "django.rawsql.expression",
            )
            before_rawsql = len(state.pending)
            expression = RawSQL(rawsql_text, [])
            assert len(state.pending) == before_rawsql
            assert list(ClientQARow.objects.annotate(marker=expression))
            assert len(state.pending) > before_rawsql
            parameter = runtime.source(
                "".join(("12", "345")),
                "http.request.parameter",
                "django.bound.parameter",
            )
            before_parameter = len(state.pending)
            assert not list(ClientQARow.objects.filter(id=parameter))
            assert len(state.pending) == before_parameter
            snapshot = _snapshot(state)
        finally:
            with connection.schema_editor() as schema_editor:
                schema_editor.delete_model(ClientQARow)
            connection.close()
    assert any(
        "django.CursorWrapper.execute" in event["sink"]["function"]
        or "django.CursorDebugWrapper.execute" in event["sink"]["function"]
        for event in _events(snapshot, "sql_injection")
    )
    assert all(
        "django.bound.parameter"
        not in {source["name"] for source in event["sources"]}
        for event in _events(snapshot, "sql_injection")
    )
    return {
        "raw_lazy_until_iteration": True,
        "rawsql_lazy_until_execution": True,
        "parameterized_negative": "no_template_finding",
    }


def _postgres_dsn() -> str:
    return os.environ.get("BEACON_SECURITY_QA_POSTGRES_DSN", "")


def _run_psycopg3(harness: Harness) -> dict[str, Any]:
    dsn = _postgres_dsn()
    if not dsn:
        raise Unverified("BEACON_SECURITY_QA_POSTGRES_DSN not supplied")
    import psycopg

    runtime = harness.runtime
    with harness.state("/client-qa/psycopg3") as state:
        query_connection = runtime.source(
            "SELECT 1 /* sync connection */",
            "http.request.parameter",
            "psycopg.connection.execute",
        )
        query_cursor = runtime.source(
            "SELECT 1 /* sync cursor */",
            "http.request.parameter",
            "psycopg.cursor.execute",
        )
        query_async_connection = runtime.source(
            "SELECT 1 /* async connection */",
            "http.request.parameter",
            "psycopg.async.connection.execute",
        )
        query_async_cursor = runtime.source(
            "SELECT 1 /* async cursor */",
            "http.request.parameter",
            "psycopg.async.cursor.execute",
        )
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            assert connection.execute(query_connection).fetchone()[0] == 1
            with connection.cursor() as cursor:
                cursor.execute(query_cursor)
                assert cursor.fetchone()[0] == 1

        async def exercise():
            async with await psycopg.AsyncConnection.connect(
                dsn, connect_timeout=5
            ) as connection:
                async_connection_cursor = await connection.execute(
                    query_async_connection
                )
                assert (await async_connection_cursor.fetchone())[0] == 1
                async with connection.cursor() as cursor:
                    await cursor.execute(query_async_cursor)
                    assert (await cursor.fetchone())[0] == 1

        asyncio.run(exercise())
        snapshot = _snapshot(state)
    sql_events = _events(snapshot, "sql_injection")
    functions = {event["sink"]["function"] for event in sql_events}
    assert any(
        "psycopg.Connection.execute" in function for function in functions
    )
    assert any("psycopg.Cursor.execute" in function for function in functions)
    assert any(
        "psycopg.AsyncConnection.execute" in function for function in functions
    )
    assert any(
        "psycopg.AsyncCursor.execute" in function for function in functions
    )
    source_names = {
        source["name"] for event in sql_events for source in event["sources"]
    }
    assert {
        "psycopg.connection.execute",
        "psycopg.cursor.execute",
        "psycopg.async.connection.execute",
        "psycopg.async.cursor.execute",
    } <= source_names
    return {"functions": sorted(functions), "queries": "read_only_select"}


def _mysql_settings() -> dict[str, Any] | None:
    required = (
        "BEACON_SECURITY_QA_MYSQL_HOST",
        "BEACON_SECURITY_QA_MYSQL_PORT",
        "BEACON_SECURITY_QA_MYSQL_USER",
        "BEACON_SECURITY_QA_MYSQL_PASSWORD",
        "BEACON_SECURITY_QA_MYSQL_DATABASE",
    )
    if not all(os.environ.get(key) for key in required):
        return None
    return {
        "host": os.environ["BEACON_SECURITY_QA_MYSQL_HOST"],
        "port": int(os.environ["BEACON_SECURITY_QA_MYSQL_PORT"]),
        "user": os.environ["BEACON_SECURITY_QA_MYSQL_USER"],
        "password": os.environ["BEACON_SECURITY_QA_MYSQL_PASSWORD"],
        "database": os.environ["BEACON_SECURITY_QA_MYSQL_DATABASE"],
        "connect_timeout": 5,
        "read_timeout": 5,
        "write_timeout": 5,
    }


def _run_pymysql(harness: Harness) -> dict[str, Any]:
    settings = _mysql_settings()
    if settings is None:
        raise Unverified("BEACON_SECURITY_QA_MYSQL_* settings not supplied")
    import pymysql
    from pymysql import cursors

    runtime = harness.runtime
    variants = (
        ("Cursor", cursors.Cursor),
        ("DictCursor", cursors.DictCursor),
        ("SSCursor", cursors.SSCursor),
        ("SSDictCursor", cursors.SSDictCursor),
    )
    with harness.state("/client-qa/pymysql") as state:
        observed = {}
        with pymysql.connect(**settings) as connection:
            for name, cursor_type in variants:
                query = runtime.source(
                    "".join(("SELECT 1 /* ", name.lower(), " */")),
                    "http.request.parameter",
                    f"pymysql.{name}.execute",
                )
                with connection.cursor(cursor=cursor_type) as cursor:
                    execute_result = cursor.execute(query)
                    assert type(execute_result) is int and execute_result > 0
                    row = cursor.fetchone()
                    observed[name] = type(row).__name__
                    while cursor.fetchone() is not None:
                        pass
        snapshot = _snapshot(state)
    sql_events = _events(snapshot, "sql_injection")
    for name in ("Cursor", "DictCursor", "SSCursor", "SSDictCursor"):
        assert any(
            event["sink"]["function"].endswith(f"{name}.execute")
            and any(
                source["name"] == f"pymysql.{name}.execute"
                for source in event["sources"]
            )
            for event in sql_events
        )
    assert observed["DictCursor"] == "dict"
    assert observed["SSDictCursor"] == "dict"
    return {"cursor_variants": observed, "queries": "read_only_select"}


@contextlib.contextmanager
def _qa_environment(output: Path):
    values = {
        "BEACON_SECURITY_ENABLED": "true",
        "BEACON_SECURITY_PYTHON_INCLUDE": "security_sample",
        "BEACON_SECURITY_OUTPUT": str(output.parent / "runtime"),
        "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED": "true",
        "BEACON_SECURITY_SBOM_ENABLED": "false",
        "OTEL_TRACES_EXPORTER": "none",
        "OTEL_METRICS_EXPORTER": "none",
        "OTEL_LOGS_EXPORTER": "none",
    }
    values.update(
        {
            f"BEACON_SECURITY_RULES_{rule.upper()}_ENABLED": "true"
            for rule in (
                "sql_injection",
                "command_execution",
                "command_injection",
                "ssrf",
                "http_request_input",
                "path_traversal",
            )
        }
    )
    previous = {key: os.environ.get(key) for key in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _dependency_versions() -> dict[str, str]:
    distributions = (
        "opentelemetry-api",
        "opentelemetry-instrumentation",
        "requests",
        "httpx",
        "aiohttp",
        "SQLAlchemy",
        "Django",
        "psycopg",
        "PyMySQL",
    )
    versions = {}
    for distribution in distributions:
        try:
            versions[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            continue
    module_names = {
        "requests": "requests",
        "httpx": "httpx",
        "aiohttp": "aiohttp",
        "SQLAlchemy": "sqlalchemy",
        "Django": "django",
        "psycopg": "psycopg",
        "PyMySQL": "pymysql",
    }
    for label, module_name in module_names.items():
        try:
            module = importlib.import_module(module_name)
            module_version = getattr(module, "__version__", None)
            if module_version:
                versions[label + ".module"] = str(module_version)
        except Exception:
            continue
    return versions


def _run_suite(output: Path | None = None) -> dict[str, Any]:
    from beacon_security import config

    harness = Harness(
        output or Path(tempfile.gettempdir()) / "beacon-security-client-qa"
    )
    cases: list[dict[str, Any]] = []
    profile_value = ""

    def record(name: str, function: Callable[[], dict[str, Any]]) -> None:
        try:
            detail = function()
            cases.append(
                {
                    "name": name,
                    "status": "passed",
                    "detail": _json_safe(detail),
                }
            )
        except Unverified as error:
            cases.append(
                {
                    "name": name,
                    "status": "unverified",
                    "reason": type(error).__name__ + ": " + str(error)[:200],
                }
            )
        except BaseException as error:
            cases.append(
                {
                    "name": name,
                    "status": "failed",
                    "error": type(error).__name__,
                }
            )

    environment_path = output or harness.output / "client-qa.json"
    with _qa_environment(environment_path):
        try:
            harness.start()
            profile_value = harness.runtime.get_runtime().profile
            with loopback_server() as base:
                record(
                    "http.requests.actual_send",
                    lambda: _run_http_requests(harness, base),
                )
                record(
                    "http.httpx.sync_actual_send",
                    lambda: _run_httpx_sync(harness, base),
                )
                record(
                    "http.httpx.async_actual_send",
                    lambda: _run_httpx_async(harness, base),
                )
                record(
                    "http.aiohttp.actual_send",
                    lambda: _run_aiohttp(harness, base),
                )
                record(
                    "http.urllib.actual_send",
                    lambda: _run_urllib(harness, base),
                )
                record(
                    "http.subclass_override",
                    lambda: _run_http_subclass(harness, base),
                )
                record(
                    "http.observer_failure_fail_open",
                    lambda: _run_http_observer_fail_open(harness, base),
                )
            record(
                "process.filesystem.boundaries",
                lambda: _run_process_and_filesystem(harness),
            )
            record(
                "process.observer_failure_fail_open",
                lambda: _run_process_observer_fail_open(harness),
            )
            record("sqlalchemy2.boundaries", lambda: _run_sqlalchemy(harness))
            record("django.lazy_sql_boundaries", lambda: _run_django(harness))
            record(
                "psycopg3.sync_async_execute", lambda: _run_psycopg3(harness)
            )
            record("pymysql.cursor_variants", lambda: _run_pymysql(harness))
        finally:
            harness.close()

    result = {
        "schema_version": 1,
        "source": "beacon_security",
        "suite": "python-client-contract",
        "runtime": config.runtime_identity(),
        "dependencies": _dependency_versions(),
        "database_backends": {
            name: {"image": image}
            for name, image in (
                (
                    "postgresql",
                    os.environ.get("BEACON_SECURITY_QA_POSTGRES_IMAGE", ""),
                ),
                (
                    "mysql",
                    os.environ.get("BEACON_SECURITY_QA_MYSQL_IMAGE", ""),
                ),
            )
            if image
        },
        "profile": profile_value,
        "adapters": sorted(harness.adapters),
        "cases": cases,
        "passed": sum(case["status"] == "passed" for case in cases),
        "failed": sum(case["status"] == "failed" for case in cases),
        "unverified": sum(case["status"] == "unverified" for case in cases),
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
    return result


def run_suite(output: Path | None = None) -> dict[str, Any]:
    """Run the suite for pytest or the command-line wrapper."""

    return _run_suite(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=PACKAGE_ROOT
        / "build"
        / "validation"
        / "python-v01"
        / "clients"
        / "client-qa.json",
    )
    args = parser.parse_args()
    result = run_suite(args.output)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
