"""Shared application behavior for the three framework fixtures.

The fixture deliberately uses ordinary library calls.  It does not import or
call :mod:`beacon_security`; the instrumentation is loaded by
``opentelemetry-instrument`` in the integration harness.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import requests


def _fixture_directory() -> Path:
    root = (
        Path(
            os.environ.get(
                "BEACON_SECURITY_SAMPLE_TEMP", tempfile.gettempdir()
            )
        )
        / "BeaconSecurity-sample"
    )
    root.mkdir(parents=True, exist_ok=True)
    safe = root / "safe.txt"
    if not safe.exists():
        safe.write_text("security-sample\n", encoding="utf-8")
    return root


def _parameterized_sql_exercise(query: str) -> int:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table users (name text)")
        connection.execute("insert into users(name) values (?)", ("known",))
        return len(
            connection.execute(
                "select name from users where name = ?", (query,)
            ).fetchall()
        )
    finally:
        connection.close()


def _unsafe_source_sql_exercise(value: str) -> str:
    """Attempt a malformed local-only query and return only its safe status."""

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table users (name text)")
        statement = (
            "select name from users where name = '" + value + "' trailing"
        )
        try:
            connection.execute(statement)
        except sqlite3.Error as error:
            return type(error).__name__
        return "executed"
    finally:
        connection.close()


def _sql_exercises(
    query: str,
    *,
    item: str,
    header: str,
    raw_body: str,
    body_query: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {"unsafe_error": ""}
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table users (name text)")
        connection.execute("insert into users(name) values (?)", ("known",))
        unsafe = "select name from users where name = '" + query + "'"
        try:
            connection.execute(unsafe).fetchall()
        except sqlite3.Error as error:
            # The route remains useful for quote-containing test values while
            # preserving the attempted SQL dataflow at the sink boundary.
            result["unsafe_error"] = type(error).__name__
    finally:
        connection.close()
    result["parameterized_rows"] = _parameterized_sql_exercise(query)
    result["source_attempts"] = {
        "path": _unsafe_source_sql_exercise(item),
        "header": _unsafe_source_sql_exercise(header),
        "raw_body": _unsafe_source_sql_exercise(raw_body),
        "body_query": _unsafe_source_sql_exercise(body_query),
    }
    return result


def form_sql_case(value: str) -> dict[str, Any]:
    """Exercise only the form/text SQL boundaries used by the small QA leg."""

    value = str(value)
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table users (name text)")
        statement = (
            "select name from users where name = '" + value + "' trailing"
        )
        try:
            connection.execute(statement)
        except sqlite3.Error as error:
            unsafe_status = type(error).__name__
        else:
            unsafe_status = "executed"
    finally:
        connection.close()
    return {
        "value_type": type(value).__name__,
        "unsafe_status": unsafe_status,
        "parameterized_rows": _parameterized_sql_exercise(value),
    }


def _command_exercises(query: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    direct = subprocess.run(
        ["/usr/bin/printf", "%s", query],
        check=True,
        capture_output=True,
        text=True,
    )
    result["argv_type"] = type(direct).__name__
    # The command is intentionally a non-destructive printf.  Inputs used by
    # the harness are alphanumeric, so shell execution cannot alter the host.
    shell = subprocess.run(
        "/usr/bin/printf '%s' '" + query + "'",
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    result["shell_returncode"] = shell.returncode
    constant = subprocess.run(
        ["/usr/bin/printf", "%s", "constant"],
        check=True,
        capture_output=True,
        text=True,
    )
    result["constant_returncode"] = constant.returncode
    return result


def _http_exercises(
    query: str, callback: str | None, target_url: str | None
) -> dict[str, Any]:
    url = callback or target_url or "http://127.0.0.1:9/target"
    result: dict[str, Any] = {"status": None, "error": ""}
    try:
        response = requests.get(url, params={"q": query}, timeout=0.8)
        result["status"] = response.status_code
    except requests.RequestException as error:
        result["error"] = type(error).__name__
    # Keep a second request whose destination is constant; only its query
    # parameter is derived from input and it must not be treated as SSRF.
    try:
        requests.get(
            (target_url or "http://127.0.0.1:9/target"),
            params={"q": query},
            timeout=0.05,
        )
    except requests.RequestException:
        pass
    return result


def _file_exercises(filename: str) -> dict[str, Any]:
    root = _fixture_directory()
    result: dict[str, Any] = {"read": False, "error": ""}
    candidate = root / filename
    try:
        candidate.read_text(encoding="utf-8")
        result["read"] = True
    except (OSError, UnicodeError) as error:
        result["error"] = type(error).__name__
    return result


def run_case(
    *,
    query: str,
    item: str,
    header: str = "",
    body: str = "",
    body_query: str = "",
    filename: str = "safe.txt",
    callback: str | None = None,
    target_url: str | None = None,
) -> dict[str, Any]:
    """Exercise positive and negative boundaries and return safe summaries."""

    query = str(query)
    item = str(item)
    header = str(header)
    body = str(body)
    body_query = str(body_query)
    filename = str(filename)

    # These expressions are intentionally ordinary Python syntax.  They are
    # used by AST/runtime tests to prove eval-once, order, f-string conversion,
    # and result-type preservation without exposing raw values in evidence.
    evaluations: list[str] = []

    def once() -> str:
        evaluations.append("once")
        return query

    format_spec = ">8"
    formatted = f"{once():{format_spec}}"
    represented = f"{query!r}"
    order: list[str] = []

    def left() -> str:
        order.append("left")
        return query

    def right() -> str:
        order.append("right")
        return item

    concatenated = left() + right()
    percent = "%s" % query
    formatted_method = "{}:{}".format(item, query)
    joined = ":".join((item, query))
    sliced = query[1:]

    summary = {
        "query_type": type(query).__name__,
        "formatted_type": type(formatted).__name__,
        "represented_type": type(represented).__name__,
        "concat_type": type(concatenated).__name__,
        "percent_type": type(percent).__name__,
        "format_type": type(formatted_method).__name__,
        "join_type": type(joined).__name__,
        "slice_type": type(sliced).__name__,
        "eval_count": len(evaluations),
        "eval_order": evaluations,
        "order": order,
        "slice_length": len(sliced),
        "body_length": len(body),
        "header_length": len(header),
    }
    summary["sql"] = _sql_exercises(
        query,
        item=item,
        header=header,
        raw_body=body,
        body_query=body_query,
    )
    summary["command"] = _command_exercises(query)
    summary["http"] = _http_exercises(query, callback, target_url)
    summary["file"] = _file_exercises(filename)

    # A Pydantic field or raw JSON body is intentionally passed through a
    # normal Python container to exercise recursive capture in the adapter.
    summary["payload_keys"] = sorted(
        json.loads(body).keys() if body.lstrip().startswith("{") else []
    )
    return summary


def target_payload(query: str = "target") -> dict[str, Any]:
    return {"target": True, "query_length": len(query)}


def stream_chunks(query: str):
    # The caller owns response closure; this generator only yields values.
    yield "chunk-1\n"
    yield f"chunk-{len(query)}\n"
