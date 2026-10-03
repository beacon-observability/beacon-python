from __future__ import annotations

import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent / "helpers"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from run_client_case import run_suite


def test_client_contract_suite(tmp_path):
    """Exercise actual client boundaries and retain explicit external gaps.

    The runner contains the loopback server and read-only SQL assertions.  A
    missing task-owned PostgreSQL/MySQL endpoint is an honest unverified case,
    not a synthetic pass.
    """

    report = run_suite(tmp_path / "client-qa.json")
    assert report["failed"] == 0, report

    required = {
        "http.requests.actual_send",
        "http.httpx.sync_actual_send",
        "http.httpx.async_actual_send",
        "http.aiohttp.actual_send",
        "http.urllib.actual_send",
        "http.subclass_override",
        "http.observer_failure_fail_open",
        "process.filesystem.boundaries",
        "process.observer_failure_fail_open",
        "sqlalchemy2.boundaries",
        "django.lazy_sql_boundaries",
    }
    by_name = {case["name"]: case for case in report["cases"]}
    assert required <= by_name.keys()
    assert all(by_name[name]["status"] == "passed" for name in required)

    external = {
        "psycopg3.sync_async_execute": bool(
            os.environ.get("BEACON_SECURITY_QA_POSTGRES_DSN")
        ),
        "pymysql.cursor_variants": all(
            os.environ.get(key)
            for key in (
                "BEACON_SECURITY_QA_MYSQL_HOST",
                "BEACON_SECURITY_QA_MYSQL_PORT",
                "BEACON_SECURITY_QA_MYSQL_USER",
                "BEACON_SECURITY_QA_MYSQL_PASSWORD",
                "BEACON_SECURITY_QA_MYSQL_DATABASE",
            )
        ),
    }
    for name, configured in external.items():
        assert by_name[name]["status"] == (
            "passed" if configured else "unverified"
        )
