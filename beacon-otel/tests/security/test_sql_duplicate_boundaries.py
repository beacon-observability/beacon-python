from __future__ import annotations

import asyncio
import uuid

import pytest
from beacon_security.patching import Patches
from beacon_security.sinks import sql
from test_transform_behavior import start_runtime


@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("many", [False, True])
def test_django_observes_one_real_execution(
    monkeypatch, tmp_path, debug: bool, many: bool
) -> None:
    django = pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            SECRET_KEY="sql-test",
        )
    django.setup()
    from django.db import connection

    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    patches = Patches()
    previous_debug = connection.force_debug_cursor
    try:
        connection.force_debug_cursor = debug
        sql.install(patches, set())
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS test_values (v TEXT)")
            query = (
                "INSERT INTO test_values VALUES ('" + uuid.uuid4().hex + "')"
            )
            runtime.source(query, "http.request.parameter", "sql")
            if many:
                cursor.executemany(query, [(), ()])
            else:
                cursor.execute(query)
        assert len(state.pending) == 1
        name = state.pending[0]["sink"]["function"]
        assert ("DebugWrapper" in name) is debug
    finally:
        patches.restore()
        connection.force_debug_cursor = previous_debug
        connection.close()
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


@pytest.mark.parametrize(
    "name", ["Cursor", "DictCursor", "SSCursor", "SSDictCursor"]
)
def test_pymysql_inherited_methods_report_once_and_restore(
    monkeypatch, tmp_path, name: str
) -> None:
    pymysql = pytest.importorskip("pymysql")
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    patches = Patches()
    cursor_class = getattr(pymysql.cursors, name)
    owned_before = "execute" in cursor_class.__dict__
    original = cursor_class.execute
    monkeypatch.setattr(
        pymysql.cursors.Cursor, "_query", lambda self, query: 1
    )
    monkeypatch.setattr(
        pymysql.cursors.SSCursor, "_query", lambda self, query: 1
    )
    connection = pymysql.Connection(defer_connect=True)
    try:
        sql._install_pymysql(patches, set())
        query = "SELECT '" + uuid.uuid4().hex + "'"
        runtime.source(query, "http.request.parameter", "sql")
        cursor_class(connection).execute(query)
        assert len(state.pending) == 1
    finally:
        patches.restore()
        assert ("execute" in cursor_class.__dict__) is owned_before
        assert cursor_class.execute is original
        runtime.end_request(state)
        runtime.detach_state(token)
        runtime.stop()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_overrides_delegate_once_and_independent_calls_remain_visible(
    monkeypatch, asynchronous: bool
) -> None:
    reports = []
    monkeypatch.setattr(
        sql, "_report_sql", lambda name, query: reports.append(query)
    )

    if asynchronous:

        class Base:
            async def execute(self, query, callback=None):
                if callback is not None:
                    await callback()
                return query

        class Child(Base):
            async def execute(self, query, callback=None):
                return await super().execute(query, callback)
    else:

        class Base:
            def execute(self, query, callback=None):
                if callback is not None:
                    callback()
                return query

        class Child(Base):
            def execute(self, query, callback=None):
                return super().execute(query, callback)

    patches = Patches()
    try:
        for cls in (Base, Child):
            sql._patch_driver_class(
                patches,
                set(),
                cls,
                "driver",
                cls.__name__,
                "driver",
                ("execute",),
            )
        cursor = Child()
        other = Base()
        if asynchronous:

            async def exercise():
                assert (
                    await cursor.execute(
                        "first", lambda: other.execute("second")
                    )
                    == "first"
                )
                await other.execute("third", lambda: other.execute("fourth"))

            asyncio.run(exercise())
        else:
            assert (
                cursor.execute("first", lambda: other.execute("second"))
                == "first"
            )
            other.execute("third", lambda: other.execute("fourth"))
        assert reports == ["first", "second", "third", "fourth"]
        assert sql._DRIVER_CALLS.get() == ()
    finally:
        patches.restore()


def test_cancelled_driver_call_resets_delegation_context(monkeypatch) -> None:
    reports = []
    monkeypatch.setattr(
        sql, "_report_sql", lambda name, query: reports.append(query)
    )

    class Cursor:
        async def execute(self, query):
            if query == "blocked":
                await asyncio.Event().wait()
            return query

    patches = Patches()
    sql._patch_driver_class(
        patches, set(), Cursor, "driver", "Cursor", "driver", ("execute",)
    )

    async def exercise() -> None:
        cursor = Cursor()
        task = asyncio.create_task(cursor.execute("blocked"))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await cursor.execute("next") == "next"
        assert sql._DRIVER_CALLS.get() == ()

    try:
        asyncio.run(exercise())
        assert reports == ["blocked", "next"]
    finally:
        patches.restore()
