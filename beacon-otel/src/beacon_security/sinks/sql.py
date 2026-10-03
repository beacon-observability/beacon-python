"""Execution-boundary hooks for DB-API, SQLAlchemy, and Django SQL calls."""

from __future__ import annotations

import contextvars
import inspect
from typing import Any

from .. import config
from ._common import (
    combined_marks,
    current_state,
    execution_boundary,
    extract_arg,
    is_awaitable,
    optional_import,
    safe_observe,
    safe_propagate,
    safe_sink,
)

_DJANGO_SQL_MARK_STACK: contextvars.ContextVar[tuple[tuple[Any, ...], ...]] = (
    contextvars.ContextVar("beacon_security_django_sql_marks", default=())
)


_SQL_PARENT_BOUNDARIES = (
    "sqlalchemy.connection.execute",
    "sqlalchemy.connection.exec_driver_sql",
    "sqlalchemy.engine.execute",
    "sqlalchemy.session.execute",
    "sqlalchemy.async_connection.execute",
    "sqlalchemy.async_connection.exec_driver_sql",
    "sqlalchemy.async_session.execute",
    "django.cursor.execute",
    "django.cursor.executemany",
    "django.cursor.debug.execute",
    "django.cursor.debug.executemany",
)


def _report_sql(function: str, template: Any) -> None:
    # Bind parameters are intentionally not inspected.  A tainted value bound
    # to a constant parameterized statement is not SQL-template pollution.
    safe_sink(
        "sql_injection",
        function,
        "template",
        template,
        marks=combined_marks(template),
    )


def _sql_template(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    if args:
        return args[0]
    for name in ("operation", "statement", "sql", "query", "script"):
        if name in kwargs:
            return kwargs[name]
    return None


def _sql_call_wrapper(function: str, key: str, parent: tuple[str, ...] = ()):
    def wrapper(wrapped, instance, args, kwargs):
        template = _sql_template(args, kwargs)
        with execution_boundary(key, nested_in=parent) as root:
            if root:
                safe_observe(_report_sql, function, template)
            return wrapped(*args, **kwargs)

    return wrapper


def _async_sql_call_wrapper(
    function: str, key: str, parent: tuple[str, ...] = ()
):
    async def wrapper(wrapped, instance, args, kwargs):
        template = _sql_template(args, kwargs)
        with execution_boundary(key, nested_in=parent) as root:
            if root:
                safe_observe(_report_sql, function, template)
            result = wrapped(*args, **kwargs)
            return await result if is_awaitable(result) else result

    return wrapper


def _driver_method_wrapper(
    function: str,
    key: str,
    parent: tuple[str, ...] = (),
    asynchronous: bool = False,
):
    parent = tuple(parent) + _SQL_PARENT_BOUNDARIES
    if asynchronous:
        return _async_sql_call_wrapper(function, key, parent)
    return _sql_call_wrapper(function, key, parent)


def _propagating_text_wrapper(wrapped, instance, args, kwargs):
    text_value = extract_arg(args, kwargs, 0, "text", None)
    result = wrapped(*args, **kwargs)
    return safe_propagate(result, (text_value,), "sqlalchemy.text", exact=True)


def _propagating_raw_sql_init(wrapped, instance, args, kwargs):
    sql = extract_arg(args, kwargs, 0, "sql", None)
    result = wrapped(*args, **kwargs)
    safe_propagate(instance, (sql,), "django.RawSQL", exact=True)
    return result


def _propagating_raw_sql_resolve(wrapped, instance, args, kwargs):
    result = wrapped(*args, **kwargs)
    # Django resolves annotations by copying the expression.  The copy keeps
    # the original ``sql`` value but does not carry runtime side-table marks;
    # bind the clone to the marked RawSQL instance before compilation.
    return safe_propagate(
        result, (instance,), "django.RawSQL.resolve_expression", exact=True
    )


def _propagating_raw_queryset(wrapped, instance, args, kwargs):
    raw_query = extract_arg(args, kwargs, 0, "raw_query", None)
    result = wrapped(*args, **kwargs)
    return safe_propagate(
        result, (raw_query,), "django.QuerySet.raw", exact=True
    )


def _propagating_raw_sql_compile(wrapped, instance, args, kwargs):
    result = wrapped(*args, **kwargs)
    safe_observe(_propagate_compiled_sql, result, instance)
    safe_observe(_record_compiled_raw_sql, instance)
    return result


def _propagate_compiled_sql(result: Any, instance: Any) -> None:
    try:
        compiled_sql = result[0]
    except BaseException:
        return
    # Django may add placeholders and quoting.  Keep the original tuple and
    # string untouched, but use conservative marks for the compiled carrier.
    safe_propagate(
        compiled_sql, (instance,), "django.RawSQL.as_sql", exact=False
    )


def _record_compiled_raw_sql(instance: Any) -> None:
    state = current_state()
    if state is None:
        return
    marks = tuple(state.marks(instance))
    stack = _DJANGO_SQL_MARK_STACK.get()
    if not marks or not stack:
        return
    frame = _bounded_compile_marks(state, stack[-1], marks)
    _DJANGO_SQL_MARK_STACK.set(stack[:-1] + (frame,))


def _mark_key(mark: Any) -> tuple[Any, ...]:
    return (
        getattr(mark, "source_id", None),
        getattr(mark, "node_id", None),
        getattr(mark, "start", None),
        getattr(mark, "end", None),
        getattr(mark, "exact", None),
        getattr(mark, "unit", None),
    )


def _bounded_compile_marks(
    state: Any, existing: tuple[Any, ...], additions: tuple[Any, ...]
) -> tuple[Any, ...]:
    limit = max(1, state.max_marks)
    frame = list(existing[:limit])
    seen = {_mark_key(mark) for mark in frame}
    overflow = len(existing) > limit
    for mark in additions:
        key = _mark_key(mark)
        if key in seen:
            continue
        if len(frame) >= limit:
            overflow = True
            break
        frame.append(mark)
        seen.add(key)
    if overflow:
        state.gap("django.sql_compile_mark_limit")
    return tuple(frame)


def _propagate_compiled_query(result: Any, marks: tuple[Any, ...]) -> None:
    try:
        template = result[0]
    except BaseException:
        return
    if type(template) not in (str, bytes) or not marks:
        return
    state = current_state()
    if state is None:
        return
    derived = state.derive(marks, "django.SQLCompiler.as_sql", exact=False)
    state.put(template, derived)


def _propagating_django_compiler(wrapped, instance, args, kwargs):
    previous = _DJANGO_SQL_MARK_STACK.get()
    token = _DJANGO_SQL_MARK_STACK.set(previous + ((),))
    completed = False
    try:
        result = wrapped(*args, **kwargs)
        completed = True
        frame = _DJANGO_SQL_MARK_STACK.get()[-1]
        safe_observe(_propagate_compiled_query, result, frame)
        return result
    finally:
        frame = _DJANGO_SQL_MARK_STACK.get()[-1]
        _DJANGO_SQL_MARK_STACK.reset(token)
        if completed and previous and frame:
            state = current_state()
            if state is not None:
                safe_observe(
                    _merge_compile_marks,
                    state,
                    previous,
                    frame,
                )


def _merge_compile_marks(
    state: Any, previous: tuple[tuple[Any, ...], ...], frame: tuple[Any, ...]
) -> None:
    merged = _bounded_compile_marks(state, previous[-1], frame)
    _DJANGO_SQL_MARK_STACK.set(previous[:-1] + (merged,))


def _propagating_clause_method_wrapper(operation: str):
    def wrapper(wrapped, instance, args, kwargs):
        result = wrapped(*args, **kwargs)
        return safe_propagate(result, (instance,), operation, exact=True)

    return wrapper


def _patch(patches, seen, target, attribute, wrapper) -> bool:
    key = (id(target), attribute)
    if key in seen:
        return False
    try:
        installed = patches.wrap(target, attribute, wrapper)
    except Exception:
        return False
    if installed:
        seen.add(key)
    return installed


def _patch_driver_class(
    patches,
    seen,
    target,
    module_name: str,
    class_name: str,
    adapter: str,
    methods: tuple[str, ...],
) -> bool:
    if target is None:
        return False
    installed_any = False
    for method in methods:
        try:
            original = getattr(target, method, None)
            asynchronous = inspect.iscoroutinefunction(original)
        except Exception:
            asynchronous = False
        key = f"{adapter}.{class_name}.{method}"
        if _patch(
            patches,
            seen,
            target,
            method,
            _driver_method_wrapper(
                f"{module_name}.{class_name}.{method}",
                key,
                asynchronous=asynchronous,
            ),
        ):
            installed_any = True
    return installed_any


def _install_psycopg(patches, seen) -> bool:
    psycopg = (
        optional_import("psycopg")
        if config.dependency_supported("psycopg", ">=3,<4")
        else None
    )
    if psycopg is None:
        return False
    installed = False
    class_names = (
        "Connection",
        "AsyncConnection",
        "Cursor",
        "AsyncCursor",
        "ClientCursor",
        "AsyncClientCursor",
        "ServerCursor",
        "AsyncServerCursor",
        "RawCursor",
        "AsyncRawCursor",
    )
    for class_name in class_names:
        target = getattr(psycopg, class_name, None)
        if target is not None and _patch_driver_class(
            patches,
            seen,
            target,
            "psycopg",
            class_name,
            "psycopg3",
            ("execute", "executemany"),
        ):
            installed = True
    for module_name in ("psycopg.connection", "psycopg.cursor"):
        module = optional_import(module_name)
        if module is None:
            continue
        for class_name in class_names:
            target = getattr(module, class_name, None)
            if target is not None and _patch_driver_class(
                patches,
                seen,
                target,
                module_name,
                class_name,
                "psycopg3",
                ("execute", "executemany"),
            ):
                installed = True
    return installed


def _install_pymysql(patches, seen) -> bool:
    pymysql = (
        optional_import("pymysql")
        if config.dependency_supported("pymysql", ">=1,<2")
        else None
    )
    if pymysql is None:
        return False
    installed = False
    connections = optional_import("pymysql.connections")
    connection_type = (
        getattr(connections, "Connection", None)
        if connections is not None
        else None
    )
    if connection_type is not None and _patch_driver_class(
        patches,
        seen,
        connection_type,
        "pymysql.connections",
        "Connection",
        "pymysql",
        ("execute", "executemany", "query"),
    ):
        installed = True
    cursors = optional_import("pymysql.cursors")
    if cursors is not None:
        for class_name in ("Cursor", "SSCursor", "DictCursor", "SSDictCursor"):
            target = getattr(cursors, class_name, None)
            if target is not None and _patch_driver_class(
                patches,
                seen,
                target,
                "pymysql.cursors",
                class_name,
                "pymysql",
                ("execute", "executemany"),
            ):
                installed = True
    return installed


def install(patches, seen) -> set[str]:
    adapters: set[str] = set()

    # Native sqlite3 methods are immutable.  No replacement object is
    # installed: AST dispatch handles exact native bound execute methods and
    # preserves all native return types and context-manager behavior.
    if optional_import("sqlite3") is not None:
        adapters.add("sqlite3")
    if _install_psycopg(patches, seen):
        adapters.add("psycopg3")
    if _install_pymysql(patches, seen):
        adapters.add("pymysql")

    sqlalchemy = (
        optional_import("sqlalchemy")
        if config.dependency_supported("sqlalchemy", ">=2,<3")
        else None
    )
    if sqlalchemy is not None:
        if _patch(
            patches, seen, sqlalchemy, "text", _propagating_text_wrapper
        ):
            adapters.add("sqlalchemy")
        sql_module = optional_import("sqlalchemy.sql")
        if sql_module is not None and _patch(
            patches, seen, sql_module, "text", _propagating_text_wrapper
        ):
            adapters.add("sqlalchemy")
        engine = optional_import("sqlalchemy.engine")
        connection = (
            getattr(engine, "Connection", None) if engine is not None else None
        )
        if connection is not None:
            for attribute in ("execute", "exec_driver_sql"):
                if _patch(
                    patches,
                    seen,
                    connection,
                    attribute,
                    _sql_call_wrapper(
                        f"sqlalchemy.Connection.{attribute}",
                        f"sqlalchemy.connection.{attribute}",
                        (
                            "sqlalchemy.session.execute",
                            "sqlalchemy.engine.execute",
                        ),
                    ),
                ):
                    adapters.add("sqlalchemy")
        engine_type = (
            getattr(engine, "Engine", None) if engine is not None else None
        )
        if engine_type is not None and _patch(
            patches,
            seen,
            engine_type,
            "execute",
            _sql_call_wrapper(
                "sqlalchemy.Engine.execute",
                "sqlalchemy.engine.execute",
                ("sqlalchemy.session.execute",),
            ),
        ):
            adapters.add("sqlalchemy")
        orm = optional_import("sqlalchemy.orm")
        session = getattr(orm, "Session", None) if orm is not None else None
        if session is not None and _patch(
            patches,
            seen,
            session,
            "execute",
            _sql_call_wrapper(
                "sqlalchemy.Session.execute",
                "sqlalchemy.session.execute",
                ("sqlalchemy.session.execute",),
            ),
        ):
            adapters.add("sqlalchemy")
        asyncio_module = optional_import("sqlalchemy.ext.asyncio")
        if asyncio_module is not None:
            async_connection = getattr(asyncio_module, "AsyncConnection", None)
            if async_connection is not None:
                for attribute in ("execute", "exec_driver_sql"):
                    if _patch(
                        patches,
                        seen,
                        async_connection,
                        attribute,
                        _async_sql_call_wrapper(
                            f"sqlalchemy.AsyncConnection.{attribute}",
                            f"sqlalchemy.async_connection.{attribute}",
                            ("sqlalchemy.async_session.execute",),
                        ),
                    ):
                        adapters.add("sqlalchemy")
            async_session = getattr(asyncio_module, "AsyncSession", None)
            if async_session is not None and _patch(
                patches,
                seen,
                async_session,
                "execute",
                _async_sql_call_wrapper(
                    "sqlalchemy.AsyncSession.execute",
                    "sqlalchemy.async_session.execute",
                ),
            ):
                adapters.add("sqlalchemy")
        elements = optional_import("sqlalchemy.sql.elements")
        text_clause = (
            getattr(elements, "TextClause", None)
            if elements is not None
            else None
        )
        if text_clause is not None:
            for attribute in ("_clone", "bindparams", "params"):
                if _patch(
                    patches,
                    seen,
                    text_clause,
                    attribute,
                    _propagating_clause_method_wrapper(
                        f"sqlalchemy.TextClause.{attribute}"
                    ),
                ):
                    adapters.add("sqlalchemy")

    django = (
        optional_import("django")
        if config.dependency_supported("django", ">=5.2,<5.3")
        else None
    )
    if django is not None:
        db_utils = optional_import("django.db.backends.utils")
        cursor_wrapper = (
            getattr(db_utils, "CursorWrapper", None)
            if db_utils is not None
            else None
        )
        if cursor_wrapper is not None and _patch(
            patches,
            seen,
            cursor_wrapper,
            "execute",
            _sql_call_wrapper(
                "django.CursorWrapper.execute", "django.cursor.execute"
            ),
        ):
            adapters.add("django")
        if cursor_wrapper is not None and _patch(
            patches,
            seen,
            cursor_wrapper,
            "executemany",
            _sql_call_wrapper(
                "django.CursorWrapper.executemany", "django.cursor.executemany"
            ),
        ):
            adapters.add("django")
        debug_wrapper = (
            getattr(db_utils, "CursorDebugWrapper", None)
            if db_utils is not None
            else None
        )
        if debug_wrapper is not None:
            if _patch(
                patches,
                seen,
                debug_wrapper,
                "execute",
                _sql_call_wrapper(
                    "django.CursorDebugWrapper.execute",
                    "django.cursor.debug.execute",
                    ("django.cursor.execute",),
                ),
            ):
                adapters.add("django")
            if _patch(
                patches,
                seen,
                debug_wrapper,
                "executemany",
                _sql_call_wrapper(
                    "django.CursorDebugWrapper.executemany",
                    "django.cursor.debug.executemany",
                    (
                        "django.cursor.debug.executemany",
                        "django.cursor.executemany",
                    ),
                ),
            ):
                adapters.add("django")
        expressions = optional_import("django.db.models.expressions")
        raw_sql = (
            getattr(expressions, "RawSQL", None)
            if expressions is not None
            else None
        )
        if raw_sql is not None and _patch(
            patches, seen, raw_sql, "__init__", _propagating_raw_sql_init
        ):
            adapters.add("django")
        if raw_sql is not None and _patch(
            patches,
            seen,
            raw_sql,
            "resolve_expression",
            _propagating_raw_sql_resolve,
        ):
            adapters.add("django")
        if raw_sql is not None and _patch(
            patches, seen, raw_sql, "as_sql", _propagating_raw_sql_compile
        ):
            adapters.add("django")
        compiler_module = optional_import("django.db.models.sql.compiler")
        compiler = (
            getattr(compiler_module, "SQLCompiler", None)
            if compiler_module is not None
            else None
        )
        if compiler is not None and _patch(
            patches, seen, compiler, "as_sql", _propagating_django_compiler
        ):
            adapters.add("django")
        query = optional_import("django.db.models.query")
        queryset = (
            getattr(query, "QuerySet", None) if query is not None else None
        )
        if queryset is not None and _patch(
            patches, seen, queryset, "raw", _propagating_raw_queryset
        ):
            adapters.add("django")

    return adapters
