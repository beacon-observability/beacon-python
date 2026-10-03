"""Security sink adapters for the Python instrumentor.

The package owns only library hooks.  Request lifecycle and source tracking
remain in ``beacon_security.runtime`` and ``beacon_security.state``.
"""

from __future__ import annotations

import os
import threading
import types

from ..patching import Patches
from . import filesystem, http, process, sql
from ._common import combined_marks, optional_import, runtime_module, safe_sink

_PATCHES = Patches()
_SEEN: set[tuple[int, str]] = set()
_ADAPTERS: set[str] = set()
_INSTALLED = False
_INSTALLING = False
_LOCK = threading.RLock()


def install() -> list[str]:
    """Install available integrations and return their stable adapter names."""

    global _INSTALLED, _INSTALLING
    with _LOCK:
        if _INSTALLED or _INSTALLING:
            return sorted(_ADAPTERS)
        _INSTALLING = True
        try:
            for installer in (
                sql.install,
                http.install,
                process.install,
                filesystem.install,
            ):
                checkpoint = len(_PATCHES.entries)
                seen_before = set(_SEEN)
                try:
                    _ADAPTERS.update(installer(_PATCHES, _SEEN))
                except BaseException as error:
                    # Optional integrations must never prevent application startup.
                    for target, attribute, original, installed in reversed(
                        _PATCHES.entries[checkpoint:]
                    ):
                        try:
                            if getattr(target, attribute, None) is installed:
                                setattr(target, attribute, original)
                        except BaseException:
                            pass
                    del _PATCHES.entries[checkpoint:]
                    _SEEN.intersection_update(seen_before)
                    _record_install_failure(error)
                    continue
            _INSTALLED = True
            return sorted(_ADAPTERS)
        finally:
            _INSTALLING = False


def uninstall() -> None:
    """Restore every hook installed by this package."""

    global _INSTALLED, _INSTALLING
    with _LOCK:
        try:
            _PATCHES.restore()
        finally:
            _SEEN.clear()
            _ADAPTERS.clear()
            _INSTALLED = False
            _INSTALLING = False


def _after_fork() -> None:
    global _LOCK, _INSTALLING
    was_installing = _INSTALLING
    _LOCK = threading.RLock()
    _INSTALLING = False
    if was_installing and not _INSTALLED:
        try:
            _PATCHES.restore()
        except BaseException:
            pass
        _SEEN.clear()
        _ADAPTERS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def _record_install_failure(error: BaseException) -> None:
    try:
        runtime = runtime_module()
        if runtime is not None:
            runtime.startup_gap("sink_install_failed:" + type(error).__name__)
    except BaseException:
        return


def _sqlite_call(function, args, kwargs, location="") -> bool:
    """Observe native sqlite calls that cannot be assigned wrapper methods."""

    try:
        function_type = type(function)
        if function_type not in (
            types.BuiltinMethodType,
            types.BuiltinFunctionType,
            types.MethodDescriptorType,
        ):
            return False
        sqlite3 = optional_import("sqlite3")
        if sqlite3 is None:
            return False
        name = getattr(function, "__name__", None)
        connection_type = getattr(sqlite3, "Connection", None)
        cursor_type = getattr(sqlite3, "Cursor", None)
        if name not in {"execute", "executemany", "executescript"}:
            return False
        if function_type is types.MethodDescriptorType:
            owner = getattr(function, "__objclass__", None)
            receiver = args[0] if args else None
            offset = 1
            if owner is connection_type and type(receiver) is connection_type:
                prefix = "sqlite3.Connection"
            elif owner is cursor_type and type(receiver) is cursor_type:
                prefix = "sqlite3.Cursor"
            else:
                return False
        else:
            receiver = getattr(function, "__self__", None)
            offset = 0
            if type(receiver) is connection_type:
                prefix = "sqlite3.Connection"
            elif type(receiver) is cursor_type:
                prefix = "sqlite3.Cursor"
            else:
                return False
        query = args[offset] if len(args) > offset else None
        if query is None:
            for key in ("sql", "operation", "query", "script"):
                if key in kwargs:
                    query = kwargs[key]
                    break
        safe_sink(
            "sql_injection",
            f"{prefix}.{name}",
            "template",
            query,
            marks=combined_marks(query),
            location=location,
        )
        return True
    except BaseException:
        return False


def call_before(function, args, kwargs, location=""):
    """AST execution hook for native SQLite; all other calls are passthrough."""

    _sqlite_call(function, args, kwargs, location)
    return None


def call_after(token, result):
    """Return the original AST call result without changing its type."""

    return result


__all__ = ["install", "uninstall", "call_before", "call_after"]
