"""Actual file-operation sinks for builtins, os, and pathlib."""

from __future__ import annotations

import os
from typing import Any

from ._common import (
    combined_marks,
    execution_boundary,
    extract_arg,
    optional_import,
    safe_gap,
    safe_observe,
    safe_propagate,
    safe_sink,
)


def _mode_role(mode: Any) -> str:
    if not isinstance(mode, str):
        return "read"
    return (
        "write"
        if any(flag in mode for flag in ("w", "a", "x", "+"))
        else "read"
    )


def _report_path(function: str, role: str, value: Any, *other: Any) -> None:
    safe_sink(
        "path_traversal",
        function,
        role,
        value,
        marks=combined_marks(value, *other),
    )


def _report_open(function: str, path: Any, mode: Any) -> None:
    _report_path(function, _mode_role(mode), path)


def _open_wrapper(wrapped, instance, args, kwargs):
    path = extract_arg(args, kwargs, 0, "file", None)
    mode = extract_arg(args, kwargs, 1, "mode", "r")
    with execution_boundary("filesystem.open") as root:
        if root:
            safe_observe(_report_open, "builtins.open", path, mode)
        return wrapped(*args, **kwargs)


def _os_open_wrapper(wrapped, instance, args, kwargs):
    path = extract_arg(args, kwargs, 0, "path", None)
    flags = extract_arg(args, kwargs, 1, "flags", os.O_RDONLY)
    try:
        writing = bool(
            flags
            & (
                os.O_WRONLY
                | os.O_RDWR
                | os.O_APPEND
                | os.O_CREAT
                | os.O_TRUNC
                | os.O_EXCL
            )
        )
    except BaseException:
        writing = False
        safe_gap("filesystem.flags_observation_error")
    with execution_boundary("filesystem.os.open") as root:
        if root:
            safe_observe(
                _report_path, "os.open", "write" if writing else "read", path
            )
        return wrapped(*args, **kwargs)


def _fspath_wrapper(wrapped, instance, args, kwargs):
    value = extract_arg(args, kwargs, 0, "path", None)
    result = wrapped(*args, **kwargs)
    safe_observe(safe_propagate, result, (value,), "os.fspath", exact=True)
    return result


def _remove_wrapper(wrapped, instance, args, kwargs):
    path = extract_arg(args, kwargs, 0, "path", None)
    with execution_boundary(
        "filesystem.remove", nested_in=("pathlib.unlink",)
    ) as root:
        if root:
            safe_observe(_report_path, "os.remove", "delete", path)
        return wrapped(*args, **kwargs)


def _unlink_wrapper(wrapped, instance, args, kwargs):
    path = extract_arg(args, kwargs, 0, "path", None)
    with execution_boundary(
        "filesystem.unlink", nested_in=("pathlib.unlink",)
    ) as root:
        if root:
            safe_observe(_report_path, "os.unlink", "delete", path)
        return wrapped(*args, **kwargs)


def _rmdir_wrapper(wrapped, instance, args, kwargs):
    path = extract_arg(args, kwargs, 0, "path", None)
    with execution_boundary(
        "filesystem.rmdir", nested_in=("pathlib.rmdir",)
    ) as root:
        if root:
            safe_observe(_report_path, "os.rmdir", "delete", path)
        return wrapped(*args, **kwargs)


def _rename_wrapper(function: str, key: str, parent: tuple[str, ...] = ()):
    def wrapper(wrapped, instance, args, kwargs):
        source = extract_arg(args, kwargs, 0, "src", None)
        target = extract_arg(args, kwargs, 1, "dst", None)
        with execution_boundary(key, nested_in=parent) as root:
            if root:
                safe_observe(_report_path, function, "rename", target, source)
            return wrapped(*args, **kwargs)

    return wrapper


def _path_open_wrapper(wrapped, instance, args, kwargs):
    mode = extract_arg(args, kwargs, 0, "mode", "r")
    parents = (
        "pathlib.read_text",
        "pathlib.read_bytes",
        "pathlib.write_text",
        "pathlib.write_bytes",
    )
    with execution_boundary("pathlib.open", nested_in=parents) as root:
        if root:
            safe_observe(_report_open, "pathlib.Path.open", instance, mode)
        return wrapped(*args, **kwargs)


def _path_read_wrapper(function: str, key: str):
    def wrapper(wrapped, instance, args, kwargs):
        with execution_boundary(key) as root:
            if root:
                safe_observe(_report_path, function, "read", instance)
            return wrapped(*args, **kwargs)

    return wrapper


def _path_write_wrapper(function: str, key: str):
    def wrapper(wrapped, instance, args, kwargs):
        with execution_boundary(key) as root:
            if root:
                safe_observe(_report_path, function, "write", instance)
            return wrapped(*args, **kwargs)

    return wrapper


def _path_delete_wrapper(
    function: str, key: str, parent: tuple[str, ...] = ()
):
    def wrapper(wrapped, instance, args, kwargs):
        with execution_boundary(key, nested_in=parent) as root:
            if root:
                safe_observe(_report_path, function, "delete", instance)
            return wrapped(*args, **kwargs)

    return wrapper


def _path_rename_wrapper(function: str, key: str):
    def wrapper(wrapped, instance, args, kwargs):
        target = extract_arg(args, kwargs, 0, "target", None)
        with execution_boundary(key) as root:
            if root:
                safe_observe(
                    _report_path, function, "rename", target, instance
                )
            result = wrapped(*args, **kwargs)
            # pathlib returns the destination path.  Source pollution is
            # observed at the rename boundary but must not taint that returned
            # destination carrier.
            return safe_propagate(result, (target,), function, exact=True)

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


def install(patches, seen) -> set[str]:
    adapters: set[str] = set()
    builtins_module = optional_import("builtins")
    if builtins_module is not None and _patch(
        patches, seen, builtins_module, "open", _open_wrapper
    ):
        adapters.add("filesystem")

    os_module = optional_import("os")
    if os_module is not None:
        for attribute, wrapper in (
            ("fspath", _fspath_wrapper),
            ("open", _os_open_wrapper),
            ("remove", _remove_wrapper),
            ("unlink", _unlink_wrapper),
            ("rmdir", _rmdir_wrapper),
            (
                "rename",
                _rename_wrapper(
                    "os.rename", "filesystem.rename", ("pathlib.rename",)
                ),
            ),
            (
                "replace",
                _rename_wrapper(
                    "os.replace", "filesystem.replace", ("pathlib.replace",)
                ),
            ),
        ):
            if _patch(patches, seen, os_module, attribute, wrapper):
                adapters.add("filesystem")

    pathlib = optional_import("pathlib")
    path_type = getattr(pathlib, "Path", None) if pathlib is not None else None
    if path_type is not None:
        path_hooks = (
            ("open", _path_open_wrapper),
            (
                "read_text",
                _path_read_wrapper(
                    "pathlib.Path.read_text", "pathlib.read_text"
                ),
            ),
            (
                "read_bytes",
                _path_read_wrapper(
                    "pathlib.Path.read_bytes", "pathlib.read_bytes"
                ),
            ),
            (
                "write_text",
                _path_write_wrapper(
                    "pathlib.Path.write_text", "pathlib.write_text"
                ),
            ),
            (
                "write_bytes",
                _path_write_wrapper(
                    "pathlib.Path.write_bytes", "pathlib.write_bytes"
                ),
            ),
            (
                "unlink",
                _path_delete_wrapper(
                    "pathlib.Path.unlink",
                    "pathlib.unlink",
                    ("filesystem.unlink",),
                ),
            ),
            (
                "rmdir",
                _path_delete_wrapper(
                    "pathlib.Path.rmdir",
                    "pathlib.rmdir",
                    ("filesystem.rmdir",),
                ),
            ),
            (
                "rename",
                _path_rename_wrapper("pathlib.Path.rename", "pathlib.rename"),
            ),
            (
                "replace",
                _path_rename_wrapper(
                    "pathlib.Path.replace", "pathlib.replace"
                ),
            ),
        )
        for attribute, wrapper in path_hooks:
            if _patch(patches, seen, path_type, attribute, wrapper):
                adapters.add("pathlib")

    return adapters
