"""Process and shell execution sinks."""

from __future__ import annotations

import os
from typing import Any

from ._common import (
    execution_boundary,
    extract_arg,
    marks_for,
    optional_import,
    safe_gap,
    safe_observe,
    safe_sink,
)

_SHELL_NAMES = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
}


def _shell_flag(value: Any) -> bool | None:
    """Read only a real bool; never invoke an application's ``__bool__``."""

    if type(value) is bool:
        return value
    safe_gap("process.shell_flag_unknown")
    return None


def _program_text(value: Any) -> str:
    if type(value) is bytes:
        try:
            return value.decode("ascii", "strict").lower()
        except UnicodeDecodeError:
            return ""
    if type(value) is str:
        return value.lower()
    return ""


def _program_name(value: Any) -> str:
    text = _program_text(value)
    return os.path.basename(text.replace("\\", "/")).lower() if text else ""


def _mark_key(mark: Any) -> tuple[Any, ...]:
    return (
        getattr(mark, "source_id", None),
        getattr(mark, "node_id", None),
        getattr(mark, "start", None),
        getattr(mark, "end", None),
        getattr(mark, "exact", None),
        getattr(mark, "unit", None),
    )


def _extend_marks(
    target: list[Any], value: Any, seen: set[tuple[Any, ...]]
) -> None:
    for mark in marks_for(value):
        key = _mark_key(mark)
        if key not in seen:
            seen.add(key)
            target.append(mark)


def _explicit_shell_index(command: Any) -> int | None:
    if type(command) not in (list, tuple) or len(command) < 3:
        return None
    executable = _program_name(command[0])
    if executable not in _SHELL_NAMES:
        return None
    for index in range(1, len(command) - 1):
        marker = _program_text(command[index])
        if marker in {"-c", "/c", "-command", "-commandline"}:
            return index + 1
    return None


def _shell_script(command: Any, shell: bool | None) -> Any | None:
    if type(shell) is not bool:
        safe_gap("process.shell_flag_unknown")
        return None
    if shell:
        if type(command) in (list, tuple):
            return command[0] if command else None
        return command
    index = _explicit_shell_index(command)
    if index is not None:
        return command[index]
    return None


def _split_command(
    command: Any, shell: bool | None, executable: Any = None
) -> tuple[list[Any], list[Any], list[Any], Any]:
    executable_marks: list[Any] = []
    argument_marks: list[Any] = []
    script_marks: list[Any] = []
    executable_seen: set[tuple[Any, ...]] = set()
    argument_seen: set[tuple[Any, ...]] = set()
    script_seen: set[tuple[Any, ...]] = set()
    items = command if type(command) in (list, tuple) else None

    # A mark on the argv container has no proven element range.  Keep it as an
    # ordinary observation rather than upgrading every element to executable.
    if items is not None:
        _extend_marks(argument_marks, command, argument_seen)
        if marks_for(command):
            safe_gap("process.argv_container_scope_unknown")

    if shell is True:
        _extend_marks(executable_marks, executable, executable_seen)
        if items is not None:
            script = items[0] if items else None
            _extend_marks(script_marks, script, script_seen)
            for item in items[1:]:
                _extend_marks(argument_marks, item, argument_seen)
        else:
            script = command
            _extend_marks(script_marks, script, script_seen)
        return executable_marks, argument_marks, script_marks, script

    if shell is None and items is not None:
        first = items[0] if items else None
        _extend_marks(executable_marks, first, executable_seen)
        _extend_marks(executable_marks, executable, executable_seen)
        _extend_marks(script_marks, first, script_seen)
        script_index = _explicit_shell_index(items)
        if script_index is not None:
            _extend_marks(script_marks, items[script_index], script_seen)
        for index, item in enumerate(items[1:], 1):
            if index != script_index:
                _extend_marks(argument_marks, item, argument_seen)
        return executable_marks, argument_marks, script_marks, first

    if items is not None:
        executable_value = items[0] if items else None
        _extend_marks(executable_marks, executable_value, executable_seen)
        _extend_marks(executable_marks, executable, executable_seen)
        script_index = _explicit_shell_index(items)
        script = items[script_index] if script_index is not None else None
        for index, item in enumerate(items[1:], 1):
            if script_index == index:
                _extend_marks(script_marks, item, script_seen)
            else:
                _extend_marks(argument_marks, item, argument_seen)
        return executable_marks, argument_marks, script_marks, script

    _extend_marks(executable_marks, command, executable_seen)
    _extend_marks(executable_marks, executable, executable_seen)
    script = None
    if shell is None:
        # The flag's truth value is intentionally unknown.  Report both
        # possible roles without calling a custom ``__bool__`` method.
        _extend_marks(script_marks, command, script_seen)
        safe_gap("process.shell_boundary_unknown")
    return executable_marks, argument_marks, script_marks, script


def _report_command(
    function: str, command: Any, shell: bool | None, executable: Any = None
) -> None:
    executable_marks, argument_marks, script_marks, script = _split_command(
        command, shell, executable
    )
    safe_sink(
        "command_execution",
        function,
        "executable",
        command,
        marks=executable_marks,
    )
    # Ordinary argv is an observation, not an executable candidate risk and
    # never a shell-injection observation.
    safe_sink(
        "command_execution",
        function,
        "argument",
        command,
        marks=argument_marks,
    )
    safe_sink(
        "command_injection",
        function,
        "shell_script",
        script,
        marks=script_marks,
    )


def _popen_init_wrapper(wrapped, instance, args, kwargs):
    command = extract_arg(args, kwargs, 0, "args", None)
    shell = _shell_flag(extract_arg(args, kwargs, 8, "shell", False))
    executable = extract_arg(args, kwargs, 2, "executable", None)
    with execution_boundary(
        "subprocess.Popen.__init__", nested_in=("subprocess.run",)
    ) as root:
        if root:
            safe_observe(
                _report_command,
                "subprocess.Popen.__init__",
                command,
                shell,
                executable,
            )
        return wrapped(*args, **kwargs)


def _run_wrapper(wrapped, instance, args, kwargs):
    command = extract_arg(args, kwargs, 0, "args", None)
    raw_shell = kwargs["shell"] if "shell" in kwargs else False
    shell = _shell_flag(raw_shell)
    executable = kwargs.get("executable")
    with execution_boundary("subprocess.run") as root:
        if root:
            safe_observe(
                _report_command, "subprocess.run", command, shell, executable
            )
        return wrapped(*args, **kwargs)


def _system_wrapper(wrapped, instance, args, kwargs):
    command = extract_arg(args, kwargs, 0, "command", None)
    with execution_boundary("os.system") as root:
        if root:
            safe_observe(_report_command, "os.system", command, True)
        return wrapped(*args, **kwargs)


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
    subprocess = optional_import("subprocess")
    if subprocess is not None:
        popen = getattr(subprocess, "Popen", None)
        if popen is not None and _patch(
            patches, seen, popen, "__init__", _popen_init_wrapper
        ):
            adapters.add("subprocess")
        if _patch(patches, seen, subprocess, "run", _run_wrapper):
            adapters.add("subprocess")
    os_module = optional_import("os")
    if os_module is not None and _patch(
        patches, seen, os_module, "system", _system_wrapper
    ):
        adapters.add("os")
    return adapters
