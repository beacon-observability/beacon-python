# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
"""Bounded lexical evidence, independent of code risk and exploit outcome."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import config
from .tracking import Mark

MAX_LENGTH = 8192
MAX_MARKS = 64
SHELLS = frozenset({"sh", "bash", "dash", "ksh", "zsh"})
SHELL_WORDS = frozenset(
    {
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "until",
        "case",
        "esac",
        "do",
        "done",
        "function",
    }
)


def evidence(status: str, reason: str) -> dict[str, str]:
    return {"status": status, "reason": reason, "outcome": "not_assessed"}


def status(event: Mapping[str, Any]) -> str:
    value = event.get("attack_evidence")
    value = value.get("status") if isinstance(value, Mapping) else None
    return value if value in ("suspected", "no_evidence") else "unknown"


def rank(event: Mapping[str, Any]) -> int:
    return {"no_evidence": 0, "unknown": 1, "suspected": 2}[status(event)]


def analyze(
    rule: str,
    role: str,
    value: Any,
    marks: Sequence[Mark],
    shell_dialect: str = "unknown",
) -> dict[str, str]:
    try:
        if rule == "sql_injection":
            if (
                config.text("beacon.security.analysis.sql.dialect", "unknown")
                != "ansi"
            ):
                return evidence("unknown", "sql_dialect_unsupported")
            return lexical(value, marks, shell=False)
        if rule == "command_injection":
            if shell_dialect not in SHELLS:
                return evidence("unknown", "shell_dialect_unsupported")
            return lexical(value, marks, shell=True)
        if rule in ("command_execution", "http_request_input") and any(
            not mark.exact for mark in marks
        ):
            return evidence("unknown", "taint_imprecise")
        if rule == "command_execution":
            return evidence(
                "no_evidence" if role == "argument" else "unknown",
                "non_control_argument"
                if role == "argument"
                else "executable_policy_unavailable",
            )
        if rule == "http_request_input":
            return evidence("no_evidence", "http_path_query_only")
        if rule == "ssrf":
            return evidence("unknown", "network_policy_unavailable")
        if rule == "path_traversal":
            return evidence("unknown", "path_policy_unavailable")
        return evidence("unknown", "analysis_unavailable")
    except Exception:
        return evidence("unknown", "analysis_failed")


def lexical(
    value: Any, marks: Sequence[Mark], *, shell: bool
) -> dict[str, str]:
    if type(value) is not str:
        return evidence("unknown", "input_unavailable")
    if len(value) > MAX_LENGTH or len(marks) > MAX_MARKS:
        return evidence("unknown", "analysis_budget")
    if not marks:
        return evidence("unknown", "taint_unavailable")
    tainted = bytearray(len(value))
    for mark in marks:
        if (
            not mark.exact
            or mark.unit != "unicode_code_point"
            or mark.start < 0
            or mark.end is None
            or mark.end > len(value)
            or mark.start >= mark.end
        ):
            return evidence("unknown", "taint_imprecise")
        tainted[mark.start : mark.end] = b"\x01" * (mark.end - mark.start)
    quote = ""
    suspected = False
    identifier = False
    command_start = True
    parentheses = 0
    index = 0
    while index < len(value):
        char = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if ord(char) < 32 and char not in "\n\r\t" or 127 <= ord(char) <= 159:
            return evidence("unknown", "syntax_unsupported")
        if shell and char == "\\" and quote != "'":
            index += 1
            if index >= len(value):
                return evidence("unknown", "syntax_incomplete")
            if quote != '"' or value[index] in '$`"\\\n':
                index += 1
            continue
        if shell and quote != "'" and char in "$`":
            return evidence("unknown", "shell_expansion_unsupported")
        if not shell and char in "\\$`[]":
            return evidence("unknown", "sql_syntax_unsupported")
        if quote:
            if char == quote:
                if not shell and following == quote:
                    index += 1
                else:
                    quote = ""
            elif not shell and quote == '"' and tainted[index]:
                identifier = True
            index += 1
            continue
        if char in "'\"":
            command_start = False
            quote = char
            index += 1
            continue
        if shell:
            if char in "*?[]~":
                return evidence("unknown", "shell_expansion_unsupported")
            if char in "(){}<>":
                return evidence("unknown", "shell_syntax_unsupported")
            if char == "#" and (index == 0 or value[index - 1].isspace()):
                end = value.find("\n", index)
                index = len(value) if end < 0 else end
                continue
            if char in ";|&\n":
                suspected |= bool(tainted[index])
                command_start = True
            elif command_start and not char.isspace():
                end = index
                while end < len(value) and value[end].isalpha():
                    end += 1
                if value[index:end] in SHELL_WORDS:
                    return evidence("unknown", "shell_syntax_unsupported")
                command_start = False
        else:
            if (char == "-" and following == "-") or (
                char == "/" and following == "*"
            ):
                suspected |= bool(tainted[index] or tainted[index + 1])
                if char == "-":
                    end = value.find("\n", index)
                    index = len(value) if end < 0 else end
                else:
                    end = value.find("*/", index + 2)
                    if end < 0:
                        return evidence("unknown", "syntax_incomplete")
                    if "/*" in value[index + 2 : end]:
                        return evidence("unknown", "sql_syntax_unsupported")
                    index = end + 2
                continue
            if char == "(":
                parentheses += 1
            elif char == ")":
                parentheses -= 1
                if parentheses < 0:
                    return evidence("unknown", "syntax_incomplete")
            previous = index - 1
            while previous >= 0 and value[previous].isspace():
                previous -= 1
            numeric_sign = previous < 0 or value[previous] in "=<>(,"
            if (
                char in "0123456789"
                or char in "-+"
                and following in "0123456789"
                and following
                and numeric_sign
            ):
                decimal = False
                while (
                    index + 1 < len(value)
                    and value[index + 1] in "0123456789."
                ):
                    index += 1
                    if value[index] == ".":
                        if decimal:
                            return evidence(
                                "unknown", "sql_syntax_unsupported"
                            )
                        decimal = True
                index += 1
                continue
            if char.isalpha() or char == "_":
                while index < len(value) and (
                    value[index].isalnum() or value[index] == "_"
                ):
                    identifier |= bool(tainted[index])
                    index += 1
                continue
            if char not in "=<>!;|&+-*/(),.?" and not char.isspace():
                return evidence("unknown", "sql_syntax_unsupported")
            if tainted[index] and char in "=<>!;|&+-*/(),":
                suspected = True
        index += 1
    if quote or parentheses:
        return evidence("unknown", "syntax_incomplete")
    if suspected:
        return evidence(
            "suspected",
            "tainted_shell_control" if shell else "tainted_sql_structure",
        )
    if identifier:
        return evidence("unknown", "sql_identifier_control")
    return evidence(
        "no_evidence", "shell_data_only" if shell else "sql_data_only"
    )
