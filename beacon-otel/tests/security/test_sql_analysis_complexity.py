from __future__ import annotations

import sys

import pytest
from beacon_security.attack_evidence import lexical
from beacon_security.tracking import Mark


def _work_for_whitespace(size: int) -> int:
    query = "SELECT id FROM items WHERE id=" + " " * size + "-42"
    start = query.index("-42")
    marks = (Mark("source", 1, start, len(query)),)
    work = 0

    def trace(frame, event, arg):
        nonlocal work
        if frame.f_code is lexical.__code__ and event == "line":
            work += 1
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        result = lexical(query, marks, shell=False)
    finally:
        sys.settrace(previous)
    assert result["status"] == "no_evidence"
    return work


def test_sql_whitespace_has_linear_work_including_near_budget_limit() -> None:
    small = _work_for_whitespace(1000)
    large = _work_for_whitespace(2000)
    near_limit = _work_for_whitespace(8000)
    # Count executed lines rather than timing the machine. This allows
    # implementation changes while rejecting quadratic amplification.
    assert large < small * 2.5
    assert near_limit < small * 9


@pytest.mark.parametrize("whitespace", [" ", "\t", "\r\n", " \t\n "])
def test_whitespace_preserves_numeric_and_quoted_context(
    whitespace: str,
) -> None:
    query = "SELECT * FROM t WHERE id=" + whitespace * 20 + "-42"
    start = query.index("-42")
    assert (
        lexical(query, (Mark("source", 1, start, len(query)),), shell=False)[
            "status"
        ]
        == "no_evidence"
    )
    query = 'SELECT "controlled field" FROM t'
    start = query.index(" ", query.index('"'))
    assert (
        lexical(query, (Mark("source", 1, start, start + 1),), shell=False)[
            "reason"
        ]
        == "sql_identifier_control"
    )
