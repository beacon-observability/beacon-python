from __future__ import annotations

import pytest
from beacon_security.attack_evidence import lexical
from beacon_security.tracking import Mark


def _analyze(query: str, fragment: str):
    start = query.index(fragment)
    return lexical(
        query, (Mark("source", 1, start, start + len(fragment)),), shell=False
    )


@pytest.mark.parametrize("prefix", ["", "/* 😀 */ "])
def test_tainted_quote_escaping_fixed_literal_is_structural(
    prefix: str,
) -> None:
    fragment = "' OR 'a' LIKE 'a"
    query = prefix + "SELECT * FROM users WHERE name='" + fragment + "'"
    result = _analyze(query, fragment)
    assert result == {
        "status": "suspected",
        "reason": "tainted_sql_structure",
        "outcome": "not_assessed",
    }


@pytest.mark.parametrize(
    "query,fragment,status",
    [
        ("SELECT 'O''Reilly'", "O''Reilly", "no_evidence"),
        ("SELECT 'OR UNION SELECT'", "OR UNION SELECT", "no_evidence"),
        ("SELECT 'a b'", "'a b'", "no_evidence"),
        ('SELECT "first""last" FROM t', 'first""last', "unknown"),
        ("SELECT 'O'Reilly'", "O'Reilly", "unknown"),
        ("SELECT id FROM t UNION SELECT id FROM s", "UNION SELECT", "unknown"),
        ("SELECT 'guest'", "'guest", "suspected"),
    ],
)
def test_quote_data_and_unsupported_syntax_preserve_uncertainty(
    query: str, fragment: str, status: str
) -> None:
    assert _analyze(query, fragment)["status"] == status


@pytest.mark.parametrize("placeholder", ["%s", "%(name)s", ":name"])
def test_placeholder_dialects_remain_explicitly_unsupported(
    placeholder: str,
) -> None:
    result = _analyze(
        f"SELECT * FROM t WHERE id={placeholder} AND tenant=user_table",
        "user_table",
    )
    assert result["status"] == "unknown"
    assert result["reason"] == "sql_syntax_unsupported"
