from __future__ import annotations

from security_sample.scenario import run_case


def test_shared_sample_exercises_eval_order_and_safe_boundaries(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("BEACON_SECURITY_SAMPLE_TEMP", str(tmp_path))
    result = run_case(
        query="plain-query",
        item="path-item",
        header="header-query",
        body='{"query": "plain-query", "filename": "safe.txt"}',
        filename="safe.txt",
    )

    assert result["eval_count"] == 1
    assert result["eval_order"] == ["once"]
    assert result["order"] == ["left", "right"]
    assert all(
        result[key] == "str"
        for key in (
            "formatted_type",
            "represented_type",
            "concat_type",
            "percent_type",
            "format_type",
            "join_type",
            "slice_type",
        )
    )
    assert result["sql"]["parameterized_rows"] == 0
    assert set(result["sql"]["source_attempts"]) == {
        "path",
        "header",
        "raw_body",
        "body_query",
    }
    assert all(
        status in {"OperationalError", "executed"}
        for status in result["sql"]["source_attempts"].values()
    )
    assert result["command"]["constant_returncode"] == 0
    assert result["file"]["read"] is True
