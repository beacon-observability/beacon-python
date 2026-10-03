from __future__ import annotations

import json
import sys
from dataclasses import replace

from beacon_security.state import SecurityState
from beacon_security.tracking import ByteBudget, Mark


def value(text: str) -> str:
    """Build a non-interned carrier so the scalar safety rule is explicit."""

    return ("_" + text)[1:]


def make_state(monkeypatch, **env) -> SecurityState:
    for key, item in env.items():
        monkeypatch.setenv(key, str(item))
    return SecurityState(identity={"application_id": "app-test"})


def test_source_returns_original_and_tracks_identity_not_equal_content(
    monkeypatch,
):
    state = make_state(monkeypatch)
    query = value("user-query")
    alias = query
    other = value("user-query")

    assert state.source(query, "http.request.parameter", "q") is query
    assert state.source(alias, "http.request.parameter", "q") is alias
    assert state.source_count == 1
    assert state.marks(alias)

    # Equal content in a different object is a separate carrier, not a match
    # discovered by equality or containment.
    assert other == query and other is not query
    assert state.source(other, "http.request.parameter", "q") is other
    assert state.source_count == 2
    assert state.marks(other)


def test_conflicting_source_labels_create_an_ambiguity_gap(monkeypatch):
    state = make_state(monkeypatch)
    query = value("ambiguous-query")

    state.source(query, "http.request.parameter", "q")
    retained_bytes = state.retained_bytes
    budget_used = state.budget.used
    object_id = id(query)
    state.source(query, "http.request.header", "x-security-query")

    assert state.marks(query) == ()
    assert "source_identity_ambiguous" in state.gaps
    assert object_id in state.objects
    assert state.objects[object_id].value() is query
    assert state.retained_bytes == retained_bytes > 0
    assert state.budget.used == budget_used
    state.close()
    assert state.retained_bytes == 0
    assert state.budget.used == 0
    assert state.source_signatures == {
        "http.request.parameter|q": 1,
        "http.request.header|x-security-query": 1,
    }


def test_ambiguity_invalidates_derived_marks_and_pending_evidence(monkeypatch):
    state = make_state(monkeypatch)
    query = value("derived-ambiguous-query")
    derived = value("derived-sql-query")

    state.source(query, "http.request.parameter", "q")
    state.propagate(derived, (query,), "string.transform", exact=False)
    event = state.sink(
        "sql_injection",
        "sqlite3.Connection.execute",
        "template",
        derived,
        location="state-contract#ambiguous",
    )
    assert event is not None
    assert state.marks(derived)

    state.source(query, "http.request.header", "x-security-query")

    assert state.marks(query) == ()
    assert state.marks(derived) == ()
    assert state.pending == []
    diagnostic = state.diagnostics()
    assert diagnostic is not None
    assert "source_identity_ambiguous" in diagnostic["coverage_gaps"]


def test_shared_scalars_and_units_are_explicit(monkeypatch):
    state = make_state(monkeypatch)
    state.source("x", "http.request.parameter", "short")
    assert state.marks("x") == ()
    assert "shared_scalar_identity" in state.gaps

    unicode_value = value("éclair")
    bytes_value = b"byte-query"
    state.source(unicode_value, "http.request.body", "payload")
    state.source(bytes_value, "http.request.body", "payload")
    assert state.marks(unicode_value)[0].unit == "unicode_code_point"
    assert state.marks(bytes_value)[0].unit == "byte"


def test_capture_recurses_into_containers_and_pydantic_fields(monkeypatch):
    from pydantic import BaseModel

    class Payload(BaseModel):
        query: str
        nested: dict[str, list[str]]

    state = make_state(monkeypatch)
    query = value("model-query")
    nested = value("nested-query")
    payload = Payload(query=query, nested={"items": [nested]})

    assert state.capture(payload, "http.request.body", "json") is payload
    assert state.marks(query)
    assert state.marks(nested)
    assert state.source_signatures["http.request.body|json.query"] == 1
    assert (
        state.source_signatures["http.request.body|json.nested.items[0]"] == 1
    )


def test_capture_marks_numeric_and_custom_fields_unmodeled_without_tainting_conversions(
    monkeypatch,
):
    from pydantic import BaseModel, ConfigDict

    class CustomValue:
        pass

    class Payload(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)
        query: str
        count: int
        optional: str | None = None
        custom: CustomValue

    state = make_state(monkeypatch)
    payload = Payload(
        query=value("typed-query"), count=7, custom=CustomValue()
    )

    assert state.capture(payload, "http.request.body", "json") is payload
    assert state.marks(payload.query)
    converted = str(payload.count)
    assert (
        state.propagate(converted, (payload.count,), "str", exact=False)
        is converted
    )
    assert state.marks(converted) == ()
    assert "unmodeled_source_value:int" in state.gaps
    assert "unmodeled_source_value:CustomValue" in state.gaps
    assert "unmodeled_source_value:NoneType" not in state.gaps


def test_propagation_preserves_result_identity_and_ranges(monkeypatch):
    state = make_state(monkeypatch)
    query = value("abcdef")
    state.source(query, "http.request.parameter", "q")
    marks = state.marks(query)
    result = query.upper()

    assert (
        state.propagate(result, (query,), "str.upper", exact=False) is result
    )
    derived = state.marks(result)
    assert derived and not derived[0].exact
    assert derived[0].start == 0 and derived[0].end == len(result)

    narrowed = state.derive(marks, "slice", start=1, end=4, exact=True)
    assert narrowed[0].start == 1
    assert narrowed[0].end == 4
    shifted = replace(narrowed[0], start=2, end=5)
    assert shifted.start == 2 and shifted.end == 5

    original = (
        Mark("src-1", 1, -2, None),
        Mark("src-1", 1, 1, 3),
        Mark("src-1", 1, 20, 25),
        Mark("src-1", 1, 2, 2),
    )
    carrier = bytearray(b"clipped")
    state.put(carrier, original)
    assert [(m.start, m.end, m.unit) for m in state.marks(carrier)] == [
        (0, 7, "byte"),
        (1, 3, "byte"),
    ]
    assert original[0].start == -2 and original[0].end is None
    state.put(carrier, ())
    assert state.marks(carrier) == ()
    assert narrowed[0].start == 1


def test_sink_emits_no_raw_value_and_parameterized_empty_marks_are_negative(
    monkeypatch,
):
    state = make_state(monkeypatch)
    query = value("do-not-export-this-query")
    state.source(query, "http.request.parameter", "q")
    event = state.sink(
        "sql_injection",
        "sqlite3.Connection.execute",
        "query",
        query,
        location="security_sample#query",
    )
    assert event is not None
    encoded = json.dumps(event, sort_keys=True)
    assert query not in encoded
    assert event["sources"][0]["name"] == "q"
    assert event["sink"]["function"] == "sqlite3.Connection.execute"

    state.sink(
        "sql_injection",
        "sqlite3.Connection.execute",
        "bind_parameter",
        "constant-or-user-bind",
        marks=(),
        location="security_sample#parameterized",
    )
    assert len(state.pending) == 1


def test_request_and_process_tracking_budgets_are_separate(monkeypatch):
    request_limited = make_state(
        monkeypatch, BEACON_SECURITY_MAX_TRACKED_BYTES=1
    )
    query = value("request-budget")
    request_limited.source(query, "http.request.parameter", "q")
    assert request_limited.truncated
    assert "request_retained_byte_limit" in request_limited.gaps

    process_limited = make_state(
        monkeypatch,
        BEACON_SECURITY_MAX_TRACKED_BYTES=1024 * 1024,
        BEACON_SECURITY_MAX_PROCESS_TRACKED_BYTES=1,
    )
    process_limited.source(
        value("process-budget"), "http.request.parameter", "q"
    )
    assert process_limited.truncated
    assert "process_retained_byte_limit" in process_limited.gaps


def test_process_budget_exhaustion_is_sticky_after_other_request_releases(
    monkeypatch,
):
    budget = ByteBudget()
    first = value("first-process-budget")
    second = value("second-process-budget")
    third = value("third-process-budget")
    budget.maximum = sys.getsizeof(first)
    owner = SecurityState(
        identity={"application_id": "app-test"}, budget=budget
    )
    blocked = SecurityState(
        identity={"application_id": "app-test"}, budget=budget
    )
    owner.source(first, "http.request.parameter", "owner")
    blocked.source(second, "http.request.parameter", "blocked")
    assert blocked.tracking_exhausted
    assert blocked.marks(second) == ()

    owner.close()
    blocked.source(third, "http.request.parameter", "after-release")
    assert budget.used == 0
    assert blocked.marks(third) == ()
    assert "process_retained_byte_limit" in blocked.gaps
    blocked.close()


def test_source_signature_budget_uses_max_nodes(monkeypatch):
    state = make_state(monkeypatch, BEACON_SECURITY_MAX_NODES=2)
    first = value("signature-one")
    second = value("signature-two")
    third = value("signature-three")

    state.source(first, "http.request.parameter", "one")
    state.source(second, "http.request.parameter", "two")
    state.source(third, "http.request.parameter", "three")

    assert len(state.source_signatures) == 2
    assert state.source_count == 2
    assert state.marks(third) == ()
    assert "source_signature_limit" in state.gaps


def test_close_releases_process_budget_and_invalidates_marks(monkeypatch):
    budget = ByteBudget()
    state = SecurityState(
        identity={"application_id": "app-test"}, budget=budget
    )
    query = value("close-query")
    state.source(query, "http.request.parameter", "q")
    assert budget.used > 0
    state.close()
    assert state.closed
    assert budget.used == 0
    assert state.marks(query) == ()
