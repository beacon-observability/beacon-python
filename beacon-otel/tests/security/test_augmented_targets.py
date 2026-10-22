from __future__ import annotations

import asyncio
import contextvars
from types import SimpleNamespace

import pytest
from beacon_security import ast_hooks
from test_transform_behavior import execute_transformed, start_runtime

SOURCE = """
def attr(target, right):
    target.value += right
    return target.value
def item(target, key, right):
    target[key] += right
    return target[key]
def ordered(target, key, operand):
    target()[key()] += operand()
def ordered_attr(target, operand):
    target().value += operand()
async def suspended(target, operand):
    target.value += await operand()
    return target.value
def generator(target):
    target.value += (yield "ready")
    return target.value
def item_generator(target):
    target["value"] += (yield "ready")
    return target["value"]
class Private:
    def __init__(self):
        self.__value = "prefix:"
    def append(self, right):
        self.__value += right
        return self.__value
"""


@pytest.mark.parametrize("value", ["request-value", b"request-value"])
def test_attribute_item_private_and_slice_targets_propagate_before_setter(
    monkeypatch, tmp_path, value
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    fixture = execute_transformed(SOURCE, current)
    value = type(value)(value)
    prefix = "SELECT " if type(value) is str else b"SELECT "
    state.source(value, "http.request.parameter", "q")
    observed = []

    class Holder:
        def __init__(self):
            self._value = prefix

        @property
        def value(self):
            return self._value

        @value.setter
        def value(self, result):
            observed.append(
                state.sink(
                    "sql_injection",
                    "test.setter",
                    "query",
                    result,
                    marks=state.marks(result),
                )
            )
            self._value = result

    class Mapping:
        def __init__(self):
            self.value = prefix

        def __getitem__(self, key):
            assert key == slice(1, 3, 2)
            return self.value

        def __setitem__(self, key, result):
            assert key == slice(1, 3, 2)
            observed.append(
                state.sink(
                    "sql_injection",
                    "test.item",
                    "query",
                    result,
                    marks=state.marks(result),
                )
            )
            self.value = result

    try:
        results = [
            fixture["attr"](Holder(), value),
            fixture["item"]({"q": prefix}, "q", value),
        ]
        sliced = execute_transformed(
            """
def append(mapping, right):
    mapping[1:3:2] += right
    return mapping[1:3:2]
""",
            current,
        )
        results.append(sliced["append"](Mapping(), value))
        if type(value) is str:
            results.append(fixture["Private"]().append(value))
        for result in results:
            marks = state.marks(result)
            assert marks and (marks[0].start, marks[0].end) == (
                len(result) - len(value),
                len(result),
            )
        assert len(observed) == 2 and all(observed)
    finally:
        current.end_request(state)
        current.detach_state(token)


@pytest.mark.parametrize("kind", ["attr", "item"])
@pytest.mark.parametrize("failure", [None, "get", "rhs", "iadd", "set"])
def test_targets_match_native_eval_order_single_calls_and_exceptions(
    monkeypatch, tmp_path, kind, failure
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    fixture = execute_transformed(SOURCE, current)
    native = {}
    exec(compile(SOURCE, "native.py", "exec"), native)
    error = LookupError("application failure")

    def run(namespace):
        events = []

        class Value:
            def __iadd__(self, other):
                events.append(("iadd", other))
                if failure == "iadd":
                    raise error
                return self

        class Target:
            def __init__(self):
                self._value = Value()

            def read(self):
                events.append("get")
                if failure == "get":
                    raise error
                return self._value

            def write(self, value):
                events.append("set")
                if failure == "set":
                    raise error
                self._value = value

            value = property(read, write)

            def __getitem__(self, key):
                events.append(("key-get", key))
                return self.read()

            def __setitem__(self, key, value):
                events.append(("key-set", key))
                self.write(value)

        target = Target()

        def receiver():
            events.append("target")
            return target

        def key():
            events.append("key")
            return "value"

        def operand():
            events.append("rhs")
            # Exercise a nested context before raising or returning.
            namespace["attr"](SimpleNamespace(value="inner:"), "clean")
            if failure == "rhs":
                raise error
            return 7

        try:
            if kind == "attr":
                namespace["ordered_attr"](receiver, operand)
            else:
                namespace["ordered"](receiver, key, operand)
        except LookupError as caught:
            assert failure is not None and caught is error
        else:
            assert failure is None
        return events

    try:
        assert run(fixture) == run(native)
        assert ast_hooks._IADD.get() is None
        clean = fixture["attr"](SimpleNamespace(value="clean:"), "tail")
        assert not state.marks(clean)
    finally:
        current.end_request(state)
        current.detach_state(token)


def test_suspended_augassign_keeps_context_and_generator_reports_boundary(
    monkeypatch, tmp_path
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    fixture = execute_transformed(SOURCE, current)
    secret = "".join(("async", "-input"))
    state.source(secret, "http.request.parameter", "q")

    async def operand():
        await asyncio.sleep(0)
        fixture["attr"](SimpleNamespace(value="nested:"), secret)
        return secret

    try:
        result = asyncio.run(
            fixture["suspended"](SimpleNamespace(value="prefix:"), operand)
        )
        assert result == "prefix:" + secret and state.marks(result)
        assert ast_hooks._IADD.get() is None
        for name, target in (
            ("generator", SimpleNamespace(value="prefix:")),
            ("item_generator", {"value": "prefix:"}),
        ):
            generator = fixture[name](target)
            assert contextvars.Context().run(next, generator) == "ready"
            with pytest.raises(StopIteration) as stopped:
                contextvars.Context().run(generator.send, "tail")
            assert stopped.value.value == "prefix:tail"
        # Resume in the collecting context to retain a visible coverage gap.
        generator = fixture["generator"](SimpleNamespace(value="prefix:"))
        assert next(generator) == "ready"
        with pytest.raises(StopIteration):
            generator.send(secret)
        assert "generator_iadd_propagation" in state.gaps
        assert ast_hooks._IADD.get() is None
    finally:
        current.end_request(state)
        current.detach_state(token)


def test_custom_iadd_with_marked_input_reports_model_boundary(
    monkeypatch, tmp_path
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    fixture = execute_transformed(SOURCE, current)
    secret = "".join(("custom", "-input"))
    state.source(secret, "http.request.parameter", "q")
    calls = []

    class Custom:
        def __iadd__(self, value):
            calls.append(value)
            return "custom:" + value

    try:
        assert (
            fixture["attr"](SimpleNamespace(value=Custom()), secret)
            == "custom:" + secret
        )
        assert calls == [secret]
        assert "unmodeled_iadd" in state.gaps
    finally:
        current.end_request(state)
        current.detach_state(token)


def test_concurrent_async_item_and_attribute_operations_keep_marks(
    monkeypatch, tmp_path
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    fixture = execute_transformed(
        SOURCE
        + """
async def suspended_item(target, operand):
    target["value"] += await operand()
    return target["value"]
""",
        current,
    )
    secrets = ["".join(("input-", str(i))) for i in range(4)]
    for value in secrets:
        state.source(value, "http.request.parameter", value)

    async def check():
        async def append(index):
            async def operand():
                await asyncio.sleep(0)
                return secrets[index]

            if index % 2:
                return await fixture["suspended_item"](
                    {"value": "prefix:"}, operand
                )
            return await fixture["suspended"](
                SimpleNamespace(value="prefix:"), operand
            )

        return await asyncio.gather(*(append(i) for i in range(4)))

    try:
        for secret, result in zip(secrets, asyncio.run(check())):
            assert result == "prefix:" + secret
            assert {mark.source_id for mark in state.marks(result)} == {
                mark.source_id for mark in state.marks(secret)
            }
        assert ast_hooks._IADD.get() is None
    finally:
        current.end_request(state)
        current.detach_state(token)
