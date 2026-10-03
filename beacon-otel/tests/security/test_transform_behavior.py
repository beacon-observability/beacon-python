from __future__ import annotations

import importlib

import pytest
from beacon_security.transform import transform


def test_frame_sensitive_import_and_assignment_aliases_keep_business_frame():
    source = """
from builtins import locals as current_locals, eval as evaluate
from sys import _getframe as frame
alias = current_locals
def check():
    business_value = 42
    nested_alias = alias
    return nested_alias()["business_value"], evaluate("business_value"), frame().f_code.co_name
"""
    for instrumented in (False, True):
        namespace = {}
        tree = (
            transform(source, "alias_fixture.py", "security_sample.alias")
            if instrumented
            else source
        )
        exec(compile(tree, "alias_fixture.py", "exec"), namespace)
        assert namespace["check"]() == (42, 42, "check")


def test_reverse_alias_chains_and_cycles_preserve_locals_and_zero_argument_super():
    count = 2000
    source = "\n".join(f"alias{i} = None" for i in range(count))
    source += "\nif False:\n" + "\n".join(
        f"    alias{i} = alias{i + 1}" for i in range(count - 1)
    )
    source += f"\nalias{count - 1} = locals\n"
    source += "\n".join(
        f"alias{i} = alias{i + 1}" for i in reversed(range(count - 1))
    )
    source += """
loop_a = loop_b = None
if False:
    loop_a = loop_b
    loop_b = loop_a
loop_b = super
loop_a = loop_b
class Base:
    def value(self):
        return 17
class Child(Base):
    def value(self):
        __class__
        business_value = 42
        return alias0()["business_value"], loop_a().value()
"""
    for instrumented in (False, True):
        namespace = {}
        tree = (
            transform(
                source, "reverse_alias.py", "security_sample.reverse_alias"
            )
            if instrumented
            else source
        )
        exec(compile(tree, "reverse_alias.py", "exec"), namespace)
        assert namespace["Child"]().value() == (42, 17)


def test_dynamic_frame_sensitive_callables_keep_the_business_frame(
    monkeypatch, tmp_path
):
    import builtins
    import inspect
    import sys
    from functools import partial

    source = """
def check(callback, evaluate, frame):
    from builtins import __dict__ as scope
    dynamic = scope["locals"]
    business_value = 42
    return dynamic()["business_value"], callback()["business_value"], evaluate("business_value"), frame().f_code.co_name
def callback_order(factory, argument):
    return factory()(argument())
"""
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    try:
        for instrumented in (False, True):
            namespace = {}
            tree = (
                transform(
                    source, "dynamic_frame.py", "security_sample.dynamic_frame"
                )
                if instrumented
                else source
            )
            exec(compile(tree, "dynamic_frame.py", "exec"), namespace)
            for active in (False, True):
                with runtime.bound_state(state if active else None):
                    for callback in (
                        builtins.locals,
                        partial(builtins.locals),
                    ):
                        for frame in (sys._getframe, inspect.currentframe):
                            assert namespace["check"](
                                callback, builtins.eval, frame
                            ) == (42, 42, 42, "check")
                    order = []

                    def factory():
                        order.append("function")
                        return lambda value: (order.append("call"), value)[1]

                    def argument():
                        order.append("argument")
                        return 42

                    assert namespace["callback_order"](factory, argument) == 42
                    assert order == ["function", "argument", "call"]
        assert "dynamic_code_execution" in state.gaps
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def start_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "none")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    runtime = importlib.import_module("beacon_security.runtime")
    if getattr(runtime, "_runtime", None) is not None:
        runtime.stop()
    runtime = importlib.reload(runtime)
    state = runtime.start_request({"route": "/transform"})
    token = runtime.attach_state(state)
    return runtime, state, token


def execute_transformed(source_text, runtime, filename="dynamic_fixture.py"):
    tree = transform(source_text, filename, "security_sample.dynamic_fixture")
    namespace = {
        "__name__": "security_sample.dynamic_fixture",
        "__file__": filename,
        "runtime": runtime,
    }
    exec(compile(tree, filename, "exec"), namespace)
    return namespace


def test_path_construction_and_transform_reach_real_file_sinks(
    monkeypatch, tmp_path
):
    from pathlib import Path, PurePath

    from beacon_security import sinks

    runtime, state, token = start_runtime(monkeypatch, tmp_path / "output")
    sinks.install()
    namespace = execute_transformed(
        """
from pathlib import Path, PurePath
def use(name):
    pure = PurePath(name)
    path = Path(pure).with_suffix(".txt")
    path.write_text("path-regression")
    content = path.read_text()
    binary = path.read_bytes()
    path.unlink()
    return pure, path, content, binary
def join(root, name):
    return Path(root).joinpath(name)
def read_custom(path):
    return path.read_text()
""",
        runtime,
    )
    try:
        name = str(tmp_path / "controlled.input")
        runtime.source(name, "http.request.parameter", "path")
        pure, path, content, binary = namespace["use"](name)
        assert isinstance(pure, PurePath) and isinstance(path, Path)
        assert state.marks(pure) and state.marks(path)
        assert content == "path-regression" and not path.exists()
        assert binary == b"path-regression"
        assert not state.marks(content) and not state.marks(binary)
        assert "unmodeled_call_result" not in state.gaps
        assert {
            event["sink"]["operation"]
            for event in state.pending
            if event["rule"] == "path_traversal"
        } == {"read", "write", "delete"}
        leaf = "".join(("controlled", "-leaf.txt"))
        runtime.source(leaf, "http.request.parameter", "leaf")
        assert state.marks(namespace["join"](str(tmp_path), leaf))
        with monkeypatch.context() as patch:
            patch.setattr(Path, "read_text", lambda self: "custom content")
            assert namespace["read_custom"](path) == "custom content"
            assert "unmodeled_call_result" in state.gaps
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)
        sinks.uninstall()


def test_native_augmented_add_preserves_order_nested_calls_exceptions_and_marks(
    monkeypatch, tmp_path
):
    import asyncio
    import contextvars

    source = """
def append(left, right):
    left += right
    return left
def ordered(right):
    value = "prefix:"
    def operand():
        nonlocal value
        value = "replacement"
        nested = "nested:"
        nested += "value"
        return right
    value += operand()
    return value, sorted(locals())
async def suspended(right):
    import asyncio
    async def operand():
        await asyncio.sleep(0)
        nested = "async:"
        nested += right
        return nested
    value = "prefix:"
    value += await operand()
    return value
def generator():
    value = "prefix:"
    value += (yield "ready")
    return value
"""
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    try:
        native = {}
        exec(compile(source, "iadd_native.py", "exec"), native)
        fixture = execute_transformed(source, runtime)
        for active in (False, True):
            with runtime.bound_state(state) if active else runtime.suppress():
                assert fixture["ordered"]("tail") == native["ordered"]("tail")
                assert asyncio.run(
                    fixture["suspended"]("tail")
                ) == asyncio.run(native["suspended"]("tail"))
                generator = fixture["generator"]()
                assert contextvars.Context().run(next, generator) == "ready"
                with pytest.raises(StopIteration) as stopped:
                    contextvars.Context().run(generator.send, "tail")
                assert stopped.value.value == "prefix:tail"
                calls = []

                class Failing:
                    def __iadd__(self, other):
                        calls.append(other)
                        fixture["append"]("inner:", "clean")
                        raise ValueError("application failure")

                with pytest.raises(ValueError, match="application failure"):
                    fixture["append"](Failing(), 7)
                assert calls == [7]
                clean = fixture["append"]("clean:", "suffix")
                assert clean == "clean:suffix" and not state.marks(clean)
        for secret in (("_" + "request-query")[1:], b"_request-bytes"[1:]):
            state.source(secret, "http.request.parameter", "q")
            prefix = "prefix:" if type(secret) is str else b"prefix:"
            result = fixture["append"](prefix, secret)
            assert result == prefix + secret
            assert [
                (mark.start, mark.end) for mark in state.marks(result)
            ] == [(len(prefix), len(result))]
            assert fixture["append"](secret, type(secret)()) is secret
        generator = fixture["generator"]()
        assert next(generator) == "ready"
        with pytest.raises(StopIteration) as stopped:
            generator.send("tail")
        assert stopped.value.value == "prefix:tail"
        assert "generator_iadd_propagation" in state.gaps
        assert not any(
            gap.startswith("propagation_error") for gap in state.gaps
        )
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_transform_preserves_eval_once_order_fstrings_and_types(
    monkeypatch, tmp_path
):
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    query = ("_" + "甲😀乙")[1:]
    runtime.source(query, "http.request.parameter", "q")
    source_text = """
def evaluate(value):
    calls = []
    order = []
    def once():
        calls.append("once")
        return value
    def left():
        order.append("left")
        return value
    def right():
        order.append("right")
        return "tail"
    width = ">8"
    dynamic = f"{once():{width}}"
    represented = f"{value!r}"
    plus = left() + right()
    percent = "%s" % value
    formatted = "{}:{}".format("prefix", value)
    joined = "|".join(("prefix", value))
    sliced = value[1:]
    astral_slice = value[1:2]
    return calls, order, dynamic, represented, plus, percent, formatted, joined, sliced, astral_slice
"""
    try:
        result = execute_transformed(source_text, runtime)["evaluate"](query)
        assert result[0] == ["once"]
        assert result[1] == ["left", "right"]
        assert all(type(item) is str for item in result[2:])
        assert result[2].strip() == query
        assert result[3] == repr(query)
        assert result[4].endswith("tail")
        assert result[5] == query
        assert result[6].endswith(query)
        assert result[7].endswith(query)
        assert result[8] == query[1:]
        assert result[9] == "😀"
        assert state.marks(result[2])
        assert state.marks(result[3])
        assert state.marks(result[4])
        assert state.marks(result[5])
        assert state.marks(result[6])
        assert state.marks(result[7])
        assert state.marks(result[8])
        astral_marks = state.marks(result[9])
        assert astral_marks
        assert astral_marks[0].start == 0
        assert astral_marks[0].end == 1
        assert astral_marks[0].unit == "unicode_code_point"
        assert "shared_scalar_identity" not in state.gaps
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_transform_preserves_application_exception_and_calls_once(
    monkeypatch, tmp_path
):
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    source_text = """
def failing(value):
    calls = []
    def explode():
        calls.append("explode")
        raise LookupError("application failure")
    try:
        f"{explode():>8}"
    except LookupError as error:
        return type(error), str(error), calls
    return None, None, calls
"""
    try:
        result = execute_transformed(source_text, runtime)["failing"]("unused")
        assert result == (LookupError, "application failure", ["explode"])
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_transformed_sql_and_parameterized_paths_use_marks_without_copying_types(
    monkeypatch, tmp_path
):
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    query = ("_" + "sql-input")[1:]
    runtime.source(query, "http.request.parameter", "q")
    source_text = """
def build(value):
    unsafe = "select name from users where name = '" + value + "'"
    parameterized = "select name from users where name = ?"
    return unsafe, parameterized, value[1:]
"""
    try:
        unsafe, parameterized, sliced = execute_transformed(
            source_text, runtime
        )["build"](query)
        unsafe_marks = state.marks(unsafe)
        assert unsafe_marks
        assert type(unsafe) is str
        assert type(parameterized) is str
        assert type(sliced) is str
        event = state.sink(
            "sql_injection",
            "sqlite3.Connection.execute",
            "template",
            unsafe,
            marks=unsafe_marks,
            location="security_sample.dynamic_fixture#build",
        )
        assert event is not None
        negative = state.sink(
            "sql_injection",
            "sqlite3.Connection.execute",
            "template",
            parameterized,
            marks=state.marks(parameterized),
            location="security_sample.dynamic_fixture#parameterized",
        )
        assert negative is None
        assert state.marks(sliced)
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_bytes_transform_preserves_bytes_and_byte_units(monkeypatch, tmp_path):
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    value = b"bytes-input"
    runtime.source(value, "http.request.body", "body")
    source_text = """
def operate(value):
    plus = value + b"-tail"
    percent = b"%s" % value
    joined = b"|".join((b"prefix", value))
    sliced = value[1:]
    return plus, percent, joined, sliced
"""
    try:
        plus, percent, joined, sliced = execute_transformed(
            source_text, runtime
        )["operate"](value)
        assert all(
            type(item) is bytes for item in (plus, percent, joined, sliced)
        )
        assert state.marks(plus)[0].unit == "byte"
        assert state.marks(percent)[0].unit == "byte"
        assert state.marks(joined)[0].unit == "byte"
        assert state.marks(sliced)[0].unit == "byte"
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_identity_preserving_scalar_aliases_keep_original_provenance(
    monkeypatch, tmp_path
):
    runtime, state, token = start_runtime(monkeypatch, tmp_path)
    value = "".join(("alias", "-query"))
    runtime.source(value, "http.request.parameter", "q")
    original_marks = state.marks(value)
    original_nodes = len(state.nodes)
    source_text = """
def aliases(value):
    string_alias = str(value)
    singleton_join = "".join((value,))
    percent_alias = "%s" % value
    format_alias = "{}".format(value)
    return string_alias, singleton_join, percent_alias, format_alias
"""
    try:
        aliases = execute_transformed(source_text, runtime)["aliases"](value)
        assert all(type(result) is str for result in aliases)
        assert all(result is value for result in aliases)
        assert all(state.marks(result) == original_marks for result in aliases)
        assert len(state.nodes) == original_nodes
        assert "source_identity_ambiguous" not in state.gaps
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_helper_alias_avoids_all_lexical_bindings():
    sources = [
        "def run(__beacon_security_hooks__): return 'a' + 'b'",
        "def __beacon_security_hooks__(): pass\ndef run(unused): return 'a' + 'b'",
        "import math as __beacon_security_hooks__\ndef run(unused): return 'a' + 'b'",
        "def run(unused):\n try: raise ValueError()\n except ValueError as __beacon_security_hooks__: return 'a' + 'b'",
        "def run(unused):\n match unused:\n  case __beacon_security_hooks__: return 'a' + 'b'",
    ]
    for source in sources:
        for instrumented in (False, True):
            namespace = {}
            tree = (
                transform(
                    source, "binding_fixture.py", "security_sample.binding"
                )
                if instrumented
                else source
            )
            exec(compile(tree, "binding_fixture.py", "exec"), namespace)
            assert namespace["run"](None) == "ab"
