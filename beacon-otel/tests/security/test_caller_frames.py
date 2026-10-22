from __future__ import annotations

import asyncio
import logging
import pickle
import sys
import types
import warnings

import pytest
from beacon_security import ast_hooks, runtime
from beacon_security.transform import transform
from test_transform_behavior import start_runtime

SOURCE = """
import collections
import enum
import logging
import typing
import warnings
from functools import partial
from logging import warning as alias
logger = logging.getLogger("beacon.caller.regression")
adapter = logging.LoggerAdapter(logger, {})
def leaf(callback):
    callback("at leaf")
    callback("at caller", stacklevel=2)
def outer(callback):
    leaf(callback)
async def async_leaf(callback):
    callback("at async leaf")
    callback("at async caller", stacklevel=2)
async def async_outer(callback):
    await async_leaf(callback)
def warning_leaf(callback):
    callback("at leaf", UserWarning, 1)
    callback("at caller", UserWarning, 2)
def warning_outer(callback):
    warning_leaf(callback)
def zero_leaf(callback):
    callback()
def zero_outer(callback):
    zero_leaf(callback)
def factories():
    global Row, Kind, Variable, Alias, Params, Shape, Named, Typed
    Row = collections.namedtuple("Row", "value")
    Kind = enum.Enum("Kind", "YES NO")
    Variable = typing.TypeVar("Variable")
    Alias = typing.NewType("Alias", int)
    Params = typing.ParamSpec("Params")
    Shape = typing.TypeVarTuple("Shape")
    Named = typing.NamedTuple("Named", [("value", int)])
    Typed = typing.TypedDict("Typed", {"value": int})
"""


def module(monkeypatch, instrumented):
    name = "beacon_caller_fixture"
    result = types.ModuleType(name)
    monkeypatch.setitem(sys.modules, name, result)
    code = (
        transform(SOURCE, "caller_business.py", name)
        if instrumented
        else SOURCE
    )
    exec(compile(code, "caller_business.py", "exec"), result.__dict__)
    return result


@pytest.mark.parametrize("active", [False, True])
def test_logging_matches_native_locations_and_stacklevel(
    monkeypatch, tmp_path, active
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    logger = logging.getLogger("beacon.caller.regression")
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger.addHandler(handler)
    # Module-level logging functions use the root logger.
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        outputs = []
        for instrumented in (False, True):
            fixture = module(monkeypatch, instrumented)
            from functools import partial

            callbacks = (
                fixture.logger.warning,
                fixture.adapter.warning,
                logging.warning,
                fixture.alias,
                partial(fixture.logger.log, logging.WARNING),
                partial(logging.log, logging.WARNING),
            )
            with runtime.bound_state(state) if active else runtime.suppress():
                for callback in callbacks:
                    records.clear()
                    fixture.outer(callback)
                    asyncio.run(fixture.async_outer(callback))
                    outputs.append(
                        [
                            (r.filename, r.funcName, r.lineno, r.msg)
                            for r in records
                        ]
                    )
        assert outputs[: len(callbacks)] == outputs[len(callbacks) :]
        assert {item[1] for result in outputs for item in result} == {
            "leaf",
            "outer",
            "async_leaf",
            "async_outer",
        }
    finally:
        logger.removeHandler(handler)
        root.removeHandler(handler)
        current.end_request(state)
        current.detach_state(token)


@pytest.mark.parametrize("active", [False, True])
def test_warnings_and_partial_positional_stacklevel_match_native(
    monkeypatch, tmp_path, active
):
    from functools import partial

    current, state, token = start_runtime(monkeypatch, tmp_path)
    try:
        outputs = []
        for instrumented in (False, True):
            fixture = module(monkeypatch, instrumented)
            with runtime.bound_state(state) if active else runtime.suppress():
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    fixture.warning_outer(warnings.warn)
                    fixture.outer(partial(warnings.warn, category=UserWarning))
                    # Preset positional stacklevel must be adjusted as well.
                    fixture.zero_outer(
                        partial(warnings.warn, "preset", UserWarning, 2)
                    )
                outputs.append(
                    [(w.filename, w.lineno, str(w.message)) for w in caught]
                )
        assert outputs[0] == outputs[1]
    finally:
        current.end_request(state)
        current.detach_state(token)


@pytest.mark.parametrize("active", [False, True])
def test_factory_module_identity_and_pickling_match_native(
    monkeypatch, tmp_path, active
):
    current, state, token = start_runtime(monkeypatch, tmp_path)
    try:
        for instrumented in (False, True):
            fixture = module(monkeypatch, instrumented)
            with runtime.bound_state(state) if active else runtime.suppress():
                fixture.factories()
            for name in (
                "Row",
                "Kind",
                "Variable",
                "Alias",
                "Params",
                "Shape",
                "Named",
                "Typed",
            ):
                assert getattr(fixture, name).__module__ == fixture.__name__
            for value in (
                fixture.Row(7),
                fixture.Named(7),
                fixture.Kind.YES,
                fixture.Variable,
                fixture.Alias,
            ):
                assert pickle.loads(pickle.dumps(value)) == value
    finally:
        current.end_request(state)
        current.detach_state(token)


def test_frame_dispatch_does_not_probe_application_callable_attributes():
    class Callable:
        def __getattribute__(self, name):
            raise AssertionError(name)

        def __call__(self):
            return 42

    assert ast_hooks.call_target(Callable(), "test")() == 42


@pytest.mark.skipif(
    sys.version_info < (3, 12), reason="skip_file_prefixes added in 3.12"
)
def test_warning_skip_file_prefixes_matches_native(monkeypatch):
    from functools import partial

    outputs = []
    for instrumented in (False, True):
        fixture = module(monkeypatch, instrumented)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            fixture.zero_outer(
                partial(
                    warnings.warn,
                    "prefix",
                    skip_file_prefixes=("caller_business",),
                )
            )
        outputs.append([(w.filename, w.lineno) for w in caught])
    assert outputs[0] == outputs[1]
