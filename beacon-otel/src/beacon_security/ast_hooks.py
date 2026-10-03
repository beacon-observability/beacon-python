from __future__ import annotations

import builtins
import contextvars
import inspect
import operator
import sys
from functools import partial

from . import propagation, runtime

_OPERATORS = {
    "Add": operator.add,
    "Mod": operator.mod,
    "Div": operator.truediv,
    "IAdd": operator.iadd,
}
_FRAME_FUNCTIONS = (
    builtins.super,
    builtins.locals,
    builtins.globals,
    builtins.vars,
    builtins.dir,
    builtins.eval,
    builtins.exec,
    builtins.compile,
    builtins.__build_class__,
    sys._getframe,
    inspect.currentframe,
)
_FRAME_FUNCTION_IDS = frozenset(map(id, _FRAME_FUNCTIONS))
_IADD = contextvars.ContextVar("beacon_security_iadd", default=None)


class AugmentedAdd:
    __slots__ = ("token", "observation")

    def __enter__(self):
        self.observation = None
        self.token = _IADD.set(self)

    def __exit__(self, *_):
        _IADD.reset(self.token)
        self.token = self.observation = None


def iadd_operand(left, right):
    state = runtime.current_state()
    if (
        state is not None
        and type(left) is type(right)
        and type(left) in (str, bytes)
    ):
        left_marks, right_marks = state.marks(left), state.marks(right)
        if left_marks or right_marks:
            _IADD.get().observation = (
                state,
                left_marks,
                right_marks,
                len(left),
            )
    return right


def iadd_result(result, location):
    observation = _IADD.get().observation
    if observation is None:
        return
    state, left_marks, right_marks, offset = observation
    try:
        with runtime.suppress():
            if not state.marks(result):
                marks = state.derive(left_marks, "concat", location)
                marks += state.derive(
                    right_marks, "concat", location, shift=offset
                )
                if marks:
                    state.put(result, marks)
    except Exception as error:
        state.gap("propagation_error:" + type(error).__name__)


def binary(left, right, operation, location):
    function = _OPERATORS[operation]
    state = runtime.current_state()
    if state is None:
        return function(left, right)
    left_marks = state.marks(left)
    right_marks = propagation.input_marks(state, (right,))
    result = function(left, right)
    if (
        type(result) in (str, bytes)
        and (result is left or result is right)
        and state.marks(result)
    ):
        return result
    try:
        with runtime.suppress():
            if (
                operation in ("Add", "IAdd")
                and type(left) is type(right)
                and type(left) in (str, bytes)
            ):
                marks = state.derive(left_marks, "concat", location)
                marks += state.derive(
                    right_marks, "concat", location, shift=len(left)
                )
                if marks:
                    state.put(result, marks)
            elif (left_marks or right_marks) and (
                operation == "Mod"
                and type(left) in (str, bytes)
                or operation == "Div"
            ):
                from .string_models import percent_ranges

                marks = (
                    percent_ranges(state, left, right, result, location)
                    if operation == "Mod"
                    else None
                )
                if marks is None:
                    marks = state.derive(
                        left_marks + right_marks,
                        operation,
                        location,
                        exact=False,
                    )
                state.put(result, marks)
    except Exception as error:
        state.gap("propagation_error:" + type(error).__name__)
    return result


def make_slice(start, stop, step):
    return builtins.slice(start, stop, step)


def subscript(value, key, location):
    state = runtime.current_state()
    marks = state.marks(value) if state else ()
    result = value[key]
    if state is not None:
        try:
            from . import frameworks

            frameworks.observe_access(value, key, result, location)
        except Exception as error:
            state.gap("source_access_error:" + type(error).__name__)
    if (
        state is None
        or not marks
        or type(value) not in (str, bytes, bytearray)
    ):
        return result
    try:
        with runtime.suppress():
            if type(key) is slice and all(
                v is None or type(v) is int
                for v in (key.start, key.stop, key.step)
            ):
                start, stop, step = key.indices(len(value))
                if step == 1:
                    state.put(
                        result,
                        state.derive(
                            marks,
                            "slice",
                            location,
                            shift=-start,
                            start=start,
                            end=stop,
                        ),
                    )
                else:
                    state.put(
                        result,
                        state.derive(marks, "slice", location, exact=False),
                    )
            elif type(key) is int and type(result) is str:
                start = key if key >= 0 else len(value) + key
                state.put(
                    result,
                    state.derive(
                        marks,
                        "index",
                        location,
                        shift=-start,
                        start=start,
                        end=start + 1,
                    ),
                )
            else:
                state.gap("unmodeled_subscript_conversion")
    except Exception as error:
        state.gap("propagation_error:" + type(error).__name__)
    return result


def attribute(value, name, location):
    result = getattr(value, name)
    state = runtime.current_state()
    if state is not None:
        try:
            with runtime.suppress():
                from .structured_models import attribute as propagate_attribute

                propagate_attribute(state, value, name, result, location)
        except Exception as error:
            state.gap("attribute_observation_error:" + type(error).__name__)
    return result


def formatted(value, conversion, spec, location):
    state = runtime.current_state()
    marks = propagation.input_marks(state, (value, spec)) if state else ()
    converted = {115: str, 114: repr, 97: ascii}.get(conversion, lambda v: v)(
        value
    )
    result = format(converted, spec)
    if state is not None and result is value and state.marks(result):
        return result
    if state is not None and marks:
        try:
            with runtime.suppress():
                exact = (
                    type(value) is str and conversion in (-1, 115) and not spec
                )
                state.put(
                    result,
                    state.derive(
                        marks, "fstring.format", location, exact=exact
                    ),
                )
        except Exception as error:
            state.gap("propagation_error:" + type(error).__name__)
    return result


def joined(parts, location):
    result = "".join(parts)
    state = runtime.current_state()
    if state is not None and state.marks(result):
        return result
    if state is not None:
        try:
            with runtime.suppress():
                marks, offset = (), 0
                for part in parts:
                    marks += state.derive(
                        state.marks(part),
                        "fstring.join",
                        location,
                        shift=offset,
                    )
                    offset += len(part)
                if marks:
                    state.put(result, marks)
        except Exception as error:
            state.gap("propagation_error:" + type(error).__name__)
    return result


def _before(state, function, args, kwargs, location):
    from . import sinks

    try:
        with runtime.suppress():
            model, arguments = propagation.before(
                state, function, args, kwargs
            )
        # Sink hooks use current_state(), so suppression must not hide the request.
        token = sinks.call_before(function, arguments, kwargs, location)
        return model, token, arguments
    except Exception as error:
        state.gap("call_observation_error:" + type(error).__name__)
        return None, None, args


def _after(state, model, token, result, location):
    from . import sinks

    try:
        sinks.call_after(token, result)
        if model is not None:
            with runtime.suppress():
                propagation.after(state, model, result, location)
    except Exception as error:
        state.gap("call_observation_error:" + type(error).__name__)
    return result


def call_target(function, location, awaited=False):
    actual = function
    while type(actual) is partial:
        actual = actual.func
    # Return the actual callable to the transformed business frame. Calling a
    # dynamic locals/eval alias inside a helper changes its implicit namespace.
    if id(actual) in _FRAME_FUNCTION_IDS:
        if actual is builtins.eval or actual is builtins.exec:
            runtime.gap("dynamic_code_execution")
        return function
    return partial(acall if awaited else call, function, location)


def call(function, location, /, *args, **kwargs):
    state = runtime.current_state()
    if state is None or propagation.coroutine_function(function):
        return function(*args, **kwargs)
    model, token, arguments = _before(state, function, args, kwargs, location)
    with runtime.bound_state(state):
        result = function(*arguments, **kwargs)
    return _after(state, model, token, result, location)


async def acall(function, location, /, *args, **kwargs):
    state = runtime.current_state()
    if state is None:
        return await function(*args, **kwargs)
    model, token, arguments = _before(state, function, args, kwargs, location)
    with runtime.bound_state(state):
        result = await function(*arguments, **kwargs)
    return _after(state, model, token, result, location)


def unmodeled(value, reason):
    runtime.gap(reason)
    return value
