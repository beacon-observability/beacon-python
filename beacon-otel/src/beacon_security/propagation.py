from __future__ import annotations

import builtins
import pathlib
import types
from dataclasses import dataclass
from itertools import islice

from .structured_models import (
    PATH_METHODS,
    PATH_TRANSFORMS,
    URL_TRANSFORMS,
    url_parts,
)


def input_marks(state, values):
    result = []
    pending = [(value, 0) for value in values]
    seen = set()
    while pending:
        value, depth = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if len(seen) > 512:
            state.gap("call_input_traversal_limit")
            return tuple(result)
        result.extend(state.marks(value))
        if len(result) >= state.max_marks:
            state.gap("call_input_mark_limit")
            return tuple(result[: state.max_marks])
        if depth < 2 and type(value) in (tuple, list):
            if len(value) > 128:
                state.gap("call_container_limit")
            pending.extend((item, depth + 1) for item in value[:128])
        elif depth < 2 and type(value) is dict:
            if len(value) > 128:
                state.gap("call_container_limit")
            pending.extend(
                (item, depth + 1) for item in islice(value.values(), 128)
            )
        elif (
            depth >= 2
            and type(value) in (dict, list, tuple)
            and value
            and state.source_count
        ):
            state.gap("call_container_depth")
    return tuple(result)


@dataclass
class CallModel:
    name: str
    receiver: object
    marks: tuple
    receiver_marks: tuple
    args: tuple
    kwargs: dict
    pieces: list | None = None
    piece_count: int = 0
    known: bool = False


_STRING_METHODS = {
    "format",
    "format_map",
    "join",
    "replace",
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "casefold",
    "capitalize",
    "title",
    "swapcase",
    "encode",
    "decode",
    "removeprefix",
    "removesuffix",
    "partition",
    "rpartition",
    "split",
    "rsplit",
    "splitlines",
}
_CONSUMER_MODULES = (
    "sqlite3",
    "psycopg",
    "pymysql",
    "sqlalchemy",
    "django.db",
    "subprocess",
    "requests",
    "httpx",
    "aiohttp",
    "urllib.request",
    "beacon_security",
)
_PATH_TYPES = (
    pathlib.Path,
    pathlib.PosixPath,
    pathlib.WindowsPath,
    pathlib.PurePath,
    pathlib.PurePosixPath,
    pathlib.PureWindowsPath,
)


def describe(function):
    import wrapt

    if any(
        type(function) is kind
        for kind in (
            types.FunctionType,
            types.MethodType,
            types.BuiltinFunctionType,
            types.BuiltinMethodType,
            type,
            wrapt.FunctionWrapper,
            wrapt.BoundFunctionWrapper,
        )
    ):
        return (
            getattr(function, "__name__", ""),
            getattr(function, "__module__", "") or "",
            getattr(function, "__self__", None),
        )
    return "", "", None


def coroutine_function(function):
    import inspect

    import wrapt

    if any(
        type(function) is kind
        for kind in (
            types.FunctionType,
            types.MethodType,
            wrapt.FunctionWrapper,
            wrapt.BoundFunctionWrapper,
        )
    ):
        return inspect.iscoroutinefunction(function)
    return False


def before(state, function, args, kwargs):
    name, module, receiver = describe(function)
    receiver_marks = state.marks(receiver)
    marks = input_marks(state, (receiver, *args, *kwargs.values()))
    parts = url_parts(state, receiver)
    if parts is not None:
        marks += input_marks(state, parts)
    for value in args:
        parts = url_parts(state, value)
        if parts is not None:
            marks += input_marks(state, parts)
    # join can discover marked values while consuming its generator. Other
    # calls with no marked inputs need no return-value propagation model.
    if not marks and not (
        type(receiver) in (str, bytes, bytearray) and name == "join"
    ):
        return None, args
    model = CallModel(name, receiver, marks, receiver_marks, args, kwargs)
    if type(receiver) in (str, bytes, bytearray) and name in _STRING_METHODS:
        model.known = True
        if name == "join" and len(args) == 1 and not kwargs:
            model.pieces = []
            iterable = args[0]

            def capture(piece):
                model.piece_count += 1
                if len(model.pieces) < 128 and type(piece) in (str, bytes):
                    model.pieces.append((len(piece), state.marks(piece)))
                else:
                    state.gap("join_piece_limit_or_type")

            if type(iterable) in (tuple, list):
                if len(iterable) > 128:
                    state.gap("join_piece_limit_or_type")
                    model.piece_count = len(iterable)
                for piece in iterable[:128]:
                    capture(piece)
            elif type(iterable) is types.GeneratorType:

                def observe():
                    for piece in iterable:
                        capture(piece)
                        yield piece

                args = (observe(),)
            else:
                model.pieces = None
                state.gap("unmodeled_join_iterable")
    elif any(
        function is builtin
        for builtin in (builtins.str, builtins.bytes, builtins.bytearray)
    ):
        model.known = True
        model.name = "convert"
    elif any(function is kind for kind in _PATH_TYPES) or (
        any(type(receiver) is kind for kind in _PATH_TYPES)
        and module in ("pathlib", "pathlib._local", "pathlib._abc")
        and name in PATH_METHODS
    ):
        model.known = True
        model.name = "pathlib." + name
    elif any(type(receiver) is kind for kind in _PATH_TYPES) and (
        module in ("pathlib", "pathlib._local", "pathlib._abc")
        and name in ("read_text", "read_bytes")
    ):
        # The path selects a file; its characters do not map to the returned
        # contents. File sink hooks still observe the controlled path.
        model.known = True
        model.name = "consumer"
    elif (
        module in ("posixpath", "ntpath", "genericpath")
        and name in PATH_TRANSFORMS
        or module == "urllib.parse"
        and name in URL_TRANSFORMS
    ):
        model.known = True
        model.name = module + "." + name
    elif name == "geturl" and url_parts(state, receiver) is not None:
        model.known = True
        model.name = "urllib.parse.geturl"
    elif (
        module.startswith(_CONSUMER_MODULES)
        or function is builtins.open
        or module in ("os", "posix", "io", "_io")
    ):
        model.known = True
        model.name = "consumer"
    return model, args


def after(state, model, result, location):
    name, receiver, args, kwargs = (
        model.name,
        model.receiver,
        model.args,
        model.kwargs,
    )
    if type(result) in (str, bytes) and state.marks(result):
        # Identity-preserving string operations must not rewrite the original
        # object's provenance through an otherwise unused alias expression.
        return result
    if name == "join" and model.pieces is not None:
        if model.piece_count > 128:
            return result
        marks, offset = [], 0
        for index, (size, piece_marks) in enumerate(model.pieces):
            if index:
                marks.extend(
                    state.derive(
                        model.receiver_marks,
                        "join.separator",
                        location,
                        shift=offset,
                    )
                )
                offset += len(receiver)
            marks.extend(
                state.derive(piece_marks, "join", location, shift=offset)
            )
            offset += size
        if marks:
            state.put(result, marks)
        return result
    if not model.marks:
        return result
    if name in ("urllib.parse.urlsplit", "urllib.parse.urlparse") and args:
        from .structured_models import parse_parts

        if parse_parts(state, args[0], result, location):
            return result
    if name in (
        "urllib.parse.urlunsplit",
        "urllib.parse.urlunparse",
        "urllib.parse.geturl",
    ):
        from .structured_models import compose_parts

        parts = (
            receiver if name.endswith("geturl") else args[0] if args else None
        )
        if compose_parts(state, parts, result, location):
            return result
    if name in ("format", "format_map"):
        from .string_models import format_ranges

        ranges = format_ranges(
            state,
            receiver,
            args,
            kwargs,
            result,
            location,
            mapping=name == "format_map",
        )
        if ranges is not None:
            state.put(result, ranges)
            return result
    if name == "replace":
        from .string_models import replace_ranges

        ranges = replace_ranges(
            state, receiver, args, kwargs, result, location
        )
        if ranges is not None:
            state.put(result, ranges)
            return result
    if (
        name in ("strip", "lstrip", "rstrip")
        and type(receiver) in (str, bytes)
        and type(result) is type(receiver)
    ):
        if (
            len(args) <= 1
            and not kwargs
            and (
                not args or args[0] is None or type(args[0]) is type(receiver)
            )
        ):
            offset = (
                0
                if name == "rstrip"
                else len(receiver) - len(receiver.lstrip(*args))
            )
            state.put(
                result,
                state.derive(
                    model.receiver_marks,
                    name,
                    location,
                    shift=-offset,
                    start=offset,
                    end=offset + len(result),
                ),
            )
            return result
    if (
        name in ("removeprefix", "removesuffix")
        and type(receiver) in (str, bytes)
        and type(result) is type(receiver)
    ):
        offset = len(receiver) - len(result) if name == "removeprefix" else 0
        state.put(
            result,
            state.derive(
                model.receiver_marks,
                name,
                location,
                shift=-offset,
                start=offset,
                end=offset + len(result),
            ),
        )
        return result
    if (
        name in _STRING_METHODS
        or name == "convert"
        or name.startswith(
            (
                "posixpath.",
                "ntpath.",
                "genericpath.",
                "pathlib.",
                "urllib.parse.",
            )
        )
    ):
        marks = state.derive(model.marks, name, location, exact=False)
        if type(result) in (list, tuple) and (
            name
            in ("split", "rsplit", "splitlines", "partition", "rpartition")
            or name.startswith(("posixpath.", "ntpath.", "genericpath."))
        ):
            for value in result[:128]:
                state.put(value, marks)
            if len(result) > 128:
                state.gap("propagation_container_limit")
        else:
            state.put(result, marks)
    elif (
        not model.known
        and (
            type(result) in (str, bytes, bytearray)
            or isinstance(result, pathlib.PurePath)
        )
        and not state.marks(result)
    ):
        state.gap("unmodeled_call_result")
    return result
