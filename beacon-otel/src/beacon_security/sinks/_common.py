"""Small, fail-open helpers shared by the Python sink adapters.

The helpers in this module deliberately do not keep copies of application
values.  Values are handed to :mod:`beacon_security.runtime`, which owns mark
storage and evidence redaction.
"""

from __future__ import annotations

import contextlib
import contextvars
import importlib
import inspect
import os
import threading
import weakref
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

_BOUNDARY_STACK: contextvars.ContextVar[tuple[str, ...]] = (
    contextvars.ContextVar("beacon_security_sink_boundaries", default=())
)
_SEGMENT_ROLES: dict[
    int, tuple[weakref.ReferenceType, dict[tuple[Any, Any], frozenset[str]]]
] = {}
_SEGMENT_ROLES_LOCK = threading.RLock()


def _after_fork() -> None:
    global _SEGMENT_ROLES_LOCK
    _SEGMENT_ROLES_LOCK = threading.RLock()
    _SEGMENT_ROLES.clear()
    _BOUNDARY_STACK.set(())


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def optional_import(name: str) -> Any | None:
    """Import an optional integration without making instrumentation fragile."""

    try:
        return importlib.import_module(name)
    except Exception:
        return None


def runtime_module() -> Any | None:
    try:
        return importlib.import_module("beacon_security.runtime")
    except Exception:
        return None


def current_state() -> Any | None:
    runtime = runtime_module()
    if runtime is None:
        return None
    try:
        return runtime.current_state()
    except BaseException:
        return None


def safe_sink(
    rule: str,
    function: str,
    role: str,
    value: Any = None,
    *,
    marks: Iterable[Any] | None = None,
    location: str = "",
) -> None:
    """Report a sink and never interfere with the application call."""

    runtime = runtime_module()
    if runtime is None:
        return
    try:
        # Passing an explicit empty tuple is important: it lets runtime count
        # an untainted invocation without deriving marks from a bind value.
        runtime.sink(
            rule,
            function,
            role,
            value,
            marks=tuple(marks or ()),
            location=location,
        )
    except BaseException:
        return


def safe_gap(reason: str) -> None:
    runtime = runtime_module()
    if runtime is None:
        return
    try:
        runtime.gap(reason)
    except BaseException:
        return


def safe_observe(observer, *args, **kwargs) -> None:
    """Run an instrumentation-only observer without blocking its caller."""

    try:
        observer(*args, **kwargs)
    except BaseException:
        return


def marks_for(value: Any, state: Any | None = None) -> tuple[Any, ...]:
    if value is None:
        return ()
    state = state if state is not None else current_state()
    if state is None:
        return ()
    try:
        marks = state.marks(value)
    except BaseException:
        return ()
    if not marks:
        return ()
    try:
        return tuple(marks)
    except BaseException:
        return ()


def combined_marks(*values: Any, state: Any | None = None) -> tuple[Any, ...]:
    """Collect marks by object identity through ``SecurityState.marks``.

    This is intentionally not a value search: a string is never checked for a
    source string, and bind parameters are never traversed implicitly.
    """

    state = state if state is not None else current_state()
    if state is None:
        return ()
    result: list[Any] = []
    for value in values:
        result.extend(marks_for(value, state))
    return tuple(result)


def safe_propagate(
    result: Any,
    inputs: Iterable[Any],
    operation: str,
    *,
    location: str = "",
    exact: bool = False,
) -> Any:
    """Attach side-table marks while preserving the exact application result."""

    state = current_state()
    if state is None:
        return result
    values = tuple(inputs)
    try:
        state.propagate(
            result, values, operation, location=location, exact=exact
        )
        # Propagation is side-effect-only at this boundary.  Always preserve
        # the exact application result even if an incompatible runtime
        # implementation returns another object.
        return result
    except BaseException:
        try:
            state.put(result, combined_marks(*values, state=state))
        except BaseException:
            pass
        return result


def safe_propagate_carrier(
    result: Any, inputs: Iterable[Any], operation: str
) -> Any:
    """Propagate URL carrier marks through proven component ranges.

    Requests clients can normalize a URL while constructing a carrier.  A
    whole-carrier imprecise mark must not make a query-only source look like a
    destination address, so changed components retain their destination range
    and conservative precision instead of being widened to the whole URL.
    """

    values = tuple(inputs)
    state = current_state()
    if state is None:
        return result
    target_text = url_text(object_url(result))
    if target_text is None:
        return result

    source = next(
        (value for value in values if url_text(object_url(value)) is not None),
        None,
    )
    if source is None:
        return result
    source_carrier = object_url(source)
    source_text = url_text(source_carrier)
    # Prefer marks attached to the normalized URL carrier.  A request object
    # can also carry a conservative construction mark; letting that outer mark
    # override a finite query range would create a false destination finding.
    carrier_marks = marks_for(source_carrier, state)
    outer_marks = (
        marks_for(source, state) if source_carrier is not source else ()
    )
    source_marks = list(carrier_marks)
    if carrier_marks:
        known = {
            (
                getattr(mark, "source_id", None),
                getattr(mark, "node_id", None),
                getattr(mark, "start", None),
                getattr(mark, "end", None),
                getattr(mark, "exact", None),
                getattr(mark, "unit", None),
            )
            for mark in carrier_marks
        }
        # Retain outer marks only when the carrier side table proves they are
        # an additional component (for example Request.params query marks).
        # A broad outer URL mark without such metadata must not override the
        # precise URL-carrier marks.
        for mark in outer_marks:
            key = (
                getattr(mark, "source_id", None),
                getattr(mark, "node_id", None),
                getattr(mark, "start", None),
                getattr(mark, "end", None),
                getattr(mark, "exact", None),
                getattr(mark, "unit", None),
            )
            if key not in known and segment_roles(source, mark):
                source_marks.append(mark)
                known.add(key)
    else:
        source_marks = list(outer_marks)
    if not source_marks:
        return result
    if source_text == target_text:
        try:
            derived: list[Any] = []
            for mark in source_marks:
                item_marks = tuple(
                    state.derive((mark,), operation, exact=True)
                )
                derived.extend(item_marks)
                _remember_mark_roles(
                    result, item_marks, segment_roles(source, mark)
                )
            state.put(result, tuple(derived))
            _remember_segment_roles(
                result, marks_for(result, state), target_text
            )
            return result
        except BaseException:
            return result

    source_ranges = _url_component_ranges(source_text)
    target_ranges = _url_component_ranges(target_text)
    if source_ranges is None or target_ranges is None:
        safe_gap("http.url.normalize")
        mapped: list[Any] = []
        for mark in source_marks:
            try:
                derived = tuple(state.derive((mark,), operation, exact=False))
                mapped.extend(derived)
                roles = segment_roles(source, mark)
                if not roles and source_ranges is not None:
                    roles = _range_roles(mark, source_ranges)
                _remember_mark_roles(result, derived, roles)
            except BaseException:
                pass
        try:
            state.put(result, tuple(mapped))
        except BaseException:
            pass
        return result

    mapped: list[Any] = []
    for mark in source_marks:
        mark_start = getattr(mark, "start", None)
        mark_end = getattr(mark, "end", None)
        if (
            not isinstance(mark_start, int)
            or not isinstance(mark_end, int)
            or mark_end <= mark_start
        ):
            try:
                derived = tuple(state.derive((mark,), operation, exact=False))
                mapped.extend(derived)
                _remember_mark_roles(
                    result, derived, segment_roles(source, mark)
                )
            except BaseException:
                pass
            continue
        mark_mapped = False
        for component in ("authority", "path", "query"):
            source_start, source_end = source_ranges[component]
            target_start, target_end = target_ranges[component]
            left = max(mark_start, source_start)
            right = min(mark_end, source_end)
            if left >= right or target_end <= target_start:
                continue
            source_piece = source_text[source_start:source_end]
            target_piece = target_text[target_start:target_end]
            if source_piece == target_piece:
                try:
                    derived = state.derive(
                        (mark,),
                        operation,
                        shift=target_start - source_start,
                        start=left,
                        end=right,
                        exact=bool(getattr(mark, "exact", False)),
                    )
                    if not bool(getattr(mark, "exact", False)):
                        derived = tuple(
                            replace(
                                item,
                                start=target_start + (left - source_start),
                                end=target_start + (right - source_start),
                                exact=False,
                            )
                            for item in derived
                        )
                    mapped.extend(derived)
                    _remember_segment_roles(
                        result,
                        derived,
                        "address"
                        if component == "authority"
                        else "path_query",
                    )
                except BaseException:
                    pass
            else:
                # The component is still known, but its internal offset is
                # not.  Preserve its target range and conservative precision.
                try:
                    derived = tuple(
                        replace(
                            item,
                            start=target_start,
                            end=target_end,
                            exact=False,
                        )
                        for item in state.derive(
                            (mark,), operation, exact=False
                        )
                    )
                    mapped.extend(derived)
                    _remember_segment_roles(
                        result,
                        derived,
                        "address"
                        if component == "authority"
                        else "path_query",
                    )
                except BaseException:
                    pass
            mark_mapped = True
        if not mark_mapped:
            safe_gap("http.url.normalize")
            try:
                derived = tuple(state.derive((mark,), operation, exact=False))
                mapped.extend(derived)
                _remember_mark_roles(
                    result, derived, segment_roles(source, mark)
                )
            except BaseException:
                pass
    if mapped:
        try:
            state.put(result, tuple(mapped))
        except BaseException:
            pass
    return result


def safe_attach_component_marks(
    result: Any, marks: Iterable[Any], operation: str, component: str
) -> Any:
    """Attach marks from a non-URL carrier to a known URL component."""

    state = current_state()
    marks = tuple(marks)
    if state is None or not marks:
        return result
    text = url_text(object_url(result))
    ranges = _url_component_ranges(text) if text is not None else None
    try:
        if ranges is None or component not in ranges:
            state.gap("http.url.normalize")
            derived = state.derive(marks, operation, exact=False)
            _remember_mark_roles(
                result,
                derived,
                {"address" if component == "authority" else "path_query"},
            )
        else:
            start, end = ranges[component]
            if end <= start:
                state.gap("http.url.normalize")
                derived = state.derive(marks, operation, exact=False)
                _remember_mark_roles(
                    result,
                    derived,
                    {"address" if component == "authority" else "path_query"},
                )
            else:
                derived = tuple(
                    replace(item, start=start, end=end, exact=False)
                    for item in state.derive(marks, operation, exact=False)
                )
            _remember_segment_roles(
                result,
                derived,
                "address" if component == "authority" else "path_query",
            )
        existing = marks_for(result, state)
        state.put(result, existing + tuple(derived))
    except BaseException:
        return result
    return result


def object_url(value: Any) -> Any:
    """Return a URL carrier without coercing application data unnecessarily."""

    if isinstance(value, (str, bytes)):
        return value
    for attribute in ("url", "full_url", "real_url"):
        try:
            candidate = getattr(value, attribute)
        except BaseException:
            continue
        if candidate is not None:
            return candidate
    return value


def _remember_segment_roles(
    carrier: Any, marks: Iterable[Any], role_or_text: str
) -> None:
    """Keep only weak, per-carrier component roles for conservative marks."""

    marks = tuple(marks)
    if not marks:
        return
    if role_or_text in {"address", "path_query"}:
        roles = {role_or_text}
    else:
        ranges = _url_component_ranges(role_or_text)
        if ranges is None:
            return
        roles_by_mark = {}
        for mark in marks:
            current = _range_roles(mark, ranges)
            if current:
                roles_by_mark[
                    (
                        getattr(mark, "source_id", None),
                        getattr(mark, "node_id", None),
                    )
                ] = frozenset(current)
        if not roles_by_mark:
            return
        _store_segment_roles(carrier, roles_by_mark)
        return
    _remember_mark_roles(carrier, marks, roles)


def _range_roles(mark: Any, ranges: dict[str, tuple[int, int]]) -> set[str]:
    start = getattr(mark, "start", None)
    end = getattr(mark, "end", None)
    if not isinstance(start, int) or not isinstance(end, int) or end <= start:
        return set()
    result: set[str] = set()
    for component, (left, right) in ranges.items():
        if end > left and start < right:
            result.add("address" if component == "authority" else "path_query")
    return result


def _remember_mark_roles(
    carrier: Any, marks: Iterable[Any], roles: Iterable[str]
) -> None:
    roles = frozenset(roles)
    if not roles:
        return
    roles_by_mark = {
        (
            getattr(mark, "source_id", None),
            getattr(mark, "node_id", None),
        ): roles
        for mark in marks
    }
    if roles_by_mark:
        _store_segment_roles(carrier, roles_by_mark)


def _store_segment_roles(
    carrier: Any, roles_by_mark: dict[tuple[Any, Any], frozenset[str]]
) -> None:
    try:
        reference = weakref.ref(carrier)
    except TypeError:
        return
    with _SEGMENT_ROLES_LOCK:
        # Keep this side table bounded even if a client creates many short-lived
        # request objects without giving the interpreter a collection cycle.
        if len(_SEGMENT_ROLES) > 2048:
            for key, (candidate, _) in list(_SEGMENT_ROLES.items())[:256]:
                if candidate() is None:
                    _SEGMENT_ROLES.pop(key, None)
        key = id(carrier)
        previous = _SEGMENT_ROLES.get(key)
        if previous is not None and previous[0]() is carrier:
            merged = dict(previous[1])
            merged.update(roles_by_mark)
            _SEGMENT_ROLES[key] = (reference, merged)
        else:
            _SEGMENT_ROLES[key] = (reference, dict(roles_by_mark))


def segment_roles(value: Any, mark: Any) -> frozenset[str]:
    key = (getattr(mark, "source_id", None), getattr(mark, "node_id", None))
    candidates = (value, object_url(value))
    result: set[str] = set()
    with _SEGMENT_ROLES_LOCK:
        for candidate in candidates:
            entry = _SEGMENT_ROLES.get(id(candidate))
            if entry is None:
                continue
            reference, roles = entry
            if reference() is candidate:
                result.update(roles.get(key, ()))
            else:
                _SEGMENT_ROLES.pop(id(candidate), None)
    return frozenset(result)


def url_text(value: Any) -> str | None:
    value = object_url(value)
    if isinstance(value, bytes):
        try:
            return value.decode("ascii", "strict")
        except UnicodeDecodeError:
            return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except BaseException:
        safe_gap("http.url.normalize")
        return None


def _url_marks(
    value: Any, state: Any | None = None
) -> tuple[str | None, tuple[Any, ...]]:
    state = state if state is not None else current_state()
    carrier = object_url(value)
    text = url_text(carrier)
    # A request object may carry a conservative mark from construction while
    # its normalized URL string has a more precise mark.  Prefer the actual
    # URL carrier so a known query-only range does not become an address mark.
    marks = marks_for(carrier, state)
    if not marks and carrier is not value:
        marks = marks_for(value, state)
    return text, marks


def _authority_range(text: str) -> tuple[int, int] | None:
    try:
        parsed = urlsplit(text)
    except ValueError:
        safe_gap("http.url.parse")
        return None
    if not parsed.netloc:
        return None
    scheme_separator = text.find("://")
    if scheme_separator < 0:
        # urlsplit can accept a scheme-relative URL.  Its authority starts at
        # the beginning in that form.
        start = 2 if text.startswith("//") else 0
    else:
        start = scheme_separator + 3
    return start, start + len(parsed.netloc)


def _url_component_ranges(text: str) -> dict[str, tuple[int, int]] | None:
    """Return raw authority/path/query ranges for one parsed URL."""

    authority = _authority_range(text)
    if authority is None:
        return None
    authority_end = authority[1]
    fragment = text.find("#", authority_end)
    end = len(text) if fragment < 0 else fragment
    query = text.find("?", authority_end, end)
    path_end = end if query < 0 else query
    return {
        "authority": authority,
        "path": (authority_end, path_end),
        "query": (query + 1, end) if query >= 0 else (end, end),
    }


def split_url_marks(
    value: Any, state: Any | None = None
) -> tuple[Any, tuple[Any, ...], tuple[Any, ...]]:
    """Return URL text, address marks, and path/query marks.

    Finite ranges are classified by their overlap even when ``exact`` is
    false: conservative precision does not erase a known affected segment.
    Only an absent/unbounded range, or a carrier normalization that lost its
    component offset, is retained for both classes.
    """

    state = state if state is not None else current_state()
    text, marks = _url_marks(value, state)
    if text is None or not marks:
        return text, (), marks
    authority = _authority_range(text)
    if authority is None:
        return text, (), marks
    start, end = authority
    address: list[Any] = []
    path_query: list[Any] = []
    for mark in marks:
        roles = segment_roles(value, mark)
        if "address" in roles:
            address.append(mark)
        if "path_query" in roles:
            path_query.append(mark)
        if roles:
            continue
        mark_start = getattr(mark, "start", None)
        mark_end = getattr(mark, "end", None)
        if (
            not isinstance(mark_start, int)
            or not isinstance(mark_end, int)
            or mark_end <= mark_start
        ):
            address.append(mark)
            path_query.append(mark)
            continue
        if mark_end > start and mark_start < end:
            address.append(mark)
        else:
            path_query.append(mark)
    return text, tuple(address), tuple(path_query)


def extract_arg(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    index: int,
    name: str,
    default: Any = None,
) -> Any:
    if len(args) > index:
        return args[index]
    return kwargs.get(name, default)


@contextlib.contextmanager
def execution_boundary(key: str, *, nested_in: Iterable[str] = ()):
    """Mark a wrapper boundary and indicate whether it is a delegated call.

    We only suppress a known parent/child pair.  Re-entrant calls of the same
    public operation are not suppressed, so unrelated nested application work
    still produces its own sink invocation.
    """

    stack = _BOUNDARY_STACK.get()
    nested = any(parent in stack for parent in nested_in)
    if nested:
        yield False
        return
    token = _BOUNDARY_STACK.set(stack + (key,))
    try:
        yield True
    finally:
        _BOUNDARY_STACK.reset(token)


def is_awaitable(value: Any) -> bool:
    try:
        return inspect.isawaitable(value)
    except BaseException:
        return False


def target_marks(value: Any, state: Any | None = None) -> tuple[Any, ...]:
    """Marks for a path/URL/command carrier, including propagated containers."""

    state = state if state is not None else current_state()
    marks: list[Any] = []
    pending = [(value, 0)]
    seen: set[int] = set()
    while pending:
        item, depth = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        marks.extend(marks_for(item, state))
        if depth >= 2:
            continue
        if type(item) in (list, tuple):
            if len(item) > 128:
                safe_gap("sink_container_limit")
            pending.extend((child, depth + 1) for child in item[:128])
        elif isinstance(item, Mapping):
            try:
                children = []
                for index, child in enumerate(item.values()):
                    if index >= 128:
                        safe_gap("sink_container_limit")
                        break
                    children.append(child)
                pending.extend((child, depth + 1) for child in children)
            except BaseException:
                continue
    return tuple(marks)
