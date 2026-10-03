from __future__ import annotations

import re
import string

_PERCENT = re.compile(
    r"%(?:\(([^)]+)\))?([-+#0 ]*)(\d+)?(?:\.(\d+))?([diouxXeEfFgGcrsa%])"
)
_PRIMITIVES = (str, bytes, int, float, bool, type(None))


def replace_ranges(state, receiver, args, kwargs, result, location):
    if (
        type(receiver) not in (str, bytes)
        or type(result) is not type(receiver)
        or len(args) < 2
    ):
        return None
    old, new = args[:2]
    count = args[2] if len(args) > 2 else kwargs.get("count", -1)
    if (
        type(old) is not type(receiver)
        or type(new) is not type(receiver)
        or type(count) is not int
        or not old
        or len(result) > state.max_bytes
    ):
        return None
    remaining = count if count >= 0 else len(receiver) + 1
    cursor, offset, replacements, marks = 0, 0, 0, []
    receiver_marks, new_marks = state.marks(receiver), state.marks(new)
    while remaining:
        found = receiver.find(old, cursor)
        if found < 0:
            break
        replacements += 1
        if replacements > 128:
            return None
        marks.extend(
            state.derive(
                receiver_marks,
                "replace.keep",
                location,
                start=cursor,
                end=found,
                shift=offset - cursor,
            )
        )
        offset += found - cursor
        marks.extend(
            state.derive(new_marks, "replace.insert", location, shift=offset)
        )
        offset += len(new)
        cursor = found + len(old)
        remaining -= 1
    marks.extend(
        state.derive(
            receiver_marks,
            "replace.keep",
            location,
            start=cursor,
            end=len(receiver),
            shift=offset - cursor,
        )
    )
    return (
        tuple(marks)
        if offset + len(receiver) - cursor == len(result)
        else None
    )


def format_ranges(
    state, receiver, args, kwargs, result, location, *, mapping=False
):
    if (
        type(receiver) is not str
        or type(result) is not str
        or len(result) > state.max_bytes
    ):
        return None
    if state.marks(receiver):
        return None
    if mapping and (len(args) != 1 or type(args[0]) is not dict):
        return None
    offset, automatic, marks = 0, 0, []
    for literal, field, spec, conversion in string.Formatter().parse(receiver):
        offset += len(literal)
        if field is None:
            continue
        if any(char in field for char in ".[{") or "{" in spec or "}" in spec:
            return None
        if not field:
            if mapping:
                return None
            value = args[automatic]
            automatic += 1
        elif field.isdecimal() and not mapping:
            value = args[int(field)]
        else:
            value = (args[0] if mapping else kwargs)[field]
        if type(value) not in _PRIMITIVES:
            return None
        converted = {"s": str, "r": repr, "a": ascii}.get(
            conversion, lambda item: item
        )(value)
        size = len(format(converted, spec))
        source_marks = state.marks(value)
        if source_marks:
            exact = (
                type(value) is str and conversion in (None, "s") and not spec
            )
            derived = state.derive(
                source_marks, "str.format", location, exact=exact
            )
            if exact:
                marks.extend(
                    state.derive(
                        derived, "format.field", location, shift=offset
                    )
                )
            else:
                # The field's interior mapping is conservative, but its extent
                # is known. Keep it out of an unrelated literal URL authority.
                from dataclasses import replace

                marks.extend(
                    replace(mark, start=offset, end=offset + size)
                    for mark in derived
                )
        offset += size
    return tuple(marks) if offset == len(result) else None


def percent_ranges(state, template, values, result, location):
    if (
        type(template) is not str
        or type(result) is not str
        or len(result) > state.max_bytes
        or state.marks(template)
    ):
        return None
    positional = values if type(values) is tuple else (values,)
    index, position, offset, marks = 0, 0, 0, []
    while position < len(template):
        percent = template.find("%", position)
        if percent < 0:
            offset += len(template) - position
            break
        offset += percent - position
        match = _PERCENT.match(template, percent)
        if match is None:
            return None
        key, flags, width, precision, conversion = match.groups()
        position = match.end()
        if conversion == "%":
            offset += 1
            continue
        if key is not None:
            if type(values) is not dict:
                return None
            value = values[key]
        else:
            value = positional[index]
            index += 1
        if type(value) not in _PRIMITIVES:
            return None
        directive = (
            "%"
            + flags
            + (width or "")
            + ("." + precision if precision is not None else "")
            + conversion
        )
        size = len(directive % value)
        source_marks = state.marks(value)
        if source_marks:
            exact = (
                type(value) is str
                and conversion == "s"
                and not width
                and precision is None
            )
            derived = state.derive(
                source_marks, "percent.field", location, exact=exact
            )
            if exact:
                marks.extend(
                    state.derive(
                        derived, "percent.offset", location, shift=offset
                    )
                )
            else:
                from dataclasses import replace

                marks.extend(
                    replace(mark, start=offset, end=offset + size)
                    for mark in derived
                )
        offset += size
    return tuple(marks) if offset == len(result) else None
