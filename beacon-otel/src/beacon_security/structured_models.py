from __future__ import annotations

import urllib.parse
from pathlib import PurePath

URL_PARTS = (
    urllib.parse.SplitResult,
    urllib.parse.ParseResult,
    urllib.parse.SplitResultBytes,
    urllib.parse.ParseResultBytes,
)
PATH_TRANSFORMS = {
    "join",
    "normpath",
    "normcase",
    "abspath",
    "relpath",
    "realpath",
    "expanduser",
    "expandvars",
    "basename",
    "dirname",
    "split",
    "splitext",
    "splitdrive",
    "commonpath",
    "commonprefix",
}
PATH_METHODS = {
    "joinpath",
    "with_name",
    "with_stem",
    "with_suffix",
    "relative_to",
    "absolute",
    "resolve",
    "expanduser",
    "as_posix",
    "as_uri",
    "__fspath__",
}
URL_TRANSFORMS = {
    "quote",
    "quote_plus",
    "quote_from_bytes",
    "unquote",
    "unquote_plus",
    "unquote_to_bytes",
    "urlencode",
    "urljoin",
    "urlsplit",
    "urlparse",
    "urlunsplit",
    "urlunparse",
}


def url_parts(state, value):
    actual = type(value)
    if any(actual is kind for kind in URL_PARTS):
        return value
    if issubclass(actual, URL_PARTS):
        # Subclasses may override iteration, indexing and derived properties.
        state.gap("unmodeled_url_parts_subclass")
    return None


def compose_parts(state, parts, result, location):
    if not (
        type(parts) in (tuple, list) or url_parts(state, parts) is not None
    ) or len(parts) not in (5, 6):
        return False
    if type(result) not in (str, bytes) or any(
        type(part) is not type(result) for part in parts
    ):
        return False
    if len(result) > state.max_bytes:
        state.gap("url_compose_mapping_budget")
        return False
    literal = (
        (lambda text: text.encode("ascii"))
        if type(result) is bytes
        else (lambda text: text)
    )
    scheme, netloc, path = parts[:3]
    scheme_name = scheme.decode("ascii") if type(scheme) is bytes else scheme
    pieces = [path]
    if len(parts) == 6 and parts[3]:
        pieces.extend((literal(";"), parts[3]))
    if (
        netloc
        or scheme
        and scheme_name in urllib.parse.uses_netloc
        and not path.startswith(literal("//"))
    ):
        if path and not path.startswith(literal("/")):
            pieces.insert(0, literal("/"))
        pieces[:0] = [literal("//"), netloc]
    if scheme:
        pieces[:0] = [scheme, literal(":")]
    if parts[-2]:
        pieces.extend((literal("?"), parts[-2]))
    if parts[-1]:
        pieces.extend((literal("#"), parts[-1]))
    # Equality validates the modeled layout only; source identity was already
    # established on the specific component objects, never by content search.
    if literal("").join(pieces) != result:
        state.gap("url_compose_layout_unknown")
        return False
    marks, offset = [], 0
    for piece in pieces:
        marks.extend(
            state.derive(
                state.marks(piece), "url.compose", location, shift=offset
            )
        )
        offset += len(piece)
    if marks:
        state.put(result, marks)
    return True


def parse_parts(state, original, result, location):
    if type(original) not in (str, bytes) or url_parts(state, result) is None:
        return False
    marks = state.marks(original)
    if not marks:
        return True
    if type(original) is bytes:
        try:
            text = original.decode("ascii")
        except UnicodeDecodeError:
            state.gap("url_parse_offset_unavailable")
            return True
    else:
        text = original
    if (
        text[:1]
        and ord(text[0]) <= 32
        or any(char in text for char in "\t\r\n")
    ):
        state.gap("url_parse_offset_unavailable")
        return True
    scheme, netloc, path = result[:3]
    cursor = len(scheme) + 1 if scheme else 0
    if scheme:
        state.put(
            scheme,
            state.derive(
                marks, "url.scheme", location, start=0, end=len(scheme)
            ),
        )
    if text[cursor : cursor + 2] == "//":
        cursor += 2
        state.put(
            netloc,
            state.derive(
                marks,
                "url.authority",
                location,
                start=cursor,
                end=cursor + len(netloc),
                shift=-cursor,
            ),
        )
        cursor += len(netloc)
    state.put(
        path,
        state.derive(
            marks,
            "url.path",
            location,
            start=cursor,
            end=cursor + len(path),
            shift=-cursor,
        ),
    )
    cursor += len(path)
    if len(result) == 6:
        params = result.params
        if params or text[cursor : cursor + 1] == ";":
            cursor += 1
            state.put(
                params,
                state.derive(
                    marks,
                    "url.params",
                    location,
                    start=cursor,
                    end=cursor + len(params),
                    shift=-cursor,
                ),
            )
            cursor += len(params)
    query, fragment = result[-2:]
    if text[cursor : cursor + 1] == "?":
        cursor += 1
        state.put(
            query,
            state.derive(
                marks,
                "url.query",
                location,
                start=cursor,
                end=cursor + len(query),
                shift=-cursor,
            ),
        )
        cursor += len(query)
    if text[cursor : cursor + 1] == "#":
        cursor += 1
        state.put(
            fragment,
            state.derive(
                marks,
                "url.fragment",
                location,
                start=cursor,
                end=cursor + len(fragment),
                shift=-cursor,
            ),
        )
    return True


def attribute(state, receiver, name, result, location):
    if url_parts(state, receiver) is not None and name in {
        "hostname",
        "username",
        "password",
        "port",
    }:
        # These are derived solely from the authority, never from a query.
        marks = state.marks(receiver.netloc)
        if marks and type(result) in (str, bytes):
            state.put(
                result,
                state.derive(marks, "url." + name, location, exact=False),
            )
    elif issubclass(type(receiver), PurePath):
        if name in {
            "name",
            "stem",
            "suffix",
            "parent",
            "drive",
            "root",
            "anchor",
            "parts",
            "suffixes",
        }:
            marks = state.marks(receiver)
            if marks:
                derived = state.derive(
                    marks, "path." + name, location, exact=False
                )
                if type(result) in (tuple, list):
                    for item in result[:128]:
                        state.put(item, derived)
                else:
                    state.put(result, derived)
