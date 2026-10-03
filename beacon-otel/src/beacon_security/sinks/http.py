"""Actual-send hooks for common Python HTTP clients."""

from __future__ import annotations

import contextvars
import os
from typing import Any

from .. import config
from ._common import (
    current_state,
    execution_boundary,
    extract_arg,
    is_awaitable,
    object_url,
    optional_import,
    safe_attach_component_marks,
    safe_observe,
    safe_propagate_carrier,
    safe_sink,
    split_url_marks,
    target_marks,
)

_EXTRA_HTTP_MARKS: contextvars.ContextVar[tuple[Any, ...]] = (
    contextvars.ContextVar("beacon_security_http_request_marks", default=())
)


def _after_fork() -> None:
    _EXTRA_HTTP_MARKS.set(())


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def _current_extra_marks() -> tuple[Any, ...]:
    return _EXTRA_HTTP_MARKS.get()


def _report_http(
    function: str, carrier: Any, extra_marks: tuple[Any, ...] = ()
) -> None:
    state = current_state()
    text, address_marks, url_marks = split_url_marks(carrier, state)
    request_marks = tuple(url_marks) + tuple(extra_marks)
    # A relative, malformed, or otherwise unknown target is conservative for
    # SSRF.  A parsed fixed-host URL keeps exact query/path-only marks out of
    # the address sink.
    from urllib.parse import urlsplit

    try:
        has_authority = bool(text and urlsplit(text).netloc)
    except ValueError:
        has_authority = False
    ssrf_marks = address_marks if has_authority else url_marks
    safe_sink(
        "ssrf",
        function,
        "destination_address" if has_authority else "unknown_target",
        object_url(carrier),
        marks=ssrf_marks,
    )
    # This rule records tainted data reaching an outbound request's path/query
    # carrier.  It is intentionally separate from the SSRF address rule.
    safe_sink(
        "http_request_input",
        function,
        "path_query",
        object_url(carrier),
        marks=request_marks,
    )


def _send_wrapper(function: str, key: str, parent: tuple[str, ...] = ()):
    def wrapper(wrapped, instance, args, kwargs):
        carrier = extract_arg(args, kwargs, 0, "request", None)
        with execution_boundary(key, nested_in=parent) as root:
            if root:
                safe_observe(
                    _report_http, function, carrier, _current_extra_marks()
                )
            return wrapped(*args, **kwargs)

    return wrapper


def _async_send_wrapper(function: str, key: str, parent: tuple[str, ...] = ()):
    async def wrapper(wrapped, instance, args, kwargs):
        carrier = extract_arg(args, kwargs, 0, "request", None)
        with execution_boundary(key, nested_in=parent) as root:
            if root:
                safe_observe(
                    _report_http, function, carrier, _current_extra_marks()
                )
            result = wrapped(*args, **kwargs)
            return await result if is_awaitable(result) else result

    return wrapper


async def _aiohttp_request_wrapper(wrapped, instance, args, kwargs):
    carrier = extract_arg(args, kwargs, 1, "str_or_url", None)
    params = kwargs.get("params")
    with execution_boundary("aiohttp.session._request") as root:
        if root:
            try:
                params_marks = target_marks(params)
            except BaseException:
                params_marks = ()
            safe_observe(
                _report_http,
                "aiohttp.ClientSession._request",
                carrier,
                params_marks,
            )
        result = wrapped(*args, **kwargs)
        return await result if is_awaitable(result) else result


def _request_constructor_wrapper(
    url_index: int, operation: str, params_index: int | None = None
):
    def wrapper(wrapped, instance, args, kwargs):
        url = extract_arg(args, kwargs, url_index, "url", None)
        params = (
            extract_arg(args, kwargs, params_index, "params", None)
            if params_index is not None
            else kwargs.get("params")
        )
        result = wrapped(*args, **kwargs)
        # Request/PreparedRequest objects are carriers only.  No response is
        # propagated here: URL taint does not become response-body taint.
        safe_observe(safe_propagate_carrier, instance, (url,), operation)
        try:
            params_marks = target_marks(params)
        except BaseException:
            params_marks = ()
        safe_observe(
            safe_attach_component_marks,
            instance,
            params_marks,
            operation + ".params",
            "query",
        )
        return result

    return wrapper


def _prepare_request_wrapper(wrapped, instance, args, kwargs):
    request = extract_arg(args, kwargs, 0, "request", None)
    result = wrapped(*args, **kwargs)
    safe_observe(
        safe_propagate_carrier, result, (request,), "requests.prepare_request"
    )
    return result


def _build_request_wrapper(wrapped, instance, args, kwargs):
    url = extract_arg(args, kwargs, 1, "url", None)
    params = kwargs.get("params")
    result = wrapped(*args, **kwargs)
    safe_observe(safe_propagate_carrier, result, (url,), "httpx.build_request")
    try:
        params_marks = target_marks(params)
    except BaseException:
        params_marks = ()
    safe_observe(
        safe_attach_component_marks,
        result,
        params_marks,
        "httpx.build_request.params",
        "query",
    )
    return result


def _request_wrapper(wrapped, instance, args, kwargs):
    params = kwargs.get("params")
    try:
        marks = target_marks(params)
    except BaseException:
        marks = ()
    if not marks:
        return wrapped(*args, **kwargs)
    token = _EXTRA_HTTP_MARKS.set(marks)
    try:
        return wrapped(*args, **kwargs)
    finally:
        _EXTRA_HTTP_MARKS.reset(token)


async def _async_request_wrapper(wrapped, instance, args, kwargs):
    params = kwargs.get("params")
    try:
        marks = target_marks(params)
    except BaseException:
        marks = ()
    if not marks:
        result = wrapped(*args, **kwargs)
        return await result if is_awaitable(result) else result
    token = _EXTRA_HTTP_MARKS.set(marks)
    try:
        result = wrapped(*args, **kwargs)
        return await result if is_awaitable(result) else result
    finally:
        _EXTRA_HTTP_MARKS.reset(token)


def _urlopen_wrapper(wrapped, instance, args, kwargs):
    carrier = extract_arg(args, kwargs, 0, "url", None)
    with execution_boundary("urllib.urlopen", nested_in=()) as root:
        if root:
            safe_observe(_report_http, "urllib.request.urlopen", carrier)
        return wrapped(*args, **kwargs)


def _opener_open_wrapper(wrapped, instance, args, kwargs):
    carrier = extract_arg(args, kwargs, 0, "fullurl", None)
    with execution_boundary(
        "urllib.opener.open", nested_in=("urllib.urlopen",)
    ) as root:
        if root:
            safe_observe(
                _report_http, "urllib.request.OpenerDirector.open", carrier
            )
        return wrapped(*args, **kwargs)


def _patch(patches, seen, target, attribute, wrapper) -> bool:
    key = (id(target), attribute)
    if key in seen:
        return False
    try:
        installed = patches.wrap(target, attribute, wrapper)
    except Exception:
        return False
    if installed:
        seen.add(key)
    return installed


def install(patches, seen) -> set[str]:
    adapters: set[str] = set()

    requests = (
        optional_import("requests")
        if config.dependency_supported("requests", ">=2,<3")
        else None
    )
    if requests is not None:
        sessions = optional_import("requests.sessions")
        session_type = (
            getattr(sessions, "Session", None)
            if sessions is not None
            else None
        )
        if session_type is not None and _patch(
            patches,
            seen,
            session_type,
            "send",
            _send_wrapper("requests.Session.send", "requests.send"),
        ):
            adapters.add("requests")
        if session_type is not None and _patch(
            patches, seen, session_type, "request", _request_wrapper
        ):
            adapters.add("requests")
        if session_type is not None and _patch(
            patches,
            seen,
            session_type,
            "prepare_request",
            _prepare_request_wrapper,
        ):
            adapters.add("requests")
        models = optional_import("requests.models")
        request_type = (
            getattr(models, "Request", None) if models is not None else None
        )
        if request_type is not None and _patch(
            patches,
            seen,
            request_type,
            "__init__",
            _request_constructor_wrapper(1, "requests.Request", 5),
        ):
            adapters.add("requests")

    httpx = (
        optional_import("httpx")
        if config.dependency_supported("httpx", ">=0.28,<0.29")
        else None
    )
    if httpx is not None:
        client_type = getattr(httpx, "Client", None)
        if client_type is not None and _patch(
            patches,
            seen,
            client_type,
            "send",
            _send_wrapper("httpx.Client.send", "httpx.client.send"),
        ):
            adapters.add("httpx")
        if client_type is not None and _patch(
            patches, seen, client_type, "request", _request_wrapper
        ):
            adapters.add("httpx")
        if client_type is not None and _patch(
            patches,
            seen,
            client_type,
            "build_request",
            _build_request_wrapper,
        ):
            adapters.add("httpx")
        async_client_type = getattr(httpx, "AsyncClient", None)
        if async_client_type is not None and _patch(
            patches,
            seen,
            async_client_type,
            "send",
            _async_send_wrapper(
                "httpx.AsyncClient.send", "httpx.async_client.send"
            ),
        ):
            adapters.add("httpx")
        if async_client_type is not None and _patch(
            patches, seen, async_client_type, "request", _async_request_wrapper
        ):
            adapters.add("httpx")
        if async_client_type is not None and _patch(
            patches,
            seen,
            async_client_type,
            "build_request",
            _build_request_wrapper,
        ):
            adapters.add("httpx")
        request_type = getattr(httpx, "Request", None)
        if request_type is not None and _patch(
            patches,
            seen,
            request_type,
            "__init__",
            _request_constructor_wrapper(1, "httpx.Request"),
        ):
            adapters.add("httpx")

    aiohttp = (
        optional_import("aiohttp")
        if config.dependency_supported("aiohttp", ">=3,<4")
        else None
    )
    if aiohttp is not None:
        session_type = getattr(aiohttp, "ClientSession", None)
        if session_type is not None and _patch(
            patches,
            seen,
            session_type,
            "_request",
            _aiohttp_request_wrapper,
        ):
            adapters.add("aiohttp")
        request_type = getattr(aiohttp, "ClientRequest", None)
        if request_type is not None and _patch(
            patches,
            seen,
            request_type,
            "__init__",
            _request_constructor_wrapper(1, "aiohttp.ClientRequest", 2),
        ):
            adapters.add("aiohttp")

    urllib_request = optional_import("urllib.request")
    if urllib_request is not None:
        request_type = getattr(urllib_request, "Request", None)
        if request_type is not None and _patch(
            patches,
            seen,
            request_type,
            "__init__",
            _request_constructor_wrapper(0, "urllib.request.Request"),
        ):
            adapters.add("urllib")
        opener_type = getattr(urllib_request, "OpenerDirector", None)
        if opener_type is not None and _patch(
            patches,
            seen,
            opener_type,
            "open",
            _opener_open_wrapper,
        ):
            adapters.add("urllib")
        if _patch(patches, seen, urllib_request, "urlopen", _urlopen_wrapper):
            adapters.add("urllib")

    return adapters
