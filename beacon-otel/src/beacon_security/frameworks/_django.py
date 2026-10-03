from __future__ import annotations

import importlib
import inspect
from collections.abc import Mapping
from typing import Any

from .. import config
from ..patching import Patches
from ._common import (
    HTTP_BODY,
    HTTP_HEADER,
    HTTP_PARAMETER,
    HTTP_PATH,
    WSGIResult,
    asgi_receive_wrapper,
    asgi_send_wrapper,
    begin,
    capture_mapping,
    capture_sequence,
    carrier_spec,
    current_state,
    detach,
    finish,
    is_http_state,
    register_carrier,
    source,
    wrap_descriptor,
)


def _optional(name: str) -> Any | None:
    try:
        return importlib.import_module(name)
    except (ImportError, ModuleNotFoundError, AttributeError):
        return None


def _patch(
    patches: Patches,
    seen: set[tuple[int, str]],
    target: Any,
    attribute: str,
    wrapper: Any,
) -> bool:
    key = (id(target), attribute)
    if key in seen:
        return False
    try:
        installed = patches.wrap(target, attribute, wrapper)
    except (ImportError, ModuleNotFoundError, AttributeError, TypeError):
        return False
    if installed:
        seen.add(key)
    return installed


def _patch_descriptor(
    patches: Patches,
    seen: set[tuple[int, str]],
    target: Any,
    attribute: str,
    callback: Any,
) -> bool:
    key = (id(target), attribute)
    if key in seen:
        return False
    try:
        installed = wrap_descriptor(patches, target, attribute, callback)
    except (AttributeError, TypeError):
        return False
    if installed:
        seen.add(key)
    return installed


def _carrier_name(prefix: str, key: Any) -> str:
    try:
        key_text = str(key)[:128]
    except Exception:
        key_text = "value"
    if prefix == "header":
        key_text = key_text.lower()
    return f"{prefix}.{key_text}" if prefix else key_text


def _carrier_method_wrapper(method: str, location: str):
    def wrapper(
        wrapped: Any,
        instance: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        result = wrapped(*args, **kwargs)
        state = current_state()
        spec = carrier_spec(instance, state)
        if spec is None or method not in {"__getitem__", "get", "getlist"}:
            return result
        key = args[0] if args else kwargs.get("key")
        if key is None:
            return result
        if method != "__getitem__":
            try:
                if key not in instance:
                    return result
            except Exception:
                return result
        field_name = _carrier_name(spec[1], key)
        if method == "getlist" and type(result) in (list, tuple):
            for item in result:
                source(item, spec[0], field_name, location)
        else:
            source(result, spec[0], field_name, location)
        return result

    return wrapper


def _patch_carrier_methods(
    patches: Patches,
    seen: set[tuple[int, str]],
    target: Any,
    methods: tuple[str, ...],
    location: str,
) -> None:
    for method in methods:
        _patch(
            patches,
            seen,
            target,
            method,
            _carrier_method_wrapper(method, location),
        )


def _request_carrier(value: Any, instance: Any, kind: str, name: str) -> Any:
    state = current_state()
    if state is not None and is_http_state(state):
        # The request attribute/property has completed its own parsing before
        # this callback runs.  Capture the bounded carrier now so later
        # items()/values() iteration is covered without changing its iterator
        # semantics or reading the body a second time.
        capture_mapping(value, kind, f"django.http.HttpRequest.{name}", name)
        register_carrier(state, value, kind, name)
    return value


def _request_attribute_wrapper(
    wrapped: Any,
    instance: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Any:
    result = wrapped(*args, **kwargs)
    attribute = args[0] if args else kwargs.get("name")
    if attribute == "GET":
        return _request_carrier(result, instance, HTTP_PARAMETER, "query")
    if attribute in {"POST", "FILES"}:
        return _request_carrier(result, instance, HTTP_BODY, "body")
    return result


def _request_init_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    # GET/POST/FILES are intentionally observed by __getattribute__ below,
    # after framework/application access, rather than eagerly at construction.
    return wrapped(*args, **kwargs)


def _load_post_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    state = current_state()
    if state is not None and is_http_state(state):
        for attribute in ("POST", "FILES"):
            try:
                _request_carrier(
                    getattr(instance, attribute), instance, HTTP_BODY, "body"
                )
            except Exception:
                pass
    return result


def _body_read_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    if inspect.isawaitable(result):

        async def awaited() -> Any:
            value = await result
            source(value, HTTP_BODY, "body", "django.http.HttpRequest.body")
            return value

        return awaited()
    source(result, HTTP_BODY, "body", "django.http.HttpRequest.read")
    return result


def _resolve_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    state = current_state()
    if state is None or not is_http_state(state):
        return result
    try:
        location = "django.core.handlers.base.BaseHandler.resolve_request"
        if isinstance(result, tuple) and len(result) >= 3:
            capture_sequence(result[1], HTTP_PATH, location, "path")
            capture_mapping(result[2], HTTP_PATH, location, "path")
        else:
            # Django 5.2 returns ResolverMatch directly; older supported
            # handler shapes returned (callback, args, kwargs).
            capture_sequence(
                getattr(result, "args", ()), HTTP_PATH, location, "path"
            )
            capture_mapping(
                getattr(result, "kwargs", {}), HTTP_PATH, location, "path"
            )
    except Exception:
        pass
    return result


def _start_response_wrapper(start_response: Any, session: Any) -> Any:
    def wrapped(status: Any, headers: Any, exc_info: Any = None) -> Any:
        state = current_state()
        if state is not None and state is session.state:
            try:
                state.request["status_code"] = int(
                    str(status).split(" ", 1)[0]
                )
            except Exception:
                pass
        if exc_info is None:
            return start_response(status, headers)
        return start_response(status, headers, exc_info)

    return wrapped


def _wsgi_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    if current_state() is not None:
        return wrapped(*args, **kwargs)
    environ = args[0] if args else kwargs.get("environ")
    method = (
        str(environ.get("REQUEST_METHOD", ""))[:16]
        if isinstance(environ, Mapping)
        else ""
    )
    session = begin(
        {"framework": "django", "transport": "wsgi", "method": method}
    )
    if session is None:
        return wrapped(*args, **kwargs)

    call_args = list(args)
    call_kwargs = dict(kwargs)
    start_response = args[1] if len(args) > 1 else kwargs.get("start_response")
    if start_response is not None:
        callback = _start_response_wrapper(start_response, session)
        if len(call_args) > 1:
            call_args[1] = callback
        else:
            call_kwargs["start_response"] = callback
    try:
        result = wrapped(*call_args, **call_kwargs)
    except BaseException as error:
        finish(session, error)
        raise
    finally:
        detach(session)
    if result is None:
        finish(session, None)
        return result
    try:
        return WSGIResult(result, session)
    except Exception:
        finish(session, None)
        return result


def _asgi_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    scope = args[0] if args else kwargs.get("scope")
    if not isinstance(scope, Mapping) or scope.get("type") != "http":
        return wrapped(*args, **kwargs)
    if current_state() is not None:
        return wrapped(*args, **kwargs)

    async def awaited_call() -> Any:
        # Start/attach only once the ASGI coroutine is actually awaited.  The
        # server is allowed to create the coroutine in a different task from
        # the one that awaits it.
        session = begin(
            {
                "framework": "django",
                "transport": "asgi",
                "method": str(scope.get("method", ""))[:16],
            }
        )
        if session is None:
            result = wrapped(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result
        if not session.owner:
            result = wrapped(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result

        receive = args[1] if len(args) > 1 else kwargs.get("receive")
        send = args[2] if len(args) > 2 else kwargs.get("send")
        call_args = list(args)
        call_kwargs = dict(kwargs)
        if receive is not None:
            callback = asgi_receive_wrapper(receive, session)
            if len(call_args) > 1:
                call_args[1] = callback
            else:
                call_kwargs["receive"] = callback
        if send is not None:
            callback = asgi_send_wrapper(send, session)
            if len(call_args) > 2:
                call_args[2] = callback
            else:
                call_kwargs["send"] = callback
        try:
            result = wrapped(*call_args, **call_kwargs)
            value = await result if inspect.isawaitable(result) else result
        except BaseException as error:
            finish(session, error)
            raise
        else:
            if not session.finished:
                finish(session, None)
            return value
        finally:
            if session.finished:
                detach(session)

    return awaited_call()


def install(patches: Patches, seen: set[tuple[int, str]]) -> set[str]:
    if not config.dependency_supported("Django", ">=5.2,<5.3"):
        return set()
    django = _optional("django")
    if django is None:
        return set()
    wsgi = _optional("django.core.handlers.wsgi")
    asgi = _optional("django.core.handlers.asgi")
    base = _optional("django.core.handlers.base")
    request_module = _optional("django.http.request")
    if wsgi is None and asgi is None:
        return set()

    adapters = {"django"}
    if wsgi is not None:
        handler = getattr(wsgi, "WSGIHandler", None)
        if handler is not None:
            _patch(patches, seen, handler, "__call__", _wsgi_wrapper)
        request = getattr(wsgi, "WSGIRequest", None)
        if request is not None:
            _patch(patches, seen, request, "__init__", _request_init_wrapper)
    if asgi is not None:
        handler = getattr(asgi, "ASGIHandler", None)
        if handler is not None:
            _patch(patches, seen, handler, "__call__", _asgi_wrapper)
        request = getattr(asgi, "ASGIRequest", None)
        if request is not None:
            _patch(patches, seen, request, "__init__", _request_init_wrapper)

    if base is not None:
        handler = getattr(base, "BaseHandler", None)
        if handler is not None:
            _patch(patches, seen, handler, "resolve_request", _resolve_wrapper)
            _patch(
                patches,
                seen,
                handler,
                "_load_post_and_files",
                _load_post_wrapper,
            )

    if request_module is not None:
        request = getattr(request_module, "HttpRequest", None)
        if request is not None:
            _patch(
                patches,
                seen,
                request,
                "__getattribute__",
                _request_attribute_wrapper,
            )
            _patch(
                patches,
                seen,
                request,
                "_load_post_and_files",
                _load_post_wrapper,
            )
            _patch_descriptor(
                patches,
                seen,
                request,
                "body",
                lambda value, instance: (
                    source(
                        value,
                        HTTP_BODY,
                        "body",
                        "django.http.HttpRequest.body",
                    ),
                    value,
                )[1],
            )
            _patch_descriptor(
                patches,
                seen,
                request,
                "headers",
                lambda value, instance: _request_carrier(
                    value, instance, HTTP_HEADER, "header"
                ),
            )
            for method in ("read", "readline", "readlines"):
                _patch(patches, seen, request, method, _body_read_wrapper)

        multidict = getattr(request_module, "MultiValueDict", None)
        if multidict is None:
            datastructures = _optional("django.utils.datastructures")
            multidict = (
                getattr(datastructures, "MultiValueDict", None)
                if datastructures is not None
                else None
            )
        if multidict is not None:
            _patch_carrier_methods(
                patches,
                seen,
                multidict,
                ("__getitem__", "get", "getlist"),
                "django.utils.datastructures.MultiValueDict",
            )
        headers = getattr(request_module, "HttpHeaders", None)
        if headers is not None:
            _patch_carrier_methods(
                patches,
                seen,
                headers,
                ("__getitem__", "get", "getlist"),
                "django.http.request.HttpHeaders",
            )
    return adapters
