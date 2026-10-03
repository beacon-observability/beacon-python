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
    begin,
    capture_mapping,
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
        if spec[0] == "__combined__":
            # Werkzeug's CombinedMultiDict delegates to its child mappings;
            # their registered wrappers observe the actual read.  Do not read
            # a child again here just to infer the source.
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
        if kind != "__combined__":
            # Flask/Werkzeug has already parsed these request properties when
            # the property is accessed.  Recording bounded contents here
            # covers items()/values() consumers without rereading a body.
            capture_mapping(value, kind, f"flask.Request.{name}", name)
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
    # Request.headers is initialized as an instance attribute by Werkzeug's
    # Request constructor, so it is not a class descriptor that can be
    # wrapped reliably on Flask.Request.  Observe the completed lookup.
    if attribute == "headers":
        return _request_carrier(result, instance, HTTP_HEADER, "header")
    return result


def _body_result(result: Any, location: str) -> Any:
    if inspect.isawaitable(result):

        async def awaited() -> Any:
            value = await result
            source(value, HTTP_BODY, "body", location)
            return value

        return awaited()
    source(result, HTTP_BODY, "body", location)
    return result


def _get_data_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    return _body_result(wrapped(*args, **kwargs), "flask.Request.get_data")


def _get_json_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    return _body_result(wrapped(*args, **kwargs), "flask.Request.get_json")


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


def _entry_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    if current_state() is not None:
        return wrapped(*args, **kwargs)
    environ = args[0] if args else kwargs.get("environ")
    method = ""
    if isinstance(environ, Mapping):
        method = str(environ.get("REQUEST_METHOD", ""))[:16]
    session = begin(
        {"framework": "flask", "transport": "wsgi", "method": method}
    )
    if session is None:
        return wrapped(*args, **kwargs)

    call_args = list(args)
    call_kwargs = dict(kwargs)
    start_response = args[1] if len(args) > 1 else kwargs.get("start_response")
    if start_response is not None:
        wrapped_start_response = _start_response_wrapper(
            start_response, session
        )
        if len(call_args) > 1:
            call_args[1] = wrapped_start_response
        else:
            call_kwargs["start_response"] = wrapped_start_response
    try:
        result = wrapped(*call_args, **call_kwargs)
    except BaseException as error:
        finish(session, error)
        raise
    finally:
        # The Flask request context is popped before the returned WSGI iterable
        # is consumed.  State is therefore detached now and reattached by
        # WSGIResult for each iterator operation.
        detach(session)
    if result is None:
        finish(session, None)
        return result
    try:
        return WSGIResult(result, session)
    except Exception:
        finish(session, None)
        return result


def _dispatch_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    state = current_state()
    if state is not None and is_http_state(state):
        try:
            from flask import request

            view_args = request.view_args
            if isinstance(view_args, Mapping):
                capture_mapping(
                    view_args,
                    HTTP_PATH,
                    "flask.Flask.dispatch_request",
                    "path",
                )
        except Exception:
            pass
    return wrapped(*args, **kwargs)


def install(patches: Patches, seen: set[tuple[int, str]]) -> set[str]:
    if not config.dependency_supported("Flask", ">=3.1,<3.2"):
        return set()
    flask = _optional("flask")
    if flask is None:
        return set()
    app_class = getattr(flask, "Flask", None)
    request_class = getattr(flask, "Request", None)
    if app_class is None or request_class is None:
        return set()

    adapters = {"flask"}
    _patch(patches, seen, app_class, "__call__", _entry_wrapper)
    _patch(patches, seen, app_class, "wsgi_app", _entry_wrapper)
    _patch(patches, seen, app_class, "dispatch_request", _dispatch_wrapper)
    _patch(
        patches,
        seen,
        request_class,
        "__getattribute__",
        _request_attribute_wrapper,
    )

    _patch_descriptor(
        patches,
        seen,
        request_class,
        "args",
        lambda value, instance: _request_carrier(
            value, instance, HTTP_PARAMETER, "query"
        ),
    )
    _patch_descriptor(
        patches,
        seen,
        request_class,
        "form",
        lambda value, instance: _request_carrier(
            value, instance, HTTP_BODY, "body"
        ),
    )
    _patch_descriptor(
        patches,
        seen,
        request_class,
        "files",
        lambda value, instance: _request_carrier(
            value, instance, HTTP_BODY, "body"
        ),
    )
    _patch_descriptor(
        patches,
        seen,
        request_class,
        "values",
        lambda value, instance: _request_carrier(
            value, instance, "__combined__", "parameter"
        ),
    )
    _patch_descriptor(
        patches,
        seen,
        request_class,
        "headers",
        lambda value, instance: _request_carrier(
            value, instance, HTTP_HEADER, "header"
        ),
    )
    _patch(patches, seen, request_class, "get_data", _get_data_wrapper)
    _patch(patches, seen, request_class, "get_json", _get_json_wrapper)

    datastructures = _optional("werkzeug.datastructures")
    if datastructures is not None:
        multidict = getattr(datastructures, "MultiDict", None)
        if multidict is not None:
            _patch_carrier_methods(
                patches,
                seen,
                multidict,
                ("__getitem__", "get", "getlist"),
                "werkzeug.datastructures.MultiDict",
            )
        combined = getattr(datastructures, "CombinedMultiDict", None)
        if combined is not None:
            _patch_carrier_methods(
                patches,
                seen,
                combined,
                ("__getitem__", "get", "getlist"),
                "werkzeug.datastructures.CombinedMultiDict",
            )
        headers = getattr(datastructures, "Headers", None)
        if headers is not None:
            _patch_carrier_methods(
                patches,
                seen,
                headers,
                ("__getitem__", "get", "getlist"),
                "werkzeug.datastructures.Headers",
            )
        environ_headers = getattr(datastructures, "EnvironHeaders", None)
        if environ_headers is not None:
            # Only direct methods are wrapped here; inherited methods already
            # pass through Headers and must not be wrapped twice.
            for method in ("__getitem__", "get", "getlist"):
                if method in vars(environ_headers):
                    _patch(
                        patches,
                        seen,
                        environ_headers,
                        method,
                        _carrier_method_wrapper(
                            method, "werkzeug.datastructures.EnvironHeaders"
                        ),
                    )
    return adapters
