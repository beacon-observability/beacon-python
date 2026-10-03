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
    _capture_bound,
    _field_name,
    asgi_receive_wrapper,
    asgi_send_wrapper,
    asgi_session,
    attach,
    begin,
    bind_asgi_session,
    capture_bound_values,
    capture_mapping,
    carrier_spec,
    clear_asgi_session,
    current_state,
    detach,
    detach_token,
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


def _carrier_name(prefix: str, key: Any) -> str:
    try:
        key_text = str(key)[:128]
    except Exception:
        key_text = "value"
    if prefix == "header":
        key_text = key_text.lower()
    return f"{prefix}.{key_text}" if prefix else key_text


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


def _capture_request_carrier(
    value: Any, instance: Any, kind: str, name: str
) -> Any:
    state = current_state()
    if state is not None and is_http_state(state):
        # Query/header carriers are already parsed when their request
        # properties are read.  Capture their bounded contents here so an
        # application that consumes ``items()``/``values()`` still gets the
        # same field identities without requiring an iterator proxy.  Form
        # data is handled after Starlette's actual parser completes below.
        capture_mapping(
            value, kind, f"starlette.requests.Request.{name}", name
        )
        register_carrier(state, value, kind, name)
    return value


def _capture_async_result(result: Any, callback: Any) -> Any:
    if inspect.isawaitable(result):

        async def awaited() -> Any:
            value = await result
            callback(value)
            return value

        return awaited()
    callback(result)
    return result


def _request_init_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    state = current_state()
    if state is not None and is_http_state(state):
        try:
            scope = getattr(instance, "scope", None)
            if (
                isinstance(scope, Mapping)
                and scope.get("type", "http") == "http"
            ):
                path_params = getattr(instance, "path_params", {})
                # Starlette exposes path_params as a plain mutable dict.  It
                # is snapshotted at binding time instead of being retained in
                # the per-request carrier registry.
                capture_mapping(
                    path_params,
                    HTTP_PATH,
                    "starlette.requests.Request.path_params",
                    "path",
                )
        except Exception:
            pass
    return result


def _body_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    return _capture_async_result(
        result,
        lambda value: source(
            value, HTTP_BODY, "body", "starlette.requests.Request.body"
        ),
    )


def _json_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    return _capture_async_result(
        result,
        lambda value: source(
            value, HTTP_BODY, "body", "starlette.requests.Request.json"
        ),
    )


def _form_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)

    def register(value: Any) -> None:
        state = current_state()
        if state is not None and is_http_state(state):
            # _get_form has already consumed and parsed the body at this
            # point; do not trigger any additional body read here.
            capture_mapping(
                value, HTTP_BODY, "starlette.requests.Request.form", "body"
            )
            register_carrier(state, value, HTTP_BODY, "body")

    return _capture_async_result(result, register)


def _stream_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    if not hasattr(result, "__aiter__"):
        return result

    async def stream():
        async for chunk in result:
            source(
                chunk, HTTP_BODY, "body", "starlette.requests.Request.stream"
            )
            yield chunk

    return stream()


def _params_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    if not isinstance(result, tuple) or not result:
        return result
    received = args[1] if len(args) > 1 else kwargs.get("received_params")
    state = current_state()
    spec = carrier_spec(received, state)
    if spec is not None:
        try:
            fields = (
                args[0]
                if args
                else kwargs.get("fields", kwargs.get("required_params"))
            )
            _capture_validated_fields(
                fields,
                result[0],
                spec[0],
                "fastapi.dependencies.utils.request_params_to_args",
                spec[1],
                sequence_index=False,
                flatten_single_model=True,
            )
        except Exception:
            pass
    return result


def _body_params_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    result = wrapped(*args, **kwargs)
    if inspect.isawaitable(result):

        async def awaited() -> Any:
            value = await result
            _capture_body_params_result(value, args, kwargs)
            return value

        return awaited()
    _capture_body_params_result(result, args, kwargs)
    return result


def _capture_body_params_result(
    result: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    if not isinstance(result, tuple) or not result:
        return
    state = current_state()
    if state is not None and is_http_state(state):
        try:
            received_body = (
                args[1] if len(args) > 1 else kwargs.get("received_body")
            )
            embed_body_fields = (
                args[2]
                if len(args) > 2
                else kwargs.get("embed_body_fields", False)
            )
            fields = (
                args[0]
                if args
                else kwargs.get("body_fields", kwargs.get("required_params"))
            )
            _capture_validated_fields(
                fields,
                result[0],
                HTTP_BODY,
                "fastapi.dependencies.utils.request_body_to_args",
                "body",
                sequence_index=type(received_body).__name__ != "FormData",
                flatten_single_model=not bool(embed_body_fields),
            )
        except Exception:
            pass


def _capture_validated_fields(
    fields: Any,
    values: Any,
    kind: str,
    location: str,
    prefix: str,
    *,
    sequence_index: bool = True,
    flatten_single_model: bool = False,
) -> None:
    """Use the raw parameter alias as the stable source field identity."""

    if not isinstance(values, Mapping) or not fields:
        capture_bound_values(
            values,
            kind,
            location,
            prefix,
            sequence_index=sequence_index,
        )
        return
    try:
        field_list = list(fields)
    except Exception:
        capture_bound_values(
            values,
            kind,
            location,
            prefix,
            sequence_index=sequence_index,
        )
        return
    matched = False
    if flatten_single_model and len(field_list) == 1:
        field = field_list[0]
        field_name = getattr(field, "name", None)
        alias = getattr(field, "alias", None) or field_name
        key = field_name if field_name in values else alias
        if key in values:
            try:
                value = values[key]
            except Exception:
                value = None
            if isinstance(getattr(value, "model_fields", None), Mapping):
                _capture_bound(
                    value,
                    kind,
                    location,
                    prefix,
                    sequence_index=sequence_index,
                )
                return
    for field in field_list[:256]:
        field_name = getattr(field, "name", None)
        alias = getattr(field, "alias", None) or field_name
        key = field_name if field_name in values else alias
        if key not in values:
            continue
        try:
            value = values[key]
        except Exception:
            continue
        matched = True
        _capture_bound(
            value,
            kind,
            location,
            _field_name(prefix, alias),
            sequence_index=sequence_index,
        )
    if not matched:
        capture_bound_values(
            values,
            kind,
            location,
            prefix,
            sequence_index=sequence_index,
        )


def _asgi_call_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    scope = args[0] if args else kwargs.get("scope")
    if not isinstance(scope, Mapping) or scope.get("type") != "http":
        return wrapped(*args, **kwargs)
    if current_state() is not None:
        return wrapped(*args, **kwargs)

    async def awaited_call() -> Any:
        # Do not attach while merely constructing the application coroutine.
        # ASGI servers may construct it in one task and await it in another;
        # context tokens must be detached by the context that attached them.
        session = begin(
            {
                "framework": "starlette",
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

        bind_asgi_session(scope, session)

        receive = args[1] if len(args) > 1 else kwargs.get("receive")
        send = args[2] if len(args) > 2 else kwargs.get("send")
        call_args = list(args)
        call_kwargs = dict(kwargs)
        if receive is not None:
            receive = asgi_receive_wrapper(receive, session)
            if len(call_args) > 1:
                call_args[1] = receive
            else:
                call_kwargs["receive"] = receive
        if send is not None:
            send = asgi_send_wrapper(send, session)
            if len(call_args) > 2:
                call_args[2] = send
            else:
                call_kwargs["send"] = send

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
            # A terminal send can close the shared state in a child task.  The
            # attach token still belongs to this outer task.
            if session.finished:
                detach(session)
            clear_asgi_session(scope, session)

    return awaited_call()


def install(patches: Patches, seen: set[tuple[int, str]]) -> set[str]:
    # Keep the supported framework family explicit.  The metadata probe does
    # not import the framework, so an unsupported installation cannot execute
    # module import side effects before the adapter is declined.
    starlette_supported = config.dependency_supported(
        "starlette", ">=1.6,<1.7"
    )
    fastapi_supported = (
        config.dependency_supported("fastapi", ">=0.141,<0.142")
        and config.dependency_supported("pydantic", ">=2,<3")
        and starlette_supported
    )
    if not starlette_supported:
        return set()
    starlette_applications = _optional("starlette.applications")
    starlette_requests = _optional("starlette.requests")
    starlette_datastructures = _optional("starlette.datastructures")
    starlette_routing = _optional("starlette.routing")
    if starlette_applications is None:
        return set()

    adapters: set[str] = set()
    starlette = getattr(starlette_applications, "Starlette", None)
    starlette_key = (
        (id(starlette), "__call__") if starlette is not None else None
    )
    starlette_patched = bool(
        starlette is not None
        and (
            starlette_key in seen
            or _patch(patches, seen, starlette, "__call__", _asgi_call_wrapper)
        )
    )

    if starlette_requests is not None:
        request = getattr(starlette_requests, "Request", None)
        if request is not None:
            _patch(patches, seen, request, "__init__", _request_init_wrapper)
            _patch_descriptor(
                patches,
                seen,
                request,
                "query_params",
                lambda value, instance: _capture_request_carrier(
                    value, instance, HTTP_PARAMETER, "query"
                ),
            )
            _patch_descriptor(
                patches,
                seen,
                request,
                "headers",
                lambda value, instance: _capture_request_carrier(
                    value, instance, HTTP_HEADER, "header"
                ),
            )
            _patch_descriptor(
                patches,
                seen,
                request,
                "path_params",
                lambda value, instance: _capture_path_carrier(value, instance),
            )
            _patch(patches, seen, request, "body", _body_wrapper)
            _patch(patches, seen, request, "json", _json_wrapper)
            _patch(patches, seen, request, "stream", _stream_wrapper)
            _patch(patches, seen, request, "_get_form", _form_wrapper)

    if starlette_datastructures is not None:
        immutable = getattr(
            starlette_datastructures, "ImmutableMultiDict", None
        )
        if immutable is not None:
            _patch_carrier_methods(
                patches,
                seen,
                immutable,
                ("__getitem__", "get", "getlist"),
                "starlette.datastructures.ImmutableMultiDict",
            )
        headers = getattr(starlette_datastructures, "Headers", None)
        if headers is not None:
            _patch_carrier_methods(
                patches,
                seen,
                headers,
                ("__getitem__", "get", "getlist"),
                "starlette.datastructures.Headers",
            )

    if starlette_routing is not None:
        router = getattr(starlette_routing, "Router", None)
        if router is not None:
            _patch(patches, seen, router, "__call__", _router_call_wrapper)

    fastapi = _optional("fastapi") if fastapi_supported else None
    if fastapi is not None:
        adapters.add("fastapi")
        dependencies = _optional("fastapi.dependencies.utils")
        routing = _optional("fastapi.routing")
        if dependencies is not None:
            _patch(
                patches,
                seen,
                dependencies,
                "request_params_to_args",
                _params_wrapper,
            )
            _patch(
                patches,
                seen,
                dependencies,
                "request_body_to_args",
                _body_params_wrapper,
            )
        if routing is not None:
            _patch(
                patches,
                seen,
                routing,
                "request_params_to_args",
                _params_wrapper,
            )
            _patch(
                patches,
                seen,
                routing,
                "request_body_to_args",
                _body_params_wrapper,
            )
    elif starlette_patched:
        adapters.add("starlette")
    return adapters


def _router_call_wrapper(
    wrapped: Any, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    scope = args[0] if args else kwargs.get("scope")
    session = asgi_session(scope)
    if session is None or current_state() is not None or session.finished:
        return wrapped(*args, **kwargs)

    async def rebound_call() -> Any:
        token = attach(session)
        try:
            result = wrapped(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result
        finally:
            detach_token(token)

    return rebound_call()


def _capture_path_carrier(value: Any, instance: Any) -> Any:
    state = current_state()
    if state is not None and is_http_state(state):
        capture_mapping(
            value, HTTP_PATH, "starlette.requests.Request.path_params", "path"
        )
        if not isinstance(value, dict):
            register_carrier(state, value, HTTP_PATH, "path")
    return value
