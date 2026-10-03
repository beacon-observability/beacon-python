from __future__ import annotations

import importlib
import inspect
import threading
import weakref
from collections.abc import Mapping
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Callable

from ..patching import Patches

HTTP_PARAMETER = "http.request.parameter"
HTTP_PATH = "http.request.path"
HTTP_HEADER = "http.request.header"
HTTP_BODY = "http.request.body"


@dataclass
class _Registry:
    """Per-request carrier registry.

    Framework request carriers are deliberately kept here instead of being
    tagged globally.  A process can construct QueryDict/MultiDict objects for
    configuration or background work while a request is active; only objects
    handed out by the active request are eligible for source capture.
    """

    http: bool = True
    carriers: dict[int, "_Carrier"] | None = None
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        if self.carriers is None:
            self.carriers = {}


@dataclass
class _Carrier:
    reference: Any
    weak: bool
    kind: str
    name: str

    def value(self) -> Any:
        return self.reference() if self.weak else self.reference


@dataclass
class _Traversal:
    """Bound one framework-value walk to a single request-local budget."""

    state: Any
    depth_limit: int = 8
    node_limit: int = 512
    active_containers: set[int] = field(default_factory=set)
    seen_containers: set[int] = field(default_factory=set)
    nodes: int = 0
    stopped: bool = False
    complete: bool = True
    _reported: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        try:
            from .. import config

            # The hard cap prevents a permissive environment setting from
            # turning a single framework carrier into an unbounded walk.
            self.node_limit = min(
                self.node_limit,
                config.limit("beacon.security.python.max-fields", 256),
            )
        except Exception:
            pass

    def field_limit(self) -> int:
        try:
            from .. import config

            return config.limit("beacon.security.python.max-fields", 256)
        except Exception:
            return 256

    def gap(self, reason: str) -> None:
        self.complete = False
        if reason in self._reported:
            return
        self._reported.add(reason)
        try:
            if self.state is not None:
                self.state.gap(reason)
        except Exception:
            pass

    def sync(self) -> None:
        if self.stopped or self.state is None:
            return
        try:
            exhausted = bool(self.state.tracking_exhausted)
        except Exception:
            exhausted = False
        if exhausted:
            self.gap("framework.tracking_exhausted")
            self.stopped = True

    def enter(
        self, value: Any, depth: int, *, recursive: bool = False
    ) -> bool:
        self.sync()
        if self.stopped or self.state is None:
            return False
        if depth > self.depth_limit:
            self.gap("framework.field_depth")
            return False
        if self.nodes >= self.node_limit:
            self.gap("framework.field_traversal_limit")
            self.stopped = True
            return False
        if recursive:
            marker = id(value)
            if marker in self.active_containers:
                self.gap("framework.field_cycle")
                return False
            if marker in self.seen_containers:
                # Do not silently choose the first path for a shared mapping
                # or model.  Walk the alias again so scalar leaves can still
                # expose a conflicting source identity.
                self.gap("source_container_alias")
            self.seen_containers.add(marker)
            self.active_containers.add(marker)
        self.nodes += 1
        return True

    def leave(self, value: Any, *, recursive: bool = False) -> None:
        if recursive:
            self.active_containers.discard(id(value))


@dataclass
class Session:
    state: Any
    token: Any = None
    owner: bool = True
    attached: bool = True
    finished: bool = False


_registries: dict[int, _Registry] = {}
_registries_lock = threading.RLock()
_MISSING = object()
_ASGI_SESSION_KEY = "beacon_security._framework_session"


def _runtime() -> Any:
    try:
        return importlib.import_module("beacon_security.runtime")
    except Exception:
        return None


def current_state() -> Any:
    runtime = _runtime()
    if runtime is None:
        return None
    try:
        return runtime.current_state()
    except Exception:
        return None


def _registry(state: Any, create: bool = False) -> _Registry | None:
    if state is None:
        return None
    key = id(state)
    with _registries_lock:
        registry = _registries.get(key)
        if registry is None and create:
            registry = _Registry()
            _registries[key] = registry
        return registry


def begin(metadata: dict[str, Any] | None = None) -> Session | None:
    """Start an owned request state, or join an already active request.

    All failures in this helper are intentionally fail-open.  The framework
    callable is still invoked by the caller exactly once.
    """

    existing = current_state()
    if existing is not None:
        _registry(existing, create=True)
        return Session(existing, owner=False, attached=False)

    runtime = _runtime()
    if runtime is None:
        return None
    try:
        state = runtime.start_request(metadata)
    except Exception:
        return None
    if state is None:
        return None

    _registry(state, create=True)
    try:
        token = runtime.attach_state(state)
    except Exception:
        try:
            runtime.end_request(state)
        except Exception:
            pass
        _drop_registry(state)
        return None

    session = Session(state, token=token, owner=True, attached=True)
    bind_server_span(state)
    return session


def detach(session: Session | None) -> None:
    if session is None or not session.owner or not session.attached:
        return
    runtime = _runtime()
    if runtime is not None:
        try:
            runtime.detach_state(session.token)
        except Exception:
            pass
    session.attached = False


def attach(session: Session | None) -> Any:
    """Attach a request for a bounded iterator call.

    The returned token is private to this attachment and must be passed to
    :func:`detach_token`.  A WSGI result uses this for every ``next``/``close``
    call so a server cannot leak request context into the next request.
    """

    if session is None or session.finished:
        return _MISSING
    runtime = _runtime()
    if runtime is None:
        return _MISSING
    try:
        token = runtime.attach_state(session.state)
    except Exception:
        return _MISSING
    bind_server_span(session.state)
    return token


def detach_token(token: Any) -> None:
    if token is _MISSING:
        return
    runtime = _runtime()
    if runtime is None:
        return
    try:
        runtime.detach_state(token)
    except Exception:
        pass


def bind_asgi_session(scope: Any, session: Session | None) -> None:
    """Carry a request session across an OTel context replacement."""

    if session is None or not isinstance(scope, dict):
        return
    try:
        scope[_ASGI_SESSION_KEY] = session
    except Exception:
        pass


def asgi_session(scope: Any) -> Session | None:
    if not isinstance(scope, dict):
        return None
    try:
        value = scope.get(_ASGI_SESSION_KEY)
    except Exception:
        return None
    return value if isinstance(value, Session) else None


def clear_asgi_session(scope: Any, session: Session | None) -> None:
    if session is None or not isinstance(scope, dict):
        return
    try:
        if scope.get(_ASGI_SESSION_KEY) is session:
            scope.pop(_ASGI_SESSION_KEY, None)
    except Exception:
        pass


def finish(
    session: Session | None,
    error: BaseException | None = None,
    *,
    detach_context: bool = True,
) -> None:
    if session is None or not session.owner or session.finished:
        return
    session.finished = True
    runtime = _runtime()
    try:
        if runtime is not None:
            runtime.end_request(session.state, error=error)
    except Exception:
        pass
    finally:
        if detach_context:
            detach(session)
        _drop_registry(session.state)


def bind_server_span(state: Any) -> None:
    """Bind whatever server span is current, without is_recording gating."""

    if state is None:
        return
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span is not None:
            state.bind_span(span)
    except Exception:
        pass


def source(value: Any, kind: str, name: str, location: str = "") -> Any:
    """Record a source and always return the exact value supplied by the app."""

    state = current_state()
    if state is None:
        return value
    bind_server_span(state)
    runtime = _runtime()
    if runtime is not None:
        try:
            runtime.source(
                value, kind, _bounded_name(name), _bounded_location(location)
            )
        except Exception:
            pass
    return value


def _bounded_name(value: Any) -> str:
    try:
        return str(value)[:128]
    except Exception:
        return "value"


def _bounded_location(value: Any) -> str:
    try:
        return str(value)[:256]
    except Exception:
        return "framework"


def _field_name(prefix: str, key: Any) -> str:
    key_text = _bounded_name(key)
    if prefix == "header":
        key_text = key_text.lower()
    if isinstance(key, int):
        return f"{prefix}[{key_text}]" if prefix else f"[{key_text}]"
    return f"{prefix}.{key_text}" if prefix else key_text


def register_carrier(
    state: Any, carrier: Any, kind: str, name: str = ""
) -> None:
    registry = _registry(state)
    if registry is None or carrier is None:
        return
    with registry.lock:
        try:
            assert registry.carriers is not None
            key = id(carrier)
            existing = registry.carriers.get(key)
            if existing is not None and existing.value() is carrier:
                # The same framework object may be exposed through several
                # properties.  Keep its first source identity stable.
                return
            for dead_key, entry in list(registry.carriers.items()):
                if entry.weak and entry.value() is None:
                    registry.carriers.pop(dead_key, None)
            maximum = 256
            try:
                from .. import config

                maximum = config.limit(
                    "beacon.security.max.framework.carriers", maximum
                )
            except Exception:
                pass
            if len(registry.carriers) >= maximum:
                try:
                    state.gap("framework.carrier_limit")
                except Exception:
                    pass
                return
            try:
                reference = weakref.ref(carrier)
            except TypeError:
                # Never retain an unweakrefable mutable framework carrier.
                # Request-property callbacks snapshot bounded, already-parsed
                # values before reaching this path; callers can still use
                # those sources without a live carrier registry entry.  The
                # inability to retain the container is not itself a coverage
                # gap when that snapshot completed.
                return
            registry.carriers[key] = _Carrier(
                reference, True, kind, _bounded_name(name)
            )
        except Exception:
            pass


def carrier_spec(
    carrier: Any, state: Any | None = None
) -> tuple[str, str] | None:
    state = current_state() if state is None else state
    registry = _registry(state)
    if registry is None or carrier is None:
        return None
    with registry.lock:
        try:
            entry = (
                registry.carriers.get(id(carrier))
                if registry.carriers is not None
                else None
            )
            if entry is not None and entry.value() is carrier:
                return entry.kind, entry.name
        except Exception:
            pass
    return None


def _drop_registry(state: Any) -> None:
    with _registries_lock:
        registry = _registries.pop(id(state), None)
    if registry is None:
        return
    with registry.lock:
        if registry.carriers:
            registry.carriers.clear()


def is_http_state(state: Any | None = None) -> bool:
    state = current_state() if state is None else state
    registry = _registry(state)
    return bool(registry is not None and registry.http)


def _unique_marks(marks: list[Any]) -> tuple[Any, ...]:
    unique: list[Any] = []
    for mark in marks:
        try:
            if mark not in unique:
                unique.append(mark)
        except Exception:
            unique.append(mark)
    return tuple(unique)


def _model_fields(value: Any) -> Mapping[Any, Any] | None:
    try:
        fields = getattr(value, "model_fields", None)
    except Exception:
        return None
    if isinstance(fields, Mapping) and not isinstance(value, type):
        return fields
    return None


def _capture_mapping_values(
    mapping: Any,
    kind: str,
    location: str,
    prefix: str,
    depth: int,
    traversal: _Traversal,
) -> tuple[Any, ...]:
    try:
        items = iter(mapping.items())
    except Exception:
        traversal.gap("framework.field_iteration")
        return ()
    marks: list[Any] = []
    maximum = traversal.field_limit()
    try:
        for index, pair in enumerate(islice(items, maximum + 1)):
            if traversal.stopped:
                break
            if index >= maximum:
                traversal.gap("framework.field_limit")
                break
            try:
                key, value = pair
            except Exception:
                traversal.gap("framework.field_iteration")
                continue
            marks.extend(
                _capture_bound(
                    value,
                    kind,
                    location,
                    _field_name(prefix, key),
                    depth + 1,
                    _traversal=traversal,
                )
            )
    except Exception:
        traversal.gap("framework.field_iteration")
    traversal.sync()
    return _unique_marks(marks)


def _capture_sequence_values(
    values: Any,
    kind: str,
    location: str,
    prefix: str,
    depth: int,
    sequence_index: bool,
    traversal: _Traversal,
) -> tuple[Any, ...]:
    try:
        items = iter(values)
    except Exception:
        traversal.gap("framework.field_iteration")
        return ()
    marks: list[Any] = []
    maximum = traversal.field_limit()
    try:
        for index, item in enumerate(islice(items, maximum + 1)):
            if traversal.stopped:
                break
            if index >= maximum:
                traversal.gap("framework.field_limit")
                break
            item_name = (
                _field_name(prefix, index) if sequence_index else prefix
            )
            marks.extend(
                _capture_bound(
                    item,
                    kind,
                    location,
                    item_name,
                    depth + 1,
                    sequence_index=sequence_index,
                    _traversal=traversal,
                )
            )
    except Exception:
        traversal.gap("framework.field_iteration")
    traversal.sync()
    return _unique_marks(marks)


def capture_mapping(
    mapping: Any,
    kind: str,
    location: str,
    prefix: str = "",
    *,
    _traversal: _Traversal | None = None,
    _depth: int = 0,
) -> None:
    """Capture already-read mapping values with one bounded request walk."""

    state = current_state()
    if state is None:
        return
    traversal = _traversal or _Traversal(state)
    try:
        _capture_bound(
            mapping, kind, location, prefix, _depth, _traversal=traversal
        )
    except Exception:
        return


def capture_sequence(
    values: Any, kind: str, location: str, prefix: str = ""
) -> None:
    state = current_state()
    if state is None:
        return
    traversal = _Traversal(state)
    try:
        if isinstance(values, (list, tuple)):
            _capture_bound(
                values, kind, location, prefix, _traversal=traversal
            )
        else:
            _capture_sequence_values(
                values, kind, location, prefix, 0, True, traversal
            )
    except Exception:
        return


def _capture_bound(
    value: Any,
    kind: str,
    location: str,
    name: str,
    depth: int = 0,
    sequence_index: bool = True,
    *,
    _traversal: _Traversal | None = None,
) -> tuple[Any, ...]:
    traversal = _traversal or _Traversal(current_state())
    state = traversal.state
    if state is None:
        return ()
    if depth > traversal.depth_limit:
        traversal.gap("framework.field_depth")
        return ()

    fields = None
    if not isinstance(value, (Mapping, list, tuple)):
        fields = _model_fields(value)
    recursive = isinstance(value, (Mapping, list, tuple)) or fields is not None
    if not traversal.enter(value, depth, recursive=recursive):
        return ()
    try:
        if isinstance(value, Mapping):
            return _capture_mapping_values(
                value, kind, location, name, depth, traversal
            )
        if isinstance(value, (list, tuple)):
            return _capture_sequence_values(
                value, kind, location, name, depth, sequence_index, traversal
            )

        # Pydantic v2 model instances expose model_fields on the instance's
        # class.  Read only declared fields; do not call model_dump(), which
        # would copy or execute user serializers.
        if fields is not None:
            handled = False
            field_marks: list[Any] = []
            try:
                field_items = iter(fields.items())
            except Exception:
                traversal.gap("framework.field_iteration")
                field_items = iter(())
            maximum = traversal.field_limit()
            try:
                for index, pair in enumerate(islice(field_items, maximum + 1)):
                    if traversal.stopped:
                        break
                    if index >= maximum:
                        traversal.gap("framework.field_limit")
                        break
                    try:
                        field_name, field_info = pair
                        field_value = getattr(value, field_name)
                    except Exception:
                        continue
                    alias = getattr(field_info, "alias", None) or field_name
                    field_marks.extend(
                        _capture_bound(
                            field_value,
                            kind,
                            location,
                            _field_name(name, alias),
                            depth + 1,
                            sequence_index,
                            _traversal=traversal,
                        )
                    )
                    handled = True
            except Exception:
                traversal.gap("framework.field_iteration")
            if handled:
                traversal.sync()
                field_marks_tuple = _unique_marks(field_marks)
                if (
                    field_marks_tuple
                    and traversal.complete
                    and not traversal.stopped
                    and not getattr(state, "tracking_exhausted", False)
                ):
                    try:
                        aggregate = state.derive(
                            field_marks_tuple,
                            "model.fields",
                            location,
                            exact=False,
                        )
                        state.put(value, aggregate)
                    except Exception:
                        state.gap("framework.model_propagation")
                traversal.sync()
                return field_marks_tuple
            traversal.sync()
            return ()

        source(value, kind, name, location)
        try:
            marks = tuple(state.marks(value))
        except Exception:
            marks = ()
        traversal.sync()
        return marks
    finally:
        traversal.leave(value, recursive=recursive)


def capture_bound_values(
    values: Any,
    kind: str,
    location: str,
    prefix: str = "",
    *,
    sequence_index: bool = True,
) -> None:
    if isinstance(values, Mapping):
        capture_mapping(values, kind, location, prefix)
    else:
        _capture_bound(
            values,
            kind,
            location,
            prefix or "value",
            sequence_index=sequence_index,
        )


def capture_carrier_result(
    instance: Any,
    result: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    method: str,
    location: str,
) -> Any:
    state = current_state()
    spec = carrier_spec(instance, state)
    if spec is None:
        return result
    kind, prefix = spec
    if method not in {"__getitem__", "get", "getlist"}:
        return result
    key = args[0] if args else kwargs.get("key", _MISSING)
    if key is _MISSING:
        return result
    if method != "__getitem__":
        try:
            if key not in instance:
                return result
        except Exception:
            return result
    field_name = _field_name(prefix, key)
    if method == "getlist" and type(result) in (list, tuple):
        for item in result:
            source(item, kind, field_name, location)
    else:
        source(result, kind, field_name, location)
    return result


def observe_access(
    container: Any, key: Any, result: Any, location: str = ""
) -> Any:
    """Observe a successful AST subscript without performing another read."""

    state = current_state()
    spec = carrier_spec(container, state)
    if spec is None:
        return result
    try:
        source(
            result,
            spec[0],
            _field_name(spec[1], key),
            location or "framework.access",
        )
    except BaseException:
        pass
    return result


def wrap_descriptor(
    patches: Patches,
    target: type[Any],
    attribute: str,
    callback: Callable[[Any, Any], Any],
) -> bool:
    """Wrap a property/cached-property while preserving its descriptor shape."""

    try:
        descriptor = inspect.getattr_static(target, attribute)
    except (AttributeError, TypeError):
        return False

    def observe(value: Any, instance: Any) -> Any:
        try:
            callback(value, instance)
        except Exception:
            state = current_state()
            if state is not None:
                state.gap("framework.descriptor_observation")
        return value

    # Werkzeug cached_property subclasses property, but its __get__ performs
    # cache lookup. Calling fget directly turns form's self.form read recursive.
    if type(descriptor) is property:
        if descriptor.fget is None:
            return False

        def getter(instance: Any) -> Any:
            value = descriptor.fget(instance)
            return observe(value, instance)

        replacement: Any = property(
            getter, descriptor.fset, descriptor.fdel, descriptor.__doc__
        )
    elif hasattr(descriptor, "__get__") and not callable(descriptor):
        original = descriptor

        class DescriptorProxy:
            __doc__ = getattr(original, "__doc__", None)

            def __get__(
                self, instance: Any, owner: type[Any] | None = None
            ) -> Any:
                if instance is None:
                    return self
                value = original.__get__(instance, owner or type(instance))
                return observe(value, instance)

            def __getattr__(self, name: str) -> Any:
                return getattr(original, name)

        if hasattr(type(original), "__set__"):

            def set_value(self, instance, value):
                return original.__set__(instance, value)

            DescriptorProxy.__set__ = set_value
        if hasattr(type(original), "__delete__"):

            def delete_value(self, instance):
                return original.__delete__(instance)

            DescriptorProxy.__delete__ = delete_value

        replacement = DescriptorProxy()
    else:
        return False
    setattr(target, attribute, replacement)
    patches.entries.append((target, attribute, descriptor, replacement))
    return True


def wrap_carrier_methods(
    patches: Patches,
    target: type[Any],
    methods: tuple[str, ...],
    location: str,
) -> None:
    for method in methods:
        if not hasattr(target, method):
            continue

        def wrapper(
            wrapped: Any,
            instance: Any,
            args: tuple[Any, ...],
            kwargs: dict[str, Any],
            _method: str = method,
        ) -> Any:
            result = wrapped(*args, **kwargs)
            return capture_carrier_result(
                instance, result, args, kwargs, _method, location
            )

        patches.wrap(target, method, wrapper)


def maybe_await(result: Any) -> Any:
    return result


class WSGIResult:
    """A WSGI result that keeps state attached only during iterator calls."""

    def __init__(self, iterable: Any, session: Session):
        self._iterable = iterable
        self._iterator: Any = None
        self._session = session
        self._telemetry_done = False
        self._underlying_closed = False

    def __iter__(self) -> "WSGIResult":
        return self

    def __next__(self) -> Any:
        if self._telemetry_done:
            raise StopIteration
        token = attach(self._session)
        try:
            try:
                if self._iterator is None:
                    self._iterator = iter(self._iterable)
                return next(self._iterator)
            except StopIteration:
                self._complete(None)
                raise
            except BaseException as error:
                self._complete(error)
                raise
        finally:
            detach_token(token)

    def close(self) -> None:
        if self._underlying_closed:
            return
        self._underlying_closed = True
        token = attach(self._session) if not self._telemetry_done else _MISSING
        try:
            try:
                closer = getattr(self._iterable, "close", None)
                if closer is not None:
                    closer()
            except BaseException as error:
                if not self._telemetry_done:
                    self._complete(error)
                raise
            else:
                if not self._telemetry_done:
                    self._complete(None)
        finally:
            detach_token(token)

    def _complete(self, error: BaseException | None) -> None:
        if self._telemetry_done:
            return
        self._telemetry_done = True
        finish(self._session, error)


def wrap_wsgi_result(result: Any, session: Session | None) -> Any:
    if session is None or not session.owner:
        return result
    if result is None:
        finish(session, None)
        return result
    try:
        return WSGIResult(result, session)
    except Exception:
        finish(session, None)
        return result


def asgi_message_ends_response(message: Any) -> bool:
    if not isinstance(message, Mapping):
        return False
    message_type = message.get("type")
    if message_type == "http.response.body":
        return not bool(message.get("more_body", False))
    if message_type == "http.response.trailers":
        return not bool(message.get("more_trailers", False))
    return False


def asgi_receive_wrapper(receive: Any, session: Session | None = None) -> Any:
    async def wrapped() -> Any:
        try:
            result = receive()
            if inspect.isawaitable(result):
                result = await result
            if isinstance(result, Mapping):
                if result.get("type") == "http.request":
                    body = result.get("body", _MISSING)
                    if body is not _MISSING:
                        source(body, HTTP_BODY, "body", "asgi.receive")
                elif result.get("type") == "http.disconnect":
                    # A disconnect may be delivered without a response or in
                    # a task different from the one that owns the token.
                    finish(session, None, detach_context=False)
            return result
        except BaseException as error:
            finish(session, error, detach_context=False)
            raise

    return wrapped


def asgi_send_wrapper(send: Any, session: Session | None) -> Any:
    trailers_expected = False

    async def wrapped(message: Any) -> Any:
        if (
            isinstance(message, Mapping)
            and message.get("type") == "http.response.start"
        ):
            nonlocal trailers_expected
            trailers_expected = bool(message.get("trailers", False))
            state = current_state()
            if session is not None and state is session.state:
                try:
                    state.request["status_code"] = int(
                        message.get("status", 0)
                    )
                except Exception:
                    pass
        terminal = asgi_message_ends_response(message)
        if (
            trailers_expected
            and isinstance(message, Mapping)
            and message.get("type") == "http.response.body"
            and not bool(message.get("more_body", False))
        ):
            terminal = False
        try:
            result = send(message)
            if inspect.isawaitable(result):
                result = await result
        except BaseException as error:
            # The ASGI send may run in a child task.  Its context is not the
            # one that owns the attach token created by the outer call.
            finish(session, error, detach_context=False)
            raise
        if terminal:
            # Close shared state here, but let the outer ASGI await finally
            # detach the token in the context that created it.
            finish(session, None, detach_context=False)
        return result

    return wrapped
