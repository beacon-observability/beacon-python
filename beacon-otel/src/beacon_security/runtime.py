from __future__ import annotations

import asyncio
import atexit
import contextlib
import contextvars
import os
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeoutError

from opentelemetry import context

from . import config
from .locations import caller_location
from .state import SecurityState, stamp
from .tracking import ByteBudget

_STATE_KEY = context.create_key("BeaconSecurity-state")
_LOCAL_STATE = contextvars.ContextVar("beacon_security_request", default=None)
_SUPPRESSED = contextvars.ContextVar(
    "beacon_security_suppressed", default=False
)
_runtime = None
_lock = threading.RLock()
_collecting = True
_adapters = []
_startup_gaps = set()


@contextlib.contextmanager
def suppress():
    token = _SUPPRESSED.set(True)
    try:
        yield
    finally:
        _SUPPRESSED.reset(token)


class Runtime:
    def __init__(self):
        from .exporter import Exporter
        from .sbom import SbomInventory

        self.pid = os.getpid()
        self.closed = False
        self.identity = config.identity()
        self.profile = config.profile(_adapters)
        self.output = config.output_directory(self.identity["instance_id"])
        self.budget = ByteBudget()
        self.exporter = Exporter(self.identity, self.profile, self.output)
        self.inventory = None
        if config.flag("beacon.security.enabled", False) and config.flag(
            "beacon.security.sbom.enabled", True
        ):
            self.inventory = SbomInventory(
                self.identity, self.output, self._sbom_event
            )
            self.inventory.start()
        else:
            self.exporter.ledger.sbom({"status": "disabled"})
        for reason in sorted(_startup_gaps):
            self.exporter.ledger.count("instrumentation_failures")
            self.exporter.emit(
                {
                    "event_name": "beacon.security.collection.incomplete",
                    "reason": reason,
                    "identity": self.identity,
                }
            )
        atexit.register(self.close)

    def _sbom_event(self, event):
        self.exporter.emit(event)
        if event.get("event_name") in (
            "beacon.security.sbom.health",
            "beacon.security.sbom.snapshot",
            "beacon.security.sbom.update_failed",
        ):
            self.exporter.ledger.sbom(event)

    def close(self, timeout=1.5):
        if self.closed or self.pid != os.getpid():
            return
        self.closed = True
        deadline = time.monotonic() + max(0.0, timeout)
        with suppress():
            if self.inventory is not None:
                self.inventory.close(
                    timeout=max(0.0, deadline - time.monotonic())
                )
            self.exporter.close(timeout=max(0.0, deadline - time.monotonic()))


def get_runtime() -> Runtime:
    global _runtime
    if _runtime is None or _runtime.pid != os.getpid() or _runtime.closed:
        with _lock, suppress():
            if (
                _runtime is None
                or _runtime.pid != os.getpid()
                or _runtime.closed
            ):
                _runtime = Runtime()
    return _runtime


def current_state() -> SecurityState | None:
    if not _collecting or _SUPPRESSED.get():
        return None
    state = context.get_value(_STATE_KEY)
    if not isinstance(state, SecurityState) or state.closed:
        # Server instrumentation can replace the OTel Context with the remote
        # propagation context. The local request lifetime must survive that.
        state = _LOCAL_STATE.get()
    if (
        not isinstance(state, SecurityState)
        or state.closed
        or not state.collection_enabled
    ):
        return None
    current = _runtime
    if current is not None and not current.exporter.ledger.enabled():
        state.gap("collection_paused_during_request")
        return None
    return state


def start_request(metadata=None) -> SecurityState | None:
    if not _collecting:
        return None
    with suppress():
        current = get_runtime()
        state = SecurityState(current.identity, current.budget, metadata)
        state.runtime = current
        current.exporter.ledger.begin(state)
        for reason in _startup_gaps:
            state.gap(reason)
        return state


def attach_state(state):
    token = context.attach(context.set_value(_STATE_KEY, state))
    return token, _LOCAL_STATE.set(state)


def detach_state(token):
    otel_token, local_token = token
    try:
        context.detach(otel_token)
    finally:
        _LOCAL_STATE.reset(local_token)


@contextlib.contextmanager
def bound_state(state):
    token = None
    if context.get_value(_STATE_KEY) is not state:
        try:
            token = context.attach(context.set_value(_STATE_KEY, state))
        except Exception:
            state.gap("context_binding_failed")
    try:
        yield
    finally:
        if token is not None:
            context.detach(token)


def end_request(state, error=None):
    with state.lock, suppress():
        if state.closed:
            return
        current = getattr(state, "runtime", None) or get_runtime()
        try:
            state.request["ended_at"] = stamp()
            if error is not None:
                state.request.setdefault("status_code", 500)
                state.request["error_type"] = type(error).__name__
            if state.request.get("route"):
                state.request["route_status"] = "observed"
            events = current.exporter.ledger.end(state)
            span = state.server_span
            span_context = None
            try:
                _summarize(state)
                span_context = (
                    span.get_span_context() if span is not None else None
                )
            except Exception:
                current.exporter.ledger.count("span_summary_errors")
            for event in events:
                current.exporter.emit(
                    event, span_context=span_context, evidence=True
                )
        except Exception:
            current.exporter.ledger.count("request_completion_errors")
        finally:
            state.close()


def _summarize(state):
    span = state.server_span
    # Only the optional span summary is gated. Findings/logs remain independent
    # of trace sampling and of early framework span termination.
    if span is None or not span.is_recording():
        return
    if state.pending or getattr(state, "summary_written", False):
        span.set_attribute("beacon.security.detected", bool(state.pending))
        span.set_attribute("beacon.security.finding_count", len(state.pending))
        span.set_attribute(
            "beacon.security.types",
            sorted({event["rule"] for event in state.pending}),
        )
        span.set_attribute(
            "beacon.security.finding.ids",
            list(
                dict.fromkeys(event["finding_id"] for event in state.pending)
            ),
        )
        span.set_attribute(
            "beacon.security.evidence.ids",
            [event["evidence_id"] for event in state.pending],
        )
        state.summary_written = True
    if state.truncated:
        span.set_attribute("beacon.security.truncated", True)


def source(value, kind, name, location=""):
    state = current_state()
    if state is not None:
        try:
            with suppress():
                state.capture(value, kind, name, location or caller_location())
                if getattr(state, "summary_written", False):
                    try:
                        _summarize(state)
                    except Exception:
                        get_runtime().exporter.ledger.count(
                            "span_summary_errors"
                        )
        except Exception as error:
            state.gap("source_capture_error:" + type(error).__name__)
    return value


def sink(rule, function, role, value=None, *, marks=None, location=""):
    state = current_state()
    if state is None:
        return None
    try:
        with suppress():
            location = location or caller_location()
            event = state.sink(
                rule, function, role, value, marks=marks, location=location
            )
            if event is not None:
                inventory = get_runtime().inventory
                if inventory is not None:
                    event["component"] = inventory.resolve(
                        location.partition("#")[0]
                    )
                else:
                    event["component"] = {
                        "status": "unresolved",
                        "reason": "sbom_disabled",
                    }
                try:
                    _summarize(state)
                except Exception:
                    get_runtime().exporter.ledger.count("span_summary_errors")
            return event
    except Exception as error:
        state.gap("sink_collection_error:" + type(error).__name__)
        return None


def gap(reason):
    state = current_state()
    if state is not None:
        state.gap(reason)


def startup_gap(reason):
    reason = str(reason)[:256]
    if len(_startup_gaps) < 32 and reason not in _startup_gaps:
        _startup_gaps.add(reason)
        current = _runtime
        if (
            current is not None
            and not current.closed
            and current.pid == os.getpid()
        ):
            current.exporter.ledger.count("instrumentation_failures")
            current.exporter.emit(
                {
                    "event_name": "beacon.security.collection.incomplete",
                    "reason": reason,
                    "identity": current.identity,
                }
            )


def start(adapters):
    global _adapters, _collecting
    _adapters = list(adapters)
    _collecting = True
    return get_runtime()


def stop():
    global _collecting
    _collecting = False
    if _runtime is not None:
        _runtime.close()


def _start_flush(timeout):
    current = _runtime
    if current is None or current.closed or current.pid != os.getpid():
        return None
    deadline = time.monotonic() + max(0.0, timeout)
    return current.exporter, current.exporter.start_flush(deadline), deadline


def flush(timeout=1.5):
    """Wait up to timeout for snapshots, delivery and the shared provider flush."""
    operation = _start_flush(timeout)
    if operation is None:
        return True
    exporter, task, deadline = operation
    try:
        return task.result(timeout=max(0.0, deadline - time.monotonic()))
    except FutureTimeoutError:
        exporter.ledger.shutdown_delivery_uncertain("shutdown_flush_timeout")
        return False


async def aflush(timeout=1.5):
    """Drain telemetry without blocking the application's event loop."""
    operation = _start_flush(timeout)
    if operation is None:
        return True
    exporter, task, deadline = operation
    try:
        while not task.done():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            await asyncio.sleep(min(0.01, remaining))
        return task.result()
    finally:
        if not task.done():
            exporter.ledger.shutdown_delivery_uncertain(
                "shutdown_flush_timeout"
            )


def _after_fork():
    global _runtime, _lock
    _runtime = None
    _lock = threading.RLock()
    _SUPPRESSED.set(False)
    _LOCAL_STATE.set(None)
    context.attach(context.set_value(_STATE_KEY, None))


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
