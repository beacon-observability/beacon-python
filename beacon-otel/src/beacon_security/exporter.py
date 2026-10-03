from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import config
from .ledger import RuntimeLedger
from .schema import PRODUCT, event_record


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    return str(value)


def _encode_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class _Entry:
    event: dict[str, Any]
    span_context: Any
    evidence: bool


class Exporter:
    """Independent bounded OTel Logs and local evidence delivery workers."""

    def __init__(self, identity: dict, profile: str, output: Path):
        self.identity = dict(identity or {})
        self.profile = str(profile or "")
        self.output = Path(output).expanduser().absolute()
        self.ledger = RuntimeLedger(self.identity, self.profile, self.output)

        self._security_queue: queue.Queue[_Entry] = queue.Queue(
            maxsize=config.limit("beacon.security.export.queue.size", 1024)
        )
        self._sbom_queue: queue.Queue[_Entry] = queue.Queue(
            maxsize=config.limit("beacon.security.export.sbom.queue.size", 256)
        )
        self._counters: dict[str, int] = {}
        self._counter_lock = threading.Lock()
        self._loss_lock = threading.Lock()
        self._pending_dropped = {"security": 0, "sbom": 0}
        self._dropped = 0
        self._dropped_by_channel = {"security": 0, "sbom": 0}
        self._running = True
        self._closed = False
        self._close_lock = threading.Lock()
        self._closing = False
        self._close_deadline = None
        self._flush_task = None
        self._flush_queue = queue.Queue(maxsize=1)
        self._monitor_stop = threading.Event()
        self._last_file_success = 0.0
        self._last_otel_call = 0.0
        self._last_error = 0.0

        local_output_enabled = config.flag(
            "beacon.security.local-output.enabled", False
        )
        configured_file = config.text("beacon.security.evidence.file", "")
        self._file = (
            Path(configured_file).expanduser().absolute()
            if local_output_enabled and configured_file
            else None
        )
        self._max_bytes = config.limit(
            "beacon.security.evidence.max.bytes", 65536
        )
        self._rotate_bytes = config.limit(
            "beacon.security.evidence.file.max.bytes", 10 * 1024 * 1024
        )
        self._backups = min(
            20, config.limit("beacon.security.evidence.file.backups", 3)
        )
        self._writer = None
        self._file_bytes = 0
        self._writer_lock = threading.RLock()

        self._otel_logger = self._make_logger()

        self._security_worker = threading.Thread(
            target=self._run_channel,
            args=(self._security_queue, "security"),
            name="BeaconSecurity-export",
            daemon=True,
        )
        self._sbom_worker = threading.Thread(
            target=self._run_channel,
            args=(self._sbom_queue, "sbom"),
            name="BeaconSecurity-sbom-export",
            daemon=True,
        )
        self._monitor = threading.Thread(
            target=self._monitor_loop,
            name="BeaconSecurity-health",
            daemon=True,
        )
        self._flush_worker = threading.Thread(
            target=self._flush_loop,
            name="BeaconSecurity-flush",
            daemon=True,
        )
        # Python 3.12+ forbids starting threads inside atexit callbacks.
        self._flush_worker.start()
        self._security_worker.start()
        self._sbom_worker.start()
        self._monitor.start()

    def emit(
        self,
        event: dict,
        span_context: Any = None,
        evidence: bool = False,
    ) -> None:
        """Enqueue one event without blocking or changing the caller's value."""

        try:
            copied = event_record(dict(event), self.ledger.identity)
        except BaseException:
            self._loss("beacon.security.invalid_event")
            return
        try:
            channel = (
                "sbom"
                if copied.get("event_name") == "beacon.security.sbom.snapshot"
                or str(copied.get("event_name", "")).startswith(
                    "beacon.security.sbom."
                )
                else "security"
            )
        except BaseException:
            self._loss("beacon.security.invalid_event")
            return
        target = (
            self._sbom_queue if channel == "sbom" else self._security_queue
        )
        frozen_context = self._freeze_context(span_context, copied)
        if not self._running:
            self._loss(channel + ".closed", copied)
            return
        try:
            target.put_nowait(_Entry(copied, frozen_context, bool(evidence)))
        except queue.Full:
            self._loss(channel + ".queue_full", copied)
        except BaseException:
            self._loss(channel + ".enqueue_failed", copied)
        else:
            self._count(channel + ".queued")

    def delivery(self) -> dict:
        with self._counter_lock:
            counters = dict(sorted(self._counters.items()))
        with self._loss_lock:
            dropped = self._dropped
            dropped_by_channel = dict(self._dropped_by_channel)
        return {
            "counters": counters,
            "dropped": dropped,
            "security_dropped": dropped_by_channel["security"],
            "sbom_dropped": dropped_by_channel["sbom"],
            "security_queue_depth": self._security_queue.qsize(),
            "sbom_queue_depth": self._sbom_queue.qsize(),
            "last_file_write_at": self._stamp_millis(self._last_file_success),
            "last_otel_api_call_at": self._stamp_millis(self._last_otel_call),
            "evidence_file": "disabled"
            if self._file is None
            else str(self._file),
            "otel_logs_config": config.text(
                "otel.logs.exporter", "agent_default"
            ),
            "backend_acknowledgement": "unknown",
            "otel_semantics": "api_emit_is_not_export_or_backend_ack",
            "delivery_guarantee": "bounded_best_effort_no_agent_replay",
            "file_write_semantics": "flushed_not_fsynced",
        }

    def flush(self, timeout: float = 1.5) -> bool:
        """Wait briefly for queued records; a blocked OTel SDK cannot block shutdown forever."""

        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            if (
                self._security_queue.unfinished_tasks == 0
                and self._sbom_queue.unfinished_tasks == 0
            ):
                return True
            time.sleep(0.01)
        return (
            self._security_queue.unfinished_tasks == 0
            and self._sbom_queue.unfinished_tasks == 0
        )

    def start_flush(self, deadline: float, *, close: bool = False) -> Future:
        with self._close_lock:
            if close:
                if not self._closing:
                    self._close_deadline = deadline
                self._closing = True
                self._monitor_stop.set()
            if self._flush_task is not None and (
                not self._flush_task.done() or self._closed
            ):
                return self._flush_task
            task = self._flush_task = Future()
            # One reusable in-flight operation: stalled filesystem/SDK calls may
            # outlive the deadline, but cannot pin the process or spawn a backlog.
            self._flush_queue.put_nowait((task, deadline))
            return task

    def _flush_loop(self) -> None:
        while True:
            task, deadline = self._flush_queue.get()
            self._flush_telemetry(task, deadline)
            self._flush_queue.task_done()
            if self._closed:
                return

    def _flush_telemetry(self, task: Future, deadline: float) -> None:
        from .runtime import suppress

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        drained = False
        with suppress():
            try:
                self._emit_pending_loss()
                snapshot = self.ledger.tick(
                    self.delivery(),
                    lambda event: self.emit(event, evidence=True),
                    force=True,
                    deadline=deadline,
                )
                drained = self.flush(timeout=remaining()) and snapshot
                if remaining() > 0:
                    from opentelemetry._logs import get_logger_provider

                    provider_flush = getattr(
                        get_logger_provider(), "force_flush", None
                    )
                    if provider_flush is not None:
                        drained = (
                            provider_flush(
                                timeout_millis=max(1, int(remaining() * 1000))
                            )
                            and drained
                        )
                drained = bool(drained and remaining() > 0)
                if not drained:
                    self.ledger.shutdown_delivery_uncertain(
                        "shutdown_flush_incomplete"
                    )
            except BaseException:
                drained = False
                self.ledger.shutdown_delivery_uncertain(
                    "shutdown_flush_errors"
                )
            try:
                self.ledger.tick(
                    self.delivery(),
                    lambda _event: None,
                    force=True,
                    deadline=deadline,
                )
            except BaseException:
                drained = False
                self.ledger.shutdown_delivery_uncertain(
                    "shutdown_flush_errors"
                )
            drained = bool(drained and remaining() > 0)
            with self._close_lock:
                if not self._closing:
                    task.set_result(drained)
                    return
                # A short flush may already have expired when close joins it.
                # Its cleanup phase gets the original close caller's budget.
                deadline = self._close_deadline
            try:
                self._running = False
                for worker in (
                    self._monitor,
                    self._security_worker,
                    self._sbom_worker,
                ):
                    if worker is not threading.current_thread():
                        worker.join(timeout=remaining())
                self._discard_pending(self._security_queue, "security")
                self._discard_pending(self._sbom_queue, "sbom")
                self._close_writer()
                self.ledger.tick(
                    self.delivery(),
                    lambda _event: None,
                    force=True,
                    deadline=deadline,
                )
            except BaseException:
                drained = False
                self.ledger.shutdown_delivery_uncertain(
                    "shutdown_close_errors"
                )
            finally:
                with self._close_lock:
                    self._closed = True
                    task.set_result(drained)

    def close(self, timeout: float = 1.5) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        task = self.start_flush(deadline, close=True)
        try:
            task.result(timeout=max(0.0, deadline - time.monotonic()))
        except FutureTimeoutError:
            self._running = False
            self.ledger.shutdown_delivery_uncertain("shutdown_close_timeout")

    def _monitor_loop(self) -> None:
        while not self._monitor_stop.is_set():
            self._emit_pending_loss()
            try:
                self.ledger.tick(
                    self.delivery(),
                    lambda event: self.emit(event, evidence=True),
                )
            except BaseException as error:
                self._diagnostic(error)
            if self._monitor_stop.wait(1.0):
                return

    def _run_channel(
        self, channel_queue: queue.Queue[_Entry], channel: str
    ) -> None:
        events_limit = config.limit(
            "beacon.security.export." + channel + ".events-per-second",
            100 if channel == "security" else 200,
        )
        bytes_limit = config.limit(
            "beacon.security.export." + channel + ".bytes-per-second",
            524288 if channel == "security" else 262144,
        )
        second = 0
        events = 0
        bytes_used = 0
        while self._running or not channel_queue.empty():
            try:
                entry = channel_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                now_second = int(time.monotonic())
                if now_second != second:
                    second = now_second
                    events = 0
                    bytes_used = 0
                encoded, truncated = self._encode_record_result(entry.event)
                if truncated:
                    self._record_record_truncation(entry.event, channel)
                loss_diagnostic = entry.event.get("event_name") in {
                    "beacon.security.export.dropped",
                    "beacon.security.sbom.export.dropped",
                }
                if not loss_diagnostic and (
                    events >= events_limit
                    or bytes_used + len(encoded) > bytes_limit
                ):
                    if channel != "sbom" or len(encoded) > bytes_limit:
                        self._loss(channel + ".budget_exceeded", entry.event)
                        continue
                    self._count("sbom.budget_deferred")
                    while int(time.monotonic()) == second:
                        if (
                            self._close_deadline is not None
                            and time.monotonic() >= self._close_deadline
                        ):
                            self._loss("sbom.shutdown_pending", entry.event)
                            return
                        time.sleep(0.025)
                    second, events, bytes_used = int(time.monotonic()), 0, 0
                if not loss_diagnostic:
                    events += 1
                    bytes_used += len(encoded)
                # A byte-budget reduction is still an incomplete security
                # record.  Preserve it in the local evidence stream even if
                # the caller did not mark the original event as evidence;
                # OTel delivery alone is only an API emission.
                export_entry = (
                    _Entry(
                        json.loads(encoded),
                        entry.span_context,
                        entry.evidence or channel == "security",
                    )
                    if truncated
                    else entry
                )
                self._export(export_entry, encoded, channel)
                self._count(channel + ".processed")
            except BaseException as error:
                self._count(channel + ".failed")
                self._record_delivery_failure(entry.event)
                self._diagnostic(error)
            finally:
                channel_queue.task_done()
        if channel == "security":
            self._close_writer()

    def _export(self, entry: _Entry, encoded: bytes, channel: str) -> None:
        event = entry.event
        body = encoded.decode("utf-8")
        try:
            self._emit_otel(body, event, entry.span_context)
            self._last_otel_call = time.time()
            self._count(channel + ".otel_api_emitted")
        except BaseException as error:
            self._count(channel + ".otel_api_failed")
            self._record_delivery_failure(event)
            self._diagnostic(error)

        if channel != "security" or self._file is None:
            return
        if not entry.evidence and not self._is_diagnostic(event):
            return
        try:
            with self._writer_lock:
                if self._writer is None:
                    self._open_writer()
                if self._file_bytes + len(encoded) + 1 > self._rotate_bytes:
                    self._rotate()
                self._writer.write(body)
                self._writer.write("\n")
                self._writer.flush()
                self._file_bytes += len(encoded) + 1
                self._last_file_success = time.time()
                self._count("beacon.security.file_written")
        except BaseException as error:
            self._count("beacon.security.file_failed")
            self._record_delivery_failure(event)
            self._close_writer()
            self._diagnostic(error)

    def _encode_record(self, event: Mapping[str, Any]) -> bytes:
        return self._encode_record_result(event)[0]

    def _encode_record_result(
        self, event: Mapping[str, Any]
    ) -> tuple[bytes, bool]:
        encoded = _encode_json(event)
        if len(encoded) <= self._max_bytes:
            return encoded, False

        reduced = dict(event)
        for field in ("propagation", "ranges", "sources"):
            reduced.pop(field, None)
        reduced["truncated"] = True
        reduced["truncation_reason"] = "record_byte_limit"
        encoded = _encode_json(reduced)
        if len(encoded) <= self._max_bytes:
            return encoded, True

        summary = {
            "schema_version": 1,
            "source": event["source"],
            "event_name": "beacon.security.export.truncated",
            "original_event": event.get("event_name"),
            "evidence_id": event.get("evidence_id"),
            "sbom_id": event.get("sbom_id"),
            "truncated": True,
        }
        encoded = _encode_json(summary)
        if len(encoded) <= self._max_bytes:
            return encoded, True

        minimal = {
            "schema_version": 1,
            "source": event["source"],
            "event_name": "beacon.security.export.truncated",
            "truncated": True,
        }
        encoded = _encode_json(minimal)
        if len(encoded) > self._max_bytes:
            self._count("record_too_small_for_envelope")
            raise ValueError("record_limit")
        return encoded, True

    def _open_writer(self) -> None:
        if self._file is None:
            return
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file_bytes = (
            self._file.stat().st_size if self._file.exists() else 0
        )
        self._writer = self._file.open("a", encoding="utf-8")

    def _rotate(self) -> None:
        if self._file is None:
            return
        self._close_writer()
        for index in range(self._backups, 0, -1):
            destination = Path(str(self._file) + "." + str(index))
            source = (
                self._file
                if index == 1
                else Path(str(self._file) + "." + str(index - 1))
            )
            if source.exists():
                os.replace(source, destination)
        self._open_writer()

    def _close_writer(self) -> None:
        with self._writer_lock:
            writer = self._writer
            self._writer = None
            if writer is not None:
                try:
                    writer.close()
                except BaseException:
                    pass

    def _emit_pending_loss(self) -> None:
        with self._loss_lock:
            pending = dict(self._pending_dropped)
            self._pending_dropped = {"security": 0, "sbom": 0}
        for channel, count in pending.items():
            if count <= 0:
                continue
            event_name = (
                "beacon.security.export.dropped"
                if channel == "security"
                else "beacon.security.sbom.export.dropped"
            )
            self.emit(
                {
                    "event_name": event_name,
                    "observed_at": self._now_stamp(),
                    "count": count,
                    "delivery": self.delivery(),
                },
                evidence=True,
            )

    def _loss(
        self, reason: str, event: Mapping[str, Any] | None = None
    ) -> None:
        channel = "sbom" if str(reason).startswith("sbom.") else "security"
        with self._loss_lock:
            self._dropped += 1
            self._pending_dropped[channel] += 1
            self._dropped_by_channel[channel] += 1
        self._count(reason)
        if channel == "security":
            try:
                self.ledger.count("delivery_loss")
                self.ledger.record_delivery_loss(event)
            except BaseException:
                pass

    def _record_delivery_failure(
        self, event: Mapping[str, Any] | None = None
    ) -> None:
        if not self._is_security_event(event):
            return
        try:
            self.ledger.count("delivery_failure")
            self.ledger.record_delivery_loss(event)
        except BaseException:
            pass

    def _record_record_truncation(
        self, event: Mapping[str, Any], channel: str
    ) -> None:
        self._count(channel + ".record_truncated")
        if channel != "security":
            return
        try:
            self.ledger.count("delivery_loss")
            self.ledger.record_delivery_loss(event)
        except BaseException:
            pass

    def _discard_pending(
        self, channel_queue: queue.Queue[_Entry], channel: str
    ) -> None:
        pending: list[_Entry] = []
        while True:
            try:
                pending.append(channel_queue.get_nowait())
            except queue.Empty:
                break
        if not pending:
            return
        amount = len(pending)
        self._count(channel + ".shutdown_pending", amount)
        with self._loss_lock:
            self._dropped += amount
            self._pending_dropped[channel] += amount
            self._dropped_by_channel[channel] += amount
        try:
            if channel == "security":
                try:
                    self.ledger.count("delivery_loss", amount)
                    for entry in pending:
                        self.ledger.record_delivery_loss(entry.event)
                except BaseException:
                    pass
        finally:
            for _ in pending:
                channel_queue.task_done()

    def _count(self, name: str, amount: int = 1) -> None:
        with self._counter_lock:
            self._counters[name] = self._counters.get(name, 0) + int(amount)

    def _diagnostic(self, error: BaseException) -> None:
        now = time.monotonic()
        if now - self._last_error < 30.0:
            return
        self._last_error = now
        try:
            print(
                "[Beacon Security] export failure: " + type(error).__name__,
                file=sys.stderr,
            )
        except BaseException:
            pass

    @staticmethod
    def _stamp_millis(value: float) -> str | None:
        if not value:
            return None
        return time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime(value)
        ) + ".%03dZ" % int((value - int(value)) * 1000)

    @staticmethod
    def _now_stamp() -> str:
        return time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime()
        ) + ".%03dZ" % int((time.time() % 1) * 1000)

    @staticmethod
    def _is_diagnostic(event: Mapping[str, Any]) -> bool:
        name = str(event.get("event_name", ""))
        return name in {
            "beacon.security.collection.incomplete",
            "beacon.security.finding.summary",
            "beacon.security.snapshot.failed",
            "beacon.security.export.dropped",
            "beacon.security.sbom.export.dropped",
        } or name.startswith("beacon.security.instrumentation.")

    @staticmethod
    def _is_security_event(event: Mapping[str, Any] | None) -> bool:
        if not isinstance(event, Mapping):
            return True
        return event.get(
            "event_name"
        ) != "beacon.security.sbom.snapshot" and not str(
            event.get("event_name", "")
        ).startswith("beacon.security.sbom.")

    @staticmethod
    def _make_logger() -> Any:
        try:
            from opentelemetry._logs import get_logger

            return get_logger(PRODUCT, config.VERSION)
        except BaseException:
            return None

    @staticmethod
    def _freeze_context(span_context: Any, event: Mapping[str, Any]) -> Any:
        try:
            return Exporter._otel_context(span_context, event)
        except BaseException:
            return None

    def _emit_otel(
        self, body: str, event: Mapping[str, Any], span_context: Any
    ) -> None:
        logger = self._otel_logger
        if logger is None:
            raise RuntimeError("otel_logs_unavailable")
        context = self._otel_context(span_context, event)
        kwargs: dict[str, Any] = {
            "timestamp": time.time_ns(),
            "body": body,
            "severity_text": "INFO",
            "attributes": {
                "event.name": str(event.get("event_name", "")),
                "source": event["source"],
            },
            "context": context,
            "event_name": str(event.get("event_name", "")),
        }
        try:
            from opentelemetry._logs import SeverityNumber

            kwargs["severity_number"] = SeverityNumber.INFO
        except BaseException:
            pass
        logger.emit(**kwargs)

    @staticmethod
    def _otel_context(span_context: Any, event: Mapping[str, Any]) -> Any:
        try:
            from opentelemetry.context import Context
            from opentelemetry.trace import (
                INVALID_SPAN,
                NonRecordingSpan,
                SpanContext,
                TraceFlags,
                TraceState,
                set_span_in_context,
            )
        except BaseException:
            return None

        if isinstance(span_context, Context):
            # ``LogRecord`` falls back to the worker's current context when
            # handed a falsy Context.  Keep the bridge explicit even for a
            # record without valid trace IDs.
            return (
                span_context
                if span_context
                else set_span_in_context(INVALID_SPAN, Context())
            )
        candidate = span_context
        if candidate is not None and not isinstance(candidate, SpanContext):
            getter = getattr(candidate, "get_span_context", None)
            if callable(getter):
                try:
                    candidate = getter()
                except BaseException:
                    candidate = None
        if isinstance(candidate, Mapping):
            candidate = Exporter._span_context_from_values(
                candidate.get("trace_id"),
                candidate.get("span_id"),
                SpanContext,
                TraceFlags,
                TraceState,
                candidate.get("trace_flags", 0),
            )
        if not isinstance(candidate, SpanContext):
            candidate = Exporter._span_context_from_values(
                event.get("trace_id"),
                event.get("server_span_id") or event.get("current_span_id"),
                SpanContext,
                TraceFlags,
                TraceState,
                event.get("trace_flags", 0),
            )
        if isinstance(candidate, SpanContext) and candidate.is_valid:
            return set_span_in_context(NonRecordingSpan(candidate), Context())
        return set_span_in_context(INVALID_SPAN, Context())

    @staticmethod
    def _span_context_from_values(
        trace_id: Any,
        span_id: Any,
        span_context_type: Any,
        trace_flags_type: Any,
        trace_state_type: Any,
        trace_flags: Any = 0,
    ) -> Any:
        try:
            trace_text = str(trace_id or "").lower()
            span_text = str(span_id or "").lower()
            if len(trace_text) != 32 or len(span_text) != 16:
                return None
            if any(
                char not in "0123456789abcdef"
                for char in trace_text + span_text
            ):
                return None
            return span_context_type(
                trace_id=int(trace_text, 16),
                span_id=int(span_text, 16),
                is_remote=False,
                trace_flags=trace_flags_type(int(trace_flags) & 255),
                trace_state=trace_state_type(),
            )
        except BaseException:
            return None
