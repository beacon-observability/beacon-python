from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import sys
import tempfile
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any, Callable, Mapping

from . import config
from .schema import event_record, request_fields

_MISSING = object()
_REQUEST_FIELDS = (
    "framework",
    "transport",
    "method",
    "route",
    "status_code",
    "route_status",
    "started_at",
    "ended_at",
    "error_type",
)


def _now() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _now_millis() -> int:
    return int(time.time() * 1000)


def _copy(value: Any) -> Any:
    """Copy ledger data without letting an application-owned value break cleanup."""

    try:
        return copy.deepcopy(value)
    except Exception:
        if isinstance(value, Mapping):
            return dict(value)
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return value


def _number(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    return str(value)


def _estimate(value: Any) -> int:
    try:
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                default=_json_default,
            ).encode("utf-8")
        )
    except Exception:
        return config.limit("beacon.security.evidence.max.bytes", 65536) + 1


def _parse_time(value: Any) -> _dt.datetime:
    if not isinstance(value, str):
        raise ValueError("time_required")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = _dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def _valid_until(value: Any) -> bool:
    try:
        return _parse_time(value) > _dt.datetime.now(_dt.timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return False


def _non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _safe_request(value: Any) -> dict[str, Any]:
    """Keep request context descriptive without retaining input/query payloads."""

    source = _mapping(value)
    result: dict[str, Any] = {}
    for field in _REQUEST_FIELDS:
        if field not in source:
            continue
        item = source[field]
        if field == "status_code":
            result[field] = _number(item)
        elif isinstance(item, str):
            result[field] = item[:1024]
    return request_fields(result)


def _bounded_error(error: BaseException, length: int = 256) -> str:
    message = str(error) or type(error).__name__
    return message[:length]


class RuntimeLedger:
    """Bounded process-local findings, verification runs, and control state.

    The JSON files written by this class are inspection snapshots.  They are
    deliberately not treated as a durable acknowledgement from an OTel
    collector or a backend.
    """

    def __init__(self, identity: dict, profile: str, output: Path):
        self.identity = (
            _copy(identity) if isinstance(identity, Mapping) else {}
        )
        self.profile = str(profile or "")
        self.output = Path(output).expanduser().absolute()
        configured_control = config.text("beacon.security.control.file", "")
        self.control = (
            Path(configured_control).expanduser().absolute()
            if configured_control
            else self.output / "control.json"
        )

        self._lock = threading.RLock()
        self._snapshot_lock = threading.Lock()
        self._shutdown_uncertainty = deque(maxlen=1)
        self._findings: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._runs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._counts: OrderedDict[str, int] = OrderedDict()
        self._policy: dict[str, Any] = {}
        self._sbom: dict[str, Any] = {"status": "initializing"}
        self._last_delivery: dict[str, Any] = {}

        self._max_findings = config.limit("beacon.security.findings.max", 4096)
        self._max_runs = config.limit("beacon.security.runs.max", 256)
        self._max_run_counter_bytes = config.limit(
            "beacon.security.runs.max.bytes", 8 * 1024 * 1024
        )
        self._run_counter_bytes = 0
        self._shared_run_counters: set[int] = set()
        self._sample_millis = (
            config.limit("beacon.security.findings.sample.seconds", 300) * 1000
        )
        self._max_finding_bytes = config.limit(
            "beacon.security.findings.max.bytes", 32 * 1024 * 1024
        )
        self._max_active = config.limit(
            "beacon.security.max.active.requests", 256
        )
        self._requests_per_second = config.limit(
            "beacon.security.requests-per-second", 1000
        )

        self._pause_generation = 0
        self._control_error = ""
        self._control_error_revision = ""
        self._applied_revision = ""
        self._snapshot_at = 0.0
        self._last_snapshot_failure_log = 0.0
        self._summary_at = 0.0
        self._started_at = _now()
        self._active = 0
        self._completed = 0
        self._finding_bytes = 0
        self._request_second = 0
        self._requests_this_second = 0
        self._snapshot_failures = 0
        self._findings_revision = 0
        self._runs_revision = 0
        self._written_revisions = {"findings": -1, "runs": -1}

    def enabled(self) -> bool:
        # Policies are replaced atomically and never mutated after publication.
        policy = self._policy
        try:
            return config.collection_configured() and not bool(
                policy.get("paused")
            )
        except BaseException:
            return False

    def paused(self) -> bool:
        return bool(self._policy.get("paused"))

    def count(self, name: str, amount: int = 1) -> None:
        key = str(name)
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + _number(amount)

    def record_delivery_loss(self, event: Mapping[str, Any] | None) -> None:
        """Invalidate the verification run carried by a lost security event."""

        if not isinstance(event, Mapping):
            return
        run = _mapping(event.get("run"))
        run_id = run.get("run_id") or event.get("run_id")
        if not run_id:
            return
        with self._lock:
            record = self._runs.get(str(run_id))
            if record is None:
                return
            self._increment_record(record, "delivery_loss", 1)
            self._increment_record(record, "incomplete_requests", 1)
            self._runs_revision += 1

    def shutdown_delivery_uncertain(self, reason: str) -> None:
        # Coalesce timeout diagnostics without waiting behind request bookkeeping.
        self._shutdown_uncertainty.append(reason)
        if self._lock.acquire(blocking=False):
            try:
                self._apply_shutdown_uncertainty()
            finally:
                self._lock.release()

    def _apply_shutdown_uncertainty(self) -> None:
        try:
            reason = self._shutdown_uncertainty.pop()
        except IndexError:
            return
        self._increment_count(reason)
        self._runs_revision += 1
        self._increment_count("delivery_failure")
        for record in self._runs.values():
            if _number(record.get("requests")) > 0:
                self._increment_record(record, "delivery_loss", 1)
                self._increment_record(record, "incomplete_requests", 1)

    def sbom(self, event: Mapping[str, Any]) -> None:
        if not isinstance(event, Mapping):
            return
        with self._lock:
            next_value = dict(self._sbom)
            next_value.update(
                _copy(
                    {
                        key: value
                        for key, value in event.items()
                        if key
                        not in {"dependencies", "part_index", "part_count"}
                    }
                )
            )
            if event.get("event_name") == "beacon.security.sbom.update_failed":
                next_value["status"] = "degraded"
            self._sbom = next_value

    def begin(self, state: Any) -> None:
        """Attach the current budget/run snapshot to a newly started request."""

        with self._lock:
            self._active += 1
            self._counts["requests_started"] = (
                self._counts.get("requests_started", 0) + 1
            )

            second = int(time.monotonic())
            if second != self._request_second:
                self._request_second = second
                self._requests_this_second = 0
            self._requests_this_second += 1
            request_budget = (
                self._active <= self._max_active
                and self._requests_this_second <= self._requests_per_second
            )

            generation = self._pause_generation
            try:
                setattr(state, "collection_generation", generation)
            except Exception:
                pass

            configured, configuration_status = self._coverage_configuration()
            paused = bool(self._policy.get("paused"))
            state.collection_enabled = bool(
                configured and not paused and request_budget
            )
            if not configured:
                state.collection_status = configuration_status
            elif paused:
                state.collection_status = "paused"
            elif not request_budget:
                state.collection_status = "budget_skipped"
            else:
                state.collection_status = "enabled"

            run = self._policy.get("run")
            if isinstance(run, Mapping) and _valid_until(
                run.get("expires_at")
            ):
                state.run = _copy(dict(run))
                run_id = str(_mapping(state.run).get("run_id", ""))
                record = self._runs.get(run_id)
                if record is not None:
                    self._increment_record(record, "active_requests", 1)
                    self._runs_revision += 1
            else:
                state.run = {}

    def end(self, state: Any) -> list[dict]:
        """Close a request, aggregate all occurrences, and return sampled output."""

        with self._lock:
            self._active = max(0, self._active - 1)
            self._completed += 1
            self._increment_count("requests_completed", 1)

            source_signatures = self._state_mapping(state, "source_signatures")
            risk_source_signatures = self._state_mapping(
                state, "risk_source_signatures"
            )
            sink_counts = self._state_mapping(state, "sink_counts")
            pending = self._state_pending(state)
            request = _safe_request(getattr(state, "request", {}))
            run_state = _copy(_mapping(getattr(state, "run", {})))

            source_count = _number(getattr(state, "source_count", 0))
            if source_count <= 0:
                source_count = sum(
                    max(0, _number(value))
                    for value in source_signatures.values()
                )
            if source_count:
                self._increment_count("sources", source_count)
                self._increment_count("requests_with_sources", 1)
            if any(_number(value) > 0 for value in sink_counts.values()):
                self._increment_count("requests_with_sinks", 1)
            for rule, amount in sink_counts.items():
                self._increment_count(
                    "sink." + str(rule), max(0, _number(amount))
                )
            if not bool(getattr(state, "collection_enabled", True)):
                self._increment_count(
                    "requests_"
                    + str(getattr(state, "collection_status", "unknown"))
                )

            generation = getattr(
                state, "collection_generation", self._pause_generation
            )
            collection_enabled = bool(
                getattr(state, "collection_enabled", True)
            )
            if collection_enabled and generation != self._pause_generation:
                self._call_gap(state, "collection_paused_during_request")
            gaps = self._state_gaps(state)
            incomplete = bool(
                getattr(state, "truncated", False)
                or gaps
                or (
                    collection_enabled
                    and (
                        not self.enabled()
                        or generation != self._pause_generation
                    )
                )
            )
            if incomplete:
                self._increment_count("requests_incomplete", 1)

            result: list[dict] = []
            now_millis = _now_millis()
            for original in pending:
                if not isinstance(original, Mapping):
                    continue
                finding_id = original.get("finding_id")
                finding_key = str(finding_id) if finding_id else ""
                finding = (
                    self._findings.get(finding_key) if finding_key else None
                )
                previous_sample = (
                    _number(finding.get("last_sample_millis"))
                    if finding
                    else 0
                )
                run_id = str(run_state.get("run_id", ""))
                sample = (
                    now_millis - previous_sample >= self._sample_millis
                    or run_id
                    != (
                        str(finding.get("sample_run_id", ""))
                        if finding
                        else ""
                    )
                )
                event = self._enrich_event(
                    original,
                    state,
                    request,
                    run_state,
                    incomplete,
                    gaps,
                    include_details=not finding_key or sample,
                )
                finding_id = event.get("finding_id")
                if not finding_id:
                    result.append(event)
                    continue
                if finding is None:
                    if len(self._findings) >= self._max_findings:
                        self._increment_count("finding_capacity_dropped", 1)
                        continue
                    finding = {
                        "finding_id": finding_key,
                        "rule": event.get("rule"),
                        "assessment": event.get("assessment"),
                        "validation": "unvalidated",
                        "sink": event.get("sink"),
                        "first_seen": event.get("observed_at"),
                        "occurrences": 0,
                        "last_sample_millis": 0,
                    }
                    self._findings[finding_key] = finding

                self._increment_record(finding, "occurrences", 1)
                finding["last_seen"] = event.get("observed_at")
                finding["last_trace_id"] = event.get("trace_id")
                finding["last_evidence_id"] = event.get("evidence_id")
                finding["last_run"] = _copy(run_state)
                finding["code"] = _copy(event.get("code"))
                finding["request"] = _copy(event.get("request", request))
                finding["component"] = _copy(event.get("component"))
                finding["triage"] = self._triage(finding_key)
                event["triage"] = _copy(finding["triage"])

                if sample:
                    finding["last_sample_millis"] = now_millis
                    finding["sample_run_id"] = run_id
                    representative = _copy(event)
                    estimate = _estimate(representative)
                    previous_bytes = _number(
                        finding.get("representative_bytes")
                    )
                    if (
                        estimate
                        > config.limit(
                            "beacon.security.evidence.max.bytes", 65536
                        )
                        or self._finding_bytes - previous_bytes + estimate
                        > self._max_finding_bytes
                    ):
                        for field in (
                            "propagation",
                            "ranges",
                            "sources",
                            "stack",
                        ):
                            representative.pop(field, None)
                        representative["truncated"] = True
                        representative["truncation_reason"] = (
                            "finding_snapshot_byte_budget"
                        )
                        estimate = _estimate(representative)
                        self._increment_count("finding_sample_truncated", 1)

                    if (
                        self._finding_bytes - previous_bytes + estimate
                        <= self._max_finding_bytes
                    ):
                        self._finding_bytes += estimate - previous_bytes
                        finding["representative_bytes"] = estimate
                        finding["representative"] = representative
                    else:
                        self._increment_count("finding_sample_dropped", 1)
                        finding.pop("representative", None)
                        self._finding_bytes = max(
                            0, self._finding_bytes - previous_bytes
                        )
                        finding["representative_bytes"] = 0
                    event["occurrences_total"] = finding["occurrences"]
                    result.append(event)
                else:
                    self._increment_count(
                        "representative_samples_suppressed", 1
                    )
                finding["dirty"] = True
                self._findings_revision += 1

            diagnostics = self._diagnostic_for_state(
                state,
                request,
                run_state,
                incomplete,
                gaps,
            )
            if diagnostics is not None:
                result.append(diagnostics)

            self._finish_run_request(
                state,
                pending,
                request,
                run_state,
                source_signatures,
                risk_source_signatures,
                sink_counts,
                incomplete,
                collection_enabled,
            )
            return result

    def tick(
        self,
        delivery: Mapping[str, Any] | None,
        emit: Callable[[dict], Any],
        force: bool = False,
        deadline: float | None = None,
    ) -> bool:
        # A forced flush may overlap the monitor. Keep file revisions ordered
        # without holding the lock used by request bookkeeping.
        acquired = (
            self._snapshot_lock.acquire(
                timeout=max(0.0, deadline - time.monotonic())
            )
            if force and deadline is not None
            else self._snapshot_lock.acquire(blocking=force)
        )
        if not acquired:
            return False
        try:
            self._tick(delivery, emit, force)
            return True
        finally:
            self._snapshot_lock.release()

    def _tick(
        self,
        delivery: Mapping[str, Any] | None,
        emit: Callable[[dict], Any],
        force: bool = False,
    ) -> None:
        """Apply control and write bounded snapshots.

        ``emit`` intentionally receives only the event.  The exporter owns
        the channel/context choice for ledger-generated records.
        """

        now_monotonic = time.monotonic()
        with self._lock:
            if not force and now_monotonic - self._snapshot_at < 1.0:
                return
            self._snapshot_at = now_monotonic
            self._last_delivery = _copy(dict(delivery or {}))

        local_output_enabled = config.flag(
            "beacon.security.local-output.enabled", False
        )
        if local_output_enabled:
            self._read_control()
        summaries: list[dict] = []
        with self._lock:
            self._apply_shutdown_uncertainty()
            now_millis = _now_millis()
            for run in self._runs.values():
                if run.get("status") == "active" and not _valid_until(
                    run.get("expires_at")
                ):
                    run["status"] = "draining"
                    run["expired"] = True
                    self._runs_revision += 1
                self._finish_if_idle(run)

            flush_due = force or (
                now_millis - int(self._summary_at * 1000)
                >= config.limit("beacon.security.findings.flush.seconds", 30)
                * 1000
            )
            for finding in self._findings.values():
                triage = self._triage(str(finding.get("finding_id", "")))
                if triage != finding.get("triage"):
                    finding["triage"] = triage
                    self._findings_revision += 1
                if flush_due and finding.pop("dirty", False):
                    summaries.append(
                        {
                            "event_name": "beacon.security.finding.summary",
                            "observed_at": _now(),
                            "identity": _copy(self.identity),
                            "finding_id": finding.get("finding_id"),
                            "occurrences_total": finding.get("occurrences", 0),
                            "first_seen": finding.get("first_seen"),
                            "last_seen": finding.get("last_seen"),
                            "triage": _copy(finding.get("triage")),
                        }
                    )
            if summaries:
                self._summary_at = time.time()

            findings_revision = self._findings_revision
            runs_revision = self._runs_revision
            findings_changed = (
                findings_revision != self._written_revisions["findings"]
            )
            runs_changed = runs_revision != self._written_revisions["runs"]
            finding_snapshot: list[dict] = []
            for finding in self._findings.values() if findings_changed else ():
                # Representatives and nested metadata are owned by the ledger
                # and replaced, never edited. Freeze just the mutable outer row.
                copied = dict(finding)
                for field in (
                    "dirty",
                    "last_sample_millis",
                    "sample_run_id",
                    "representative_bytes",
                ):
                    copied.pop(field, None)
                finding_snapshot.append(copied)

            run_snapshot: list[dict] = []
            for run in self._runs.values() if runs_changed else ():
                copied = dict(run)
                for field in (
                    "finding_counts",
                    "source_signatures",
                    "risk_source_signatures",
                ):
                    values = run.setdefault(field, {})
                    copied[field] = values
                    self._shared_run_counters.add(id(values))
                copied.pop("loss_start", None)
                copied.pop("snapshot_failures_start", None)
                run_snapshot.append(copied)

            delivery_copy = _copy(dict(delivery or {}))

        for summary in summaries:
            try:
                emit(event_record(summary, self.identity))
            except BaseException:
                self.count("request_completion_errors", 1)

        if not local_output_enabled:
            return
        try:
            if findings_changed:
                self._write_snapshot(
                    "findings.json",
                    self._envelope("findings", finding_snapshot),
                )
                with self._lock:
                    self._written_revisions["findings"] = findings_revision
            if runs_changed:
                self._write_snapshot(
                    "runs.json", self._envelope("runs", run_snapshot)
                )
                with self._lock:
                    self._written_revisions["runs"] = runs_revision
            self._write_snapshot("health.json", self.health(delivery_copy))
        except BaseException as error:
            should_emit = False
            with self._lock:
                self._snapshot_failures += 1
                now = time.monotonic()
                if now - self._last_snapshot_failure_log >= 30.0:
                    self._last_snapshot_failure_log = now
                    should_emit = True
                    count = self._snapshot_failures
            if should_emit:
                try:
                    emit(
                        {
                            "event_name": "beacon.security.snapshot.failed",
                            "error_type": type(error).__name__,
                            "count": count,
                            "observed_at": _now(),
                        }
                    )
                except BaseException:
                    pass

    def health(self, delivery: Mapping[str, Any] | None) -> dict:
        with self._lock:
            self._apply_shutdown_uncertainty()
            configured, configuration_status = self._coverage_configuration()
            paused = bool(self._policy.get("paused"))
            effective = configured and not paused
            delivery_loss = max(
                self._delivery_loss(delivery),
                self._counts.get("delivery_loss", 0)
                + self._counts.get("delivery_failure", 0),
            )
            if not configured:
                status = configuration_status
            elif paused:
                status = "paused"
            elif self._completed == 0:
                status = "in_flight" if self._active > 0 else "no_traffic"
            elif (
                self._counts.get("requests_incomplete", 0) > 0
                or self._counts.get("requests_budget_skipped", 0) > 0
                or self._counts.get("finding_capacity_dropped", 0) > 0
                or self._counts.get("run_counter_capacity_dropped", 0) > 0
                or delivery_loss > 0
            ):
                status = "incomplete"
            elif self._counts.get("requests_with_sources", 0) == 0:
                status = "no_source_observed"
            elif self._counts.get("requests_with_sinks", 0) == 0:
                status = "no_sink_observed"
            else:
                status = "observed"

            return {
                "schema_version": 1,
                "source": "beacon_security",
                "event_name": "beacon.security.health",
                "updated_at": _now(),
                "started_at": self._started_at,
                "identity": _copy(self.identity),
                "version": config.VERSION,
                "instrumentation_profile": self.profile,
                "status": status,
                "configured": configured,
                "effective": effective,
                "collection_status": (
                    "paused" if configured and paused else configuration_status
                ),
                "active_requests": self._active,
                "counts": dict(self._counts),
                "rule_status": self._rule_status(),
                "capabilities": [
                    "http_server",
                    "sql",
                    "command",
                    "http_client",
                    "file",
                    "modeled_string_propagation",
                ],
                "coverage_semantics": "observed_counters_not_vulnerability_recall",
                "coverage_scope": "modeled_calls_only",
                "sbom": _copy(self._sbom),
                "delivery": _copy(dict(delivery or {})),
                "control_revision": self._applied_revision,
                "control_error": self._control_error,
                "control_error_revision": self._control_error_revision,
                "snapshot_failures": self._snapshot_failures,
                "delivery_loss": delivery_loss,
                "retention": {
                    "findings_max": self._max_findings,
                    "runs_max": self._max_runs,
                    "run_counter_bytes_estimated": self._run_counter_bytes,
                    "run_counter_bytes_max": self._max_run_counter_bytes,
                    "representative_bytes_upper_bound": self._finding_bytes,
                    "representative_bytes_max": self._max_finding_bytes,
                },
                "pause_semantics": (
                    "collection_paused_existing_instrumentation_remains_loaded_restart_without_extension_to_unload"
                ),
            }

    def _increment_count(self, name: str, amount: int = 1) -> None:
        self._counts[name] = self._counts.get(name, 0) + _number(amount)

    @staticmethod
    def _coverage_configuration() -> tuple[bool, str]:
        """Return the configured coverage gate and its stable diagnostic status."""

        try:
            if not config.flag("beacon.security.enabled", False):
                return False, "disabled"
            if not config.prefixes("beacon.security.python.include"):
                return False, "unconfigured"
            if not config.supported_runtime():
                return False, "unsupported_runtime"
            if not config.collection_configured():
                return False, "unconfigured"
            return True, "enabled"
        except BaseException:
            # Configuration is instrumentation-owned state.  A malformed or
            # unavailable probe must disable collection rather than make a
            # request look like a fully covered negative verification.
            return False, "unconfigured"

    @staticmethod
    def _increment_record(
        record: dict[str, Any], name: str, amount: int = 1
    ) -> None:
        record[name] = _number(record.get(name)) + _number(amount)

    @staticmethod
    def _state_mapping(state: Any, name: str) -> dict[str, Any]:
        value = getattr(state, name, {})
        if callable(value):
            try:
                value = value()
            except Exception:
                value = {}
        return dict(value) if isinstance(value, Mapping) else {}

    @staticmethod
    def _state_pending(state: Any) -> list[Mapping[str, Any]]:
        value = getattr(state, "pending", [])
        if callable(value):
            try:
                value = value()
            except Exception:
                value = []
        return list(value) if isinstance(value, (list, tuple)) else []

    @staticmethod
    def _state_gaps(state: Any) -> list[str]:
        value = getattr(state, "gaps", set())
        if callable(value):
            try:
                value = value()
            except Exception:
                value = set()
        if isinstance(value, Mapping):
            value = value.keys()
        try:
            return sorted({str(item) for item in value})
        except TypeError:
            return []

    @staticmethod
    def _call_gap(state: Any, reason: str) -> None:
        try:
            state.gap(reason)
        except Exception:
            pass

    def _enrich_event(
        self,
        original: Mapping[str, Any],
        state: Any,
        request: dict,
        run: dict,
        incomplete: bool,
        gaps: list[str],
        include_details: bool = True,
    ) -> dict:
        # Sampling changes only the exported representative. The original
        # request evidence remains intact for run accounting and callers.
        event = _copy(
            dict(original)
            if include_details
            else {
                key: value
                for key, value in original.items()
                if key not in ("sources", "propagation", "ranges", "stack")
            }
        )
        if isinstance(self.identity, Mapping):
            event.update(_copy(self.identity))
        event["request"] = _copy(request)
        event["run"] = _copy(run)
        event["trace_availability"] = "not_guaranteed_by_trace_id"
        if event.get("evidence_id") is not None:
            event["occurrence_id"] = event.get("evidence_id")
        if event.get("trace_id") in (None, ""):
            event["trace_id"] = str(getattr(state, "trace_id", "") or "")
        if event.get("server_span_id") in (None, ""):
            event["server_span_id"] = str(
                getattr(state, "server_span_id", "") or ""
            )
        if incomplete:
            event["truncated"] = True
            event["coverage_gaps"] = list(gaps)
        event.setdefault("trace_flags", getattr(state, "trace_flags", 0))
        return event_record(event, self.identity)

    def _diagnostic_for_state(
        self,
        state: Any,
        request: dict,
        run: dict,
        incomplete: bool,
        gaps: list[str],
    ) -> dict | None:
        diagnostic: Any = None
        try:
            diagnostic = state.diagnostics()
        except Exception:
            diagnostic = None
        if not isinstance(diagnostic, Mapping):
            diagnostic = None
        if diagnostic is None and not incomplete:
            return None
        if diagnostic is None:
            diagnostic = {
                "event_name": "beacon.security.collection.incomplete",
                "truncated": True,
                "coverage_gaps": list(gaps),
            }
        result = self._enrich_event(
            diagnostic,
            state,
            request,
            run,
            incomplete,
            gaps,
        )
        result.setdefault(
            "event_name", "beacon.security.collection.incomplete"
        )
        result["collection_status"] = str(
            getattr(state, "collection_status", "")
        )
        return result

    def _finish_run_request(
        self,
        state: Any,
        pending: list[Mapping[str, Any]],
        request: dict,
        run_state: dict,
        source_signatures: Mapping[str, Any],
        risk_source_signatures: Mapping[str, Any],
        sink_counts: Mapping[str, Any],
        incomplete: bool,
        collection_enabled: bool,
    ) -> None:
        run_id = run_state.get("run_id")
        if run_id is None:
            return
        run = self._runs.get(str(run_id))
        if run is None:
            return

        self._runs_revision += 1
        self._increment_record(run, "active_requests", -1)
        self._increment_record(run, "requests", 1)
        source_values = {
            str(key): max(0, _number(value))
            for key, value in source_signatures.items()
            if _number(value) > 0
        }
        if source_values:
            self._increment_record(run, "source_requests", 1)
        for signature, amount in source_values.items():
            self._bounded_increment(
                run, "source_signatures", signature, amount
            )

        rule = str(run.get("rule", ""))
        if _number(sink_counts.get(rule, 0)) > 0:
            self._increment_record(run, "sink_requests", 1)
        if incomplete or not collection_enabled:
            self._increment_record(run, "incomplete_requests", 1)
        status_code = _number(request.get("status_code"), -1)
        if status_code >= 500:
            self._increment_record(run, "error_requests", 1)

        observed = 0
        event_source_counts: dict[str, int] = {}
        for event in pending:
            if (
                not isinstance(event, Mapping)
                or str(event.get("rule", "")) != rule
            ):
                continue
            if not event.get("finding_id"):
                continue
            observed += 1
            sources = event.get("sources")
            if isinstance(sources, (list, tuple)):
                for source in sources:
                    if not isinstance(source, Mapping):
                        continue
                    source_type = source.get("type")
                    source_name = source.get("name")
                    if source_type is not None and source_name is not None:
                        signature = f"{source_type}|{source_name}"
                        event_source_counts[signature] = (
                            event_source_counts.get(signature, 0) + 1
                        )
            finding_id = str(event.get("finding_id"))
            self._bounded_increment(run, "finding_counts", finding_id, 1)
        if observed:
            self._increment_record(run, "observations", observed)

        # Prefer the sources on evidence for this run's rule.  The state-level
        # risk map is a useful fallback for callers that provide a compact
        # event without its source list, but it can contain observations for
        # more than one rule in the same request.
        if event_source_counts:
            risk_values = event_source_counts
        else:
            risk_values = {
                str(key): max(0, _number(value))
                for key, value in risk_source_signatures.items()
                if _number(value) > 0
            }
        for signature, amount in risk_values.items():
            self._bounded_increment(
                run, "risk_source_signatures", signature, amount
            )

        if self.profile != str(run.get("instrumentation_profile", "")):
            self._increment_record(run, "incomplete_requests", 1)
        run["last_request"] = _copy(request)
        self._finish_if_idle(run)

    def _bounded_increment(
        self,
        run: dict[str, Any],
        field: str,
        key: str,
        amount: int,
    ) -> None:
        values = run.setdefault(field, {})
        if key not in values:
            size = 128 + sys.getsizeof(key)
            if (
                len(values) >= self._max_findings
                or self._run_counter_bytes + size > self._max_run_counter_bytes
            ):
                self._increment_record(run, "incomplete_requests", 1)
                self._increment_count("run_counter_capacity_dropped")
                return
            self._run_counter_bytes += size
        # Only tables changed after publication need copying. Closed historical
        # runs remain shared, even when another run forces a fresh snapshot.
        if id(values) in self._shared_run_counters:
            self._shared_run_counters.remove(id(values))
            values = dict(values)
            run[field] = values
        values[key] = _number(values.get(key)) + max(0, amount)

    def _finish_if_idle(self, run: dict[str, Any]) -> None:
        if (
            run.get("status") != "draining"
            or _number(run.get("active_requests")) != 0
        ):
            return
        run["delivery_loss"] = max(
            _number(run.get("delivery_loss")),
            0,
            self._loss_total() - _number(run.get("loss_start")),
        )
        run["snapshot_failures"] = max(
            0,
            self._snapshot_failures
            - _number(run.get("snapshot_failures_start")),
        )
        run["status"] = "closed"
        run["ended_at"] = _now()
        self._runs_revision += 1

    def _loss_total(self) -> int:
        value = max(
            self._delivery_loss(self._last_delivery),
            self._counts.get("delivery_loss", 0)
            + self._counts.get("delivery_failure", 0),
        )
        return (
            value
            + self._counts.get("finding_capacity_dropped", 0)
            + self._counts.get("run_counter_capacity_dropped", 0)
            + self._counts.get("request_completion_errors", 0)
        )

    @staticmethod
    def _delivery_loss(delivery: Mapping[str, Any] | None) -> int:
        values = _mapping(delivery)
        value = _number(
            values.get(
                "security_dropped",
                values.get("dropped"),
            )
        )
        counters = values.get("counters")
        if isinstance(counters, Mapping):
            value += sum(
                _number(amount)
                for name, amount in counters.items()
                if str(name).startswith("beacon.security.")
                and (
                    str(name).endswith("failed")
                    or str(name).endswith("record_truncated")
                )
            )
        return value

    def _read_control(self) -> None:
        if not self.control.exists():
            return
        attempted_revision = "unparsed"
        try:
            if self.control.stat().st_size > 256 * 1024:
                raise ValueError("control_byte_limit")
            with self.control.open("r", encoding="utf-8") as stream:
                next_policy = json.load(stream)
            if not isinstance(next_policy, Mapping):
                raise ValueError("control_object_required")
            revision = next_policy.get("revision", "")
            attempted_revision = str(revision)
            if not attempted_revision:
                raise ValueError("control_revision_required")
            with self._lock:
                if attempted_revision == self._applied_revision:
                    return
            if "paused" in next_policy and not isinstance(
                next_policy.get("paused"), bool
            ):
                raise ValueError("invalid_pause")
            self._validate_exceptions(next_policy.get("exceptions"))
            raw_run = next_policy.get("run", _MISSING)
            if raw_run is not _MISSING and raw_run is not None:
                self._validate_run(raw_run)

            with self._lock:
                new_run = (
                    dict(raw_run) if isinstance(raw_run, Mapping) else None
                )
                next_id = str(new_run.get("run_id")) if new_run else ""
                if new_run is not None:
                    existing = self._runs.get(next_id)
                    if (
                        existing is not None
                        and existing.get("status") != "active"
                    ):
                        raise ValueError("run_id_already_closed")
                    if existing is None and len(self._runs) >= self._max_runs:
                        raise ValueError("run_capacity_restart_or_archive")

                for old in self._runs.values():
                    if (
                        old.get("status") == "active"
                        and str(old.get("run_id")) != next_id
                    ):
                        old["status"] = "draining"
                        self._finish_if_idle(old)

                if new_run is not None and next_id not in self._runs:
                    paused = bool(next_policy.get("paused"))
                    configured, configuration_status = (
                        self._coverage_configuration()
                    )
                    run = _copy(new_run)
                    run.update(
                        {
                            "status": "active",
                            "started_at": _now(),
                            "identity": _copy(self.identity),
                            "rule_enabled": self._rule_status().get(
                                run.get("rule"), False
                            ),
                            "collection_enabled": configured and not paused,
                            "collection_status": (
                                "paused"
                                if configured and paused
                                else configuration_status
                            ),
                            "loss_start": self._loss_total(),
                            "snapshot_failures_start": self._snapshot_failures,
                            "instrumentation_profile": self.profile,
                            "finding_counts": {},
                            "source_signatures": {},
                            "risk_source_signatures": {},
                            "delivery_loss": 0,
                            "snapshot_failures": 0,
                        }
                    )
                    for key in (
                        "requests",
                        "source_requests",
                        "sink_requests",
                        "observations",
                        "incomplete_requests",
                        "error_requests",
                        "active_requests",
                    ):
                        run[key] = 0
                    self._runs[next_id] = run

                old_paused = bool(self._policy.get("paused"))
                new_paused = bool(next_policy.get("paused"))
                if old_paused != new_paused:
                    self._pause_generation += 1
                self._policy = _copy(dict(next_policy))
                self._runs_revision += 1
                self._applied_revision = attempted_revision
                self._control_error = ""
                self._control_error_revision = ""
        except BaseException as error:
            with self._lock:
                self._control_error_revision = attempted_revision
                self._control_error = _bounded_error(error)

    def _validate_run(self, raw_run: Any) -> None:
        if not isinstance(raw_run, Mapping):
            raise ValueError("invalid_run")
        for field in ("run_id", "case_id", "rule", "expires_at"):
            if not _non_empty_text(raw_run.get(field)):
                raise ValueError("missing_run_" + field)
        if not _valid_until(raw_run.get("expires_at")):
            raise ValueError("invalid_run_expiry_or_rule")
        if str(raw_run.get("rule")) not in self._rule_status():
            raise ValueError("invalid_run_expiry_or_rule")
        conditions = raw_run.get("conditions")
        if not isinstance(conditions, Mapping):
            raise ValueError("missing_run_conditions")
        for field in ("suite", "fixture"):
            if not _non_empty_text(conditions.get(field)):
                raise ValueError("missing_condition_" + field)
        expected = conditions.get("expected_requests")
        if (
            isinstance(expected, bool)
            or not isinstance(expected, (int, float))
            or expected <= 0
        ):
            raise ValueError("expected_requests_required")

    @staticmethod
    def _validate_exceptions(value: Any) -> None:
        if value is None:
            return
        if not isinstance(value, list) or len(value) > 128:
            raise ValueError("invalid_exceptions")
        for item in value:
            if not isinstance(item, Mapping):
                raise ValueError("invalid_exception")
            scope = item.get("scope")
            if not isinstance(scope, Mapping):
                raise ValueError("exception_scope_required")
            for field in ("application_id", "finding_id"):
                if not _non_empty_text(scope.get(field)):
                    raise ValueError("exception_scope_required")
            if not _non_empty_text(item.get("reason")):
                raise ValueError("exception_reason_required")
            if item.get("decision") not in ("accepted_risk", "false_positive"):
                raise ValueError("invalid_exception_decision")
            try:
                _parse_time(item.get("expires_at"))
            except (TypeError, ValueError, OverflowError):
                raise ValueError("exception_expiry_required")

    def _triage(self, finding_id: str) -> dict[str, Any]:
        exceptions = self._policy.get("exceptions")
        if isinstance(exceptions, list):
            for item in exceptions:
                if not isinstance(item, Mapping):
                    continue
                scope = _mapping(item.get("scope"))
                if (
                    self.identity.get("application_id")
                    == scope.get("application_id")
                    and finding_id == scope.get("finding_id")
                    and _valid_until(item.get("expires_at"))
                ):
                    return _copy(dict(item))
        return {"decision": "unreviewed"}

    @staticmethod
    def _rule_status() -> dict[str, bool]:
        return {
            rule: config.flag(f"beacon.security.rules.{rule}.enabled", True)
            for rule in config.RULES
        }

    def _envelope(self, key: str, values: list[dict]) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "source": "beacon_security",
            "updated_at": _now(),
            "identity": _copy(self.identity),
            key: values,
        }

    def _write_snapshot(self, name: str, value: Mapping[str, Any]) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        destination = self.output / name
        fd, temporary_name = tempfile.mkstemp(
            prefix=".security-", suffix=".json", dir=str(self.output)
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                encoded = json.dumps(
                    value,
                    ensure_ascii=False,
                    indent=2,
                    default=_json_default,
                ).encode("utf-8")
                stream.write(encoded)
                stream.write(b"\n")
                stream.flush()
            os.replace(temporary_name, destination)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
