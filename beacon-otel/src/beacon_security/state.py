from __future__ import annotations

import datetime as dt
import threading
import uuid
from dataclasses import replace
from itertools import islice

from opentelemetry import trace

from . import config
from .locations import call_stack, caller_location
from .schema import event_record, finding_fingerprint, sink_fields
from .tracking import ByteBudget, Mark, reference, shared_scalar


def stamp() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class SecurityState:
    def __init__(self, identity=None, budget=None, metadata=None):
        self.identity = identity or config.identity()
        self.budget = budget or ByteBudget()
        self.lock = threading.RLock()
        self.request = dict(metadata or {})
        self.started_at = stamp()
        self.request.setdefault("started_at", self.started_at)
        self.request.setdefault("route_status", "unavailable")
        self.run = {}
        self.collection_enabled = True
        self.collection_status = "enabled"
        self.collection_generation = 0
        self.closed = False
        self.runtime = None
        self.truncated = False
        self.trace_id = ""
        self.server_span_id = ""
        self.server_span = None
        self.trace_flags = 0
        self.pending = []
        self.source_signatures = {}
        self.risk_source_signatures = {}
        self.sink_counts = {}
        self.source_count = 0
        self.gaps = set()
        self.sources = {}
        self.nodes = {}
        self.objects = {}
        self.ambiguous = set()
        self.ambiguous_sources = set()
        self.seen = set()
        self.sites = set()
        self.retained_bytes = 0
        self.tracking_exhausted = False
        self.max_objects = config.limit("beacon.security.max.objects", 4096)
        self.max_bytes = config.limit(
            "beacon.security.max.tracked.bytes", 1024 * 1024
        )
        self.max_nodes = config.limit("beacon.security.max.nodes", 8192)
        self.max_marks = config.limit(
            "beacon.security.max.marks-per-object", 64
        )
        self.max_findings = config.limit("beacon.security.max.findings", 32)
        self.bind_span(trace.get_current_span())

    def bind_span(self, span):
        context = span.get_span_context()
        if not context.is_valid:
            return
        with self.lock:
            if (
                not self.server_span_id
                or getattr(span, "kind", None) == trace.SpanKind.SERVER
            ):
                self.trace_id = format(context.trace_id, "032x")
                self.server_span_id = format(context.span_id, "016x")
                self.server_span = span
                self.trace_flags = int(context.trace_flags)

    def gap(self, reason):
        with self.lock:
            if not self.closed and len(self.gaps) < 32:
                self.gaps.add(str(reason)[:256])

    def _limit(self, reason):
        self.truncated = True
        self.gap(reason)

    def marks(self, value) -> tuple[Mark, ...]:
        with self.lock:
            if (
                self.closed
                or not self.collection_enabled
                or id(value) in self.ambiguous
            ):
                return ()
            entry = self.objects.get(id(value))
            if entry is None or entry.value() is not value:
                return ()
            if not self.ambiguous_sources:
                return entry.marks
            return tuple(
                mark
                for mark in entry.marks
                if mark.source_id not in self.ambiguous_sources
            )

    def put(self, value, marks):
        with self.lock:
            if (
                self.closed
                or not self.collection_enabled
                or value is None
                or id(value) in self.ambiguous
            ):
                return
            key = id(value)
            previous = self.objects.get(key)
            if previous is not None and previous.value() is not value:
                self._remove(key)
                previous = None
            marks = tuple(marks)
            if not marks:
                self._remove(key)
                return
            if len(marks) > self.max_marks:
                self._limit("marks_per_object_limit")
                marks = marks[: self.max_marks]
            if type(value) in (str, bytes, bytearray):
                size = len(value)
                unit = "unicode_code_point" if type(value) is str else "byte"
                if any(
                    m.start < 0
                    or m.end is None
                    or m.end > size
                    or m.start >= size
                    or m.end <= m.start
                    or m.unit != unit
                    for m in marks
                ):
                    marks = tuple(
                        replace(
                            m,
                            start=max(0, m.start),
                            end=min(size, size if m.end is None else m.end),
                            unit=unit,
                        )
                        for m in marks
                        if m.start < size
                        and (m.end is None or m.end > m.start)
                    )
                if not previous and shared_scalar(value):
                    self.gap("shared_scalar_identity")
                    return
            if not marks:
                self._remove(key)
                return
            if previous is not None:
                previous.marks = marks
                return
            if self.tracking_exhausted:
                return
            if len(self.objects) >= self.max_objects:
                self._prune_dead()
            if len(self.objects) >= self.max_objects:
                self.tracking_exhausted = True
                self._limit("object_count_limit")
                return
            entry = reference(value, marks)
            if entry is None:
                self.gap("untrackable_carrier")
                return
            if self.retained_bytes + entry.size > self.max_bytes:
                self.tracking_exhausted = True
                self._limit("request_retained_byte_limit")
                return
            if not self.budget.reserve(entry.size):
                self.tracking_exhausted = True
                self._limit("process_retained_byte_limit")
                return
            self.objects[key] = entry
            self.retained_bytes += entry.size

    def _remove(self, key):
        previous = self.objects.pop(key, None)
        if previous is not None:
            self.retained_bytes -= previous.size
            self.budget.release(previous.size)

    def _prune_dead(self):
        for key, value in list(self.objects.items()):
            if value.weak and value.value() is None:
                self._remove(key)

    def capture(self, value, kind, name, location=""):
        self.bind_span(trace.get_current_span())
        location = location or caller_location()
        visited = set()
        count = 0

        def visit(item, field, depth):
            nonlocal count
            if self.closed or not self.collection_enabled:
                return
            count += 1
            if depth > 8 or count > 512:
                self.gap("source_traversal_limit")
                return
            if type(item) in (str, bytes, bytearray):
                self.source(item, kind, field, location)
                return
            if id(item) in visited:
                return
            visited.add(id(item))
            if type(item) is dict:
                if len(item) > 128:
                    self.gap("source_traversal_limit")
                for key, child in islice(item.items(), 128):
                    if type(key) is str:
                        visit(child, f"{field}.{key[:128]}", depth + 1)
            elif type(item) in (list, tuple):
                if len(item) > 128:
                    self.gap("source_traversal_limit")
                for index, child in enumerate(item[:128]):
                    visit(child, f"{field}[{index}]", depth + 1)
            else:
                cls = type(item)
                fields = getattr(cls, "model_fields", None)
                if isinstance(fields, dict) and cls.__module__ != "builtins":
                    data = getattr(item, "__dict__", {})
                    for key in islice(fields, 128):
                        if key in data:
                            visit(data[key], f"{field}.{key}", depth + 1)
                    from .propagation import input_marks

                    model_marks = input_marks(self, islice(data.values(), 128))
                    if model_marks:
                        self.put(
                            item,
                            self.derive(
                                model_marks,
                                "model.fields",
                                location,
                                exact=False,
                            ),
                        )
                elif item is not None:
                    # Numeric/custom bound values have no safe string/bytes
                    # identity model. Do not silently certify their later
                    # conversion as a fully covered negative flow.
                    self.gap("unmodeled_source_value:" + cls.__name__)

        with self.lock:
            visit(value, str(name)[:256], 0)
        return value

    def source(self, value, kind, name, location=""):
        with self.lock:
            if (
                self.closed
                or not self.collection_enabled
                or type(value) not in (str, bytes, bytearray)
                or not value
            ):
                return value
            signature = f"{kind}|{str(name)[:256]}"
            if (
                signature not in self.source_signatures
                and len(self.source_signatures) >= self.max_nodes
            ):
                self._limit("source_signature_limit")
                return value
            self.source_signatures[signature] = 1
            previous = self.marks(value)
            if previous:
                signatures = {
                    f"{self.sources[m.source_id]['type']}|{self.sources[m.source_id]['name']}"
                    for m in previous
                }
                if signature in signatures:
                    return value
                self.ambiguous.add(id(value))
                self.ambiguous_sources.update(
                    mark.source_id for mark in previous
                )
                # Keep the budgeted strong reference until request teardown;
                # an ambiguous object's id must not be reused by another value.
                self.pending[:] = [
                    event
                    for event in self.pending
                    if not any(
                        source["id"] in self.ambiguous_sources
                        for source in event["sources"]
                    )
                ]
                self.gap("source_identity_ambiguous")
                return value
            if self.tracking_exhausted:
                return value
            if len(self.nodes) >= self.max_nodes:
                self._limit("propagation_node_limit")
                return value
            self.source_count += 1
            source_id = f"src-{self.source_count}"
            self.sources[source_id] = {
                "id": source_id,
                "type": kind,
                "name": str(name)[:256],
                "location": location[:1024],
                "value_type": "string" if type(value) is str else "bytes",
                "value_length": len(value),
            }
            node = len(self.nodes) + 1
            self.nodes[node] = {
                "id": node,
                "parent_id": None,
                "source_id": source_id,
                "operation": "source",
                "location": location[:1024],
            }
            self.put(
                value,
                (
                    Mark(
                        source_id,
                        node,
                        0,
                        len(value),
                        True,
                        "unicode_code_point" if type(value) is str else "byte",
                    ),
                ),
            )
            return value

    def derive(
        self,
        marks,
        operation,
        location="",
        shift=0,
        start=0,
        end=None,
        exact=True,
        unit=None,
    ):
        with self.lock:
            if self.closed or not self.collection_enabled:
                return ()
            result = []
            for mark in marks:
                if mark.source_id in self.ambiguous_sources:
                    continue
                if (
                    len(result) >= self.max_marks
                    or len(self.nodes) >= self.max_nodes
                ):
                    self._limit("propagation_node_limit")
                    break
                left = max(mark.start, start)
                right = (
                    mark.end
                    if end is None
                    else end
                    if mark.end is None
                    else min(end, mark.end)
                )
                if exact and right is not None and left >= right:
                    continue
                node = len(self.nodes) + 1
                self.nodes[node] = {
                    "id": node,
                    "parent_id": mark.node_id,
                    "source_id": mark.source_id,
                    "operation": operation[:256],
                    "location": location[:1024],
                }
                result.append(
                    Mark(
                        mark.source_id,
                        node,
                        left + shift if exact else 0,
                        None if not exact or right is None else right + shift,
                        exact and mark.exact,
                        unit or mark.unit,
                    )
                )
            return tuple(result)

    def propagate(self, result, inputs, operation, location="", exact=False):
        marks = tuple(m for value in inputs for m in self.marks(value))
        if marks:
            self.put(
                result, self.derive(marks, operation, location, exact=exact)
            )
        return result

    def sink(
        self, rule, function, role, value=None, *, marks=None, location=""
    ):
        with self.lock:
            if self.closed or not self.collection_enabled:
                return None
            location = location or caller_location()
            site = (rule, function, location)
            if site not in self.sites:
                if len(self.sites) >= self.max_nodes:
                    self._limit("sink_site_limit")
                else:
                    self.sites.add(site)
                    self.sink_counts[rule] = self.sink_counts.get(rule, 0) + 1
            marks = tuple(
                mark
                for mark in (self.marks(value) if marks is None else marks)
                if mark.source_id not in self.ambiguous_sources
            )
            if not marks or not config.flag(
                f"beacon.security.rules.{rule}.enabled"
            ):
                return None
            sources = {
                m.source_id: self.sources[m.source_id]
                for m in marks
                if m.source_id in self.sources
            }
            source_signature = sorted(
                f"{s['type']}|{s['name']}" for s in sources.values()
            )
            sink = sink_fields(rule, role, function[:256], location[:1024])
            fingerprint = finding_fingerprint(
                self.identity["application_id"],
                "python",
                rule,
                sink,
                source_signature,
            )
            key = fingerprint
            if key in self.seen:
                return None
            if len(self.pending) >= self.max_findings:
                self._limit("request_finding_limit")
                return None
            self.seen.add(key)
            self.bind_span(trace.get_current_span())
            for signature in source_signature:
                self.risk_source_signatures[signature] = 1
            graph = {}
            for mark in marks:
                node_id = mark.node_id
                while node_id is not None and node_id not in graph:
                    if len(graph) >= 128:
                        self._limit("evidence_graph_limit")
                        break
                    node = self.nodes.get(node_id)
                    if node is None:
                        break
                    graph[node_id] = dict(node)
                    node_id = node["parent_id"]
            exact = all(m.exact for m in marks)
            context = trace.get_current_span().get_span_context()
            event = event_record(
                {
                    "schema_version": 1,
                    "source": "beacon_security",
                    "event_name": "beacon.security.finding",
                    "evidence_id": "ev-" + str(uuid.uuid4()),
                    "finding_id": fingerprint,
                    "fingerprint_version": 1,
                    "rule": rule,
                    "assessment": "candidate_risk"
                    if rule in ("sql_injection", "command_injection")
                    or role in ("executable", "destination_address")
                    else "observation",
                    "validation": "unvalidated",
                    "severity": "unassigned",
                    "confidence": "modeled_flow"
                    if exact
                    else "conservative_flow",
                    "observed_at": stamp(),
                    "execution_observation": "invocation_attempt",
                    "precision": "exact" if exact else "conservative",
                    "trace_id": self.trace_id,
                    "server_span_id": self.server_span_id,
                    "trace_flags": self.trace_flags,
                    "current_span_id": format(context.span_id, "016x")
                    if context.is_valid
                    and format(context.trace_id, "032x") == self.trace_id
                    else "",
                    "sources": list(sources.values()),
                    "propagation": list(graph.values()),
                    "ranges": [
                        {
                            "source_id": m.source_id,
                            "start": m.start,
                            "end": m.end,
                            "exact": m.exact,
                            "unit": m.unit,
                        }
                        for m in marks
                    ],
                    "sink": sink,
                    "truncated": self.truncated,
                    "coverage": "modeled_calls_only",
                    "coverage_gaps": sorted(self.gaps),
                    "runtime": config.runtime_identity(),
                    "stack": call_stack(),
                },
                self.identity,
            )
            self.pending.append(event)
            return event

    def diagnostics(self):
        if not self.gaps and not self.truncated and self.collection_enabled:
            return None
        return {
            "event_name": "beacon.security.collection.incomplete",
            "trace_id": self.trace_id,
            "server_span_id": self.server_span_id,
            "trace_flags": self.trace_flags,
            "truncated": self.truncated,
            "coverage_gaps": sorted(self.gaps),
            "collection_status": self.collection_status,
            "counts": {
                "objects": len(self.objects),
                "retained_bytes": self.retained_bytes,
                "nodes": len(self.nodes),
                "sources": self.source_count,
                "findings": len(self.pending),
            },
        }

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            self.runtime = None
            self.server_span = None
            self.budget.release(self.retained_bytes)
            self.retained_bytes = 0
            self.objects.clear()
            self.nodes.clear()
            self.sources.clear()
            self.pending.clear()
            self.ambiguous.clear()
            self.ambiguous_sources.clear()
