"""The small, versioned Security payload sent through OTel Logs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .schema import SCHEMA_VERSION

FINDING = "beacon.security.finding"
INVENTORY = "beacon.security.sbom.inventory"


def _present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _fields(value: Any, names: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {name: value[name] for name in names if _present(value.get(name))}


def project_event(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """Drop internal bookkeeping and all retired event types at the export edge."""

    name = event.get("event_name")
    if name not in (FINDING, INVENTORY):
        return None
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": "beacon_security" if name == FINDING else "beacon_security_sbom",
        "event_name": name,
        "instance_id": event["instance_id"],
        "observed_at": event["observed_at"],
    }
    if name == INVENTORY:
        result["dependencies"] = event["dependencies"]
        result["started_at"] = event["started_at"]
        result["uptime_ms"] = event["uptime_ms"]
        for field in ("part_index", "part_count"):
            if field in event:
                result[field] = event[field]
        return result

    for field in ("finding_id", "fingerprint_version", "rule"):
        result[field] = event[field]
    result["occurrence_id"] = event["occurrence_id"]
    result["sink"] = _fields(
        event.get("sink"),
        (
            "function",
            "role",
            "location",
            "operation",
            "path_role",
            "input_part",
        ),
    )
    evidence = event.get("attack_evidence")
    result["attack_evidence"] = {
        "status": evidence.get("status", "unknown") if isinstance(evidence, Mapping) else "unknown",
        "reason": evidence.get("reason", "analysis_unavailable")
        if isinstance(evidence, Mapping)
        else "analysis_unavailable",
    }
    result["evidence_sampled"] = bool(event.get("evidence_sampled", True))
    result["collection_complete"] = bool(
        event.get(
            "collection_complete",
            not event.get("coverage_gaps") and not event.get("truncated"),
        )
    )
    optional = (
        "trace_id",
        "server_span_id",
        "precision",
        "evidence_sample_reason",
        "truncation_reason",
        "sources",
        "propagation",
        "ranges",
        "stack",
        "coverage_gaps",
        "run",
        "triage",
    )
    result.update(_fields(event, optional))
    current_span = event.get("current_span_id")
    if _present(current_span) and current_span != event.get("server_span_id"):
        result["current_span_id"] = current_span
    request = _fields(event.get("request"), ("method", "route", "status_code", "error_type"))
    if request:
        result["request"] = request
    component = event.get("component")
    if isinstance(component, Mapping) and _present(component.get("name")):
        result["component"] = {
            "name": component["name"],
            "version": component.get("version", ""),
        }
        if _present(component.get("hash")):
            result["component"]["hash"] = component["hash"]
    if event.get("truncated"):
        result["truncated"] = True
    if result["evidence_sampled"]:
        result.pop("evidence_sample_reason", None)
    else:
        result.setdefault("evidence_sample_reason", "interval")
    return result
