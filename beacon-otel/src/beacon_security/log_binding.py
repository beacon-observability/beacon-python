"""Bind logical Security events to native OTel log metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

PROFILE = "beacon-security-log-body-v1"
_TIME = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z", re.ASCII
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def event_time(value: str) -> int:
    """Convert UTC event time exactly, rejecting unset and overflowing times."""
    match = _TIME.fullmatch(value)
    if match is None:
        raise ValueError("invalid_security_event_time")
    whole = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc
    )
    delta = whole - _EPOCH
    nanos = (delta.days * 86400 + delta.seconds) * 1_000_000_000
    nanos += int((match[2] or "").ljust(9, "0"))
    if not 0 < nanos <= 9223372036854775807:
        raise ValueError("security_event_time_out_of_range")
    return nanos


def attributes(event: Mapping[str, Any]) -> dict[str, str]:
    if event["event_name"] == "beacon.security.sbom.inventory":
        identity = [
            event["source"],
            event["event_name"],
            event["instance_id"],
            event["observed_at"],
            str(event.get("part_index", 0)),
        ]
        raw = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
        event_id = (
            "inventory-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
        )
    else:
        event_id = event["occurrence_id"]
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("invalid_security_event_id")
    return {
        "event_id": event_id,
        "source": event["source"],
        "event.name": event["event_name"],
    }


def payload(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in event.items()
        if key not in ("observed_at", "occurrence_id")
    }


def encode(event: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload(event), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def metadata_size(event: Mapping[str, Any]) -> int:
    """Conservatively reserve per-record native fields and attribute encoding.

    The 128-byte allowance covers timestamp fields, severity, event name,
    trace/span IDs, and protobuf tags/lengths. Resource and request batching
    remain the existing OTLP exporter's responsibility.
    """
    return 128 + len(
        json.dumps(
            attributes(event), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    )


def record_size(body: bytes, event: Mapping[str, Any]) -> int:
    return len(body) + metadata_size(event)
