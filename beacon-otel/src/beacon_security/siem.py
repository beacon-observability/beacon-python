from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

PROFILE = "beacon-security-siem-v1"
CORRELATION_FIELDS = (
    "instance_id",
    "trace_id",
    "span_id",
    "trace_flags",
)


def project(raw: str, resource: Mapping[str, Any]) -> dict[str, Any]:
    """Project an already validated runtime v2 payload without rewriting it.

    Request principal and client address are unavailable at this boundary.
    Application headers are deliberately not used as trusted enrichment.
    """
    body = json.loads(raw)
    inventory = body["event_name"] == "beacon.security.sbom.inventory"
    if inventory:
        identity = [
            body["source"],
            body["event_name"],
            body["instance_id"],
            body["observed_at"],
            str(body.get("part_index", 0)),
        ]
        encoded = json.dumps(
            identity, ensure_ascii=False, separators=(",", ":")
        )
        event_id = (
            "inventory-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        )
    else:
        event_id = body["occurrence_id"]

    def text(key: str) -> str:
        value = resource.get(key)
        return value if isinstance(value, str) and value.strip() else ""

    result = {
        "time": body["observed_at"],
        "event_id": event_id,
        "event_class": "software_inventory_info"
        if inventory
        else "security_finding",
        "source": body["source"],
        "service": text("service.name"),
        "tenant_id": text("tenant.id") or "default",
        "actor": "",
        "ip": "",
        "action": "inventory_snapshot" if inventory else body["rule"],
        "target": body["instance_id"] if inventory else body["finding_id"],
        "target_type": "process" if inventory else "finding",
        "outcome": "success" if inventory else "unknown",
        "status": "info",
        "severity": "informational",
        "message": raw,
    }
    result.update(
        {key: body[key] for key in CORRELATION_FIELDS if key in body}
    )
    return result


def encode(raw: bytes, identity: Mapping[str, Any]) -> bytes:
    return json.dumps(
        project(raw.decode("utf-8"), identity.get("service", {})),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
