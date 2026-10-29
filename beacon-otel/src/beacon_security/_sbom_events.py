import hashlib
import json
from typing import Any

from . import config
from .schema import event_record


def component_identity(name: str, version: str) -> dict[str, str]:
    pair = json.dumps(
        [name, version], ensure_ascii=False, separators=(",", ":")
    )
    return {
        "name": name,
        "version": version,
        "hash": hashlib.md5(
            pair.encode("utf-8"), usedforsecurity=False
        ).hexdigest(),
    }


def dependency_snapshot(event, records, identity):
    unique = {}
    for record in records:
        if record.get("type") != "library" or not any(
            item.get("name") == "beacon:security:sbom:loaded"
            and item.get("value") == "true"
            for item in record.get("properties", ())
        ):
            continue
        dependency = component_identity(
            record["name"], record.get("version", "")
        )
        unique[json.dumps(dependency, sort_keys=True)] = dependency
    rows = [unique[key] for key in sorted(unique)]
    envelope = event_record(
        {
            **event,
            "event_name": "beacon.security.sbom.inventory",
        },
        identity,
    )

    def encode(value: Any) -> bytes:
        return json.dumps(
            value, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    maximum = min(
        config.limit("beacon.security.evidence.max.bytes", 65536),
        config.limit("beacon.security.export.sbom.bytes-per-second", 262144),
    )
    envelope = {
        key: envelope[key]
        for key in (
            "schema_version",
            "source",
            "event_name",
            "instance_id",
            "observed_at",
            "started_at",
            "uptime_ms",
        )
    }
    whole = {**envelope, "dependencies": rows}
    if len(encode(whole)) <= maximum:
        return [whole]
    split_envelope = {
        **envelope,
        "dependencies": [],
        "part_index": 2147483647,
        "part_count": 2147483647,
    }
    overhead = len(encode(split_envelope))
    if overhead > maximum:
        raise ValueError("dependency_snapshot_envelope_exceeds_budget")
    chunks, size = [[]], overhead
    for row in rows:
        length = len(encode(row))
        if overhead + length > maximum:
            raise ValueError("dependency_snapshot_item_exceeds_budget")
        chunk = chunks[-1]
        if size + length + bool(chunk) > maximum:
            chunk = []
            chunks.append(chunk)
            size = overhead
        size += length + bool(chunk)
        chunk.append(row)
    return [
        {
            **envelope,
            "dependencies": chunk,
            "part_index": index,
            "part_count": len(chunks),
        }
        for index, chunk in enumerate(chunks)
    ]
