import json
from typing import Any

from . import config
from .schema import event_record


def dependency_snapshot(event, records, identity):
    unique = {}
    for record in records:
        if record.get("type") != "library" or not any(
            item.get("name") == "beacon:security:sbom:loaded"
            and item.get("value") == "true"
            for item in record.get("properties", ())
        ):
            continue
        dependency = {
            "name": record["name"],
            "version": record.get("version", ""),
        }
        if not record.get("purl") or not record.get("version"):
            digest = next(
                (
                    item["content"]
                    for item in record.get("hashes", ())
                    if item.get("alg") == "SHA-256"
                ),
                None,
            )
            if digest:
                dependency["hash"] = digest
        unique[json.dumps(dependency, sort_keys=True)] = dependency
    rows = [unique[key] for key in sorted(unique)]
    envelope = event_record(
        {
            **event,
            "event_name": "beacon.security.sbom.snapshot",
            "component_count": len(rows),
            "part_index": 2147483647,
            "part_count": 2147483647,
            "dependencies": [],
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
    overhead = len(encode(envelope))
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
