"""Build-SBOM import and CycloneDX document helpers.

The helpers are methods on a small mixin so ``SbomInventory`` keeps the same
private method surface while the build declaration and document concerns stay
separate from runtime observation and publication.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from . import config
from ._sbom_metadata import (
    _MAX_DECLARED_COMPONENTS,
    _MAX_LICENSES,
    _MAX_TEXT,
    _bounded,
    _canonical_distribution_name,
    _iso_now,
    _property,
    _pypi_purl,
    _sha256,
)


class _BuildSupport:
    """Mixin for build declaration merging and CycloneDX document assembly."""

    def _application_record(self) -> dict[str, Any]:
        service = (
            self.identity.get("service")
            if isinstance(self.identity.get("service"), dict)
            else {}
        )
        name = (
            _bounded(service.get("service.name"), 512) or self.application_id
        )
        version = _bounded(service.get("service.version"), 256)
        record: dict[str, Any] = {
            "type": "application",
            "bom-ref": self.application_id,
            "name": name,
        }
        if version:
            record["version"] = version
        properties: list[dict[str, str]] = []
        for prefix, values in (
            ("otel:", service),
            ("runtime:", self.identity.get("runtime", {})),
        ):
            if not isinstance(values, dict):
                continue
            for key, value in sorted(values.items()):
                if isinstance(value, (str, int, float, bool)) and _bounded(
                    value, 512
                ):
                    properties.append(
                        {
                            "name": prefix + _bounded(key, 256),
                            "value": _bounded(value, 512),
                        }
                    )
        if properties:
            record["properties"] = properties[:64]
        return record

    @staticmethod
    def _tools(distributions: Iterable[Any]) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add(name: str, version: str, purl: str = "") -> None:
            key = _canonical_distribution_name(name)
            if not key or key in seen:
                return
            seen.add(key)
            value: dict[str, Any] = {
                "type": "application",
                "name": _bounded(name, 512),
            }
            if version:
                value["version"] = _bounded(version, 256)
            if purl:
                value["purl"] = purl
            tools.append(value)

        add("Beacon Security", getattr(config, "VERSION", "unknown"))
        for distribution in sorted(
            distributions,
            key=lambda item: (item.normalized_name, item.version),
        ):
            if not distribution.infrastructure:
                continue
            add(
                distribution.name or distribution.normalized_name,
                distribution.version,
                _pypi_purl(distribution.name, distribution.version),
            )
        return tools

    def _release_id(
        self, records: dict[str, dict[str, Any]]
    ) -> tuple[str, str]:
        digests = sorted(
            str(entry["hashes"][0]["content"])
            for entry in records.values()
            if isinstance(entry.get("hashes"), list)
            and entry["hashes"]
            and entry["hashes"][0].get("content")
        )
        status = "artifact_digest" if digests else "incomplete"
        return "release-" + _sha256(
            self.application_id + "|" + "|".join(digests)
        ), status

    @staticmethod
    def _quality(records: dict[str, dict[str, Any]]) -> dict[str, int]:
        values = {
            "components": len(records),
            "with_purl": 0,
            "with_version": 0,
            "with_hash": 0,
            "with_license": 0,
            "loaded_components": 0,
        }
        for record in records.values():
            values["with_purl"] += int(bool(record.get("purl")))
            values["with_version"] += int(bool(record.get("version")))
            values["with_hash"] += int(bool(record.get("hashes")))
            values["with_license"] += int(bool(record.get("licenses")))
            for prop in record.get("properties", []):
                if (
                    prop.get("name") == "beacon:security:sbom:loaded"
                    and prop.get("value") == "true"
                ):
                    values["loaded_components"] += 1
                    break
        return values

    def _load_build(
        self, now: float, reasons: set[str]
    ) -> dict[str, Any] | None:
        if not self.build_file:
            return None
        path = Path(self.build_file).expanduser().absolute()
        try:
            stat = path.stat()
            key = (
                str(path),
                stat.st_dev,
                stat.st_ino,
                stat.st_size,
                stat.st_mtime_ns,
            )
        except OSError:
            reasons.add("build_sbom_unreadable")
            self._build_failure_reason = "build_sbom_unreadable"
            return None
        if (
            self._build_cache_key == key
            and now - self._build_cache_at < self.cache_seconds
        ):
            return self._build_cache
        self._build_cache_key = key
        self._build_cache_at = now
        self._build_failure_reason = ""
        if stat.st_size > self.max_build_bytes:
            self._build_cache = None
            self._build_failure_reason = "build_sbom_byte_limit"
            reasons.add(self._build_failure_reason)
            return None
        try:
            with path.open("rb") as stream:
                raw = stream.read(self.max_build_bytes + 1)
            if len(raw) > self.max_build_bytes:
                raise ValueError("build SBOM exceeds byte limit")
            value = json.loads(raw.decode("utf-8"))
            if (
                not isinstance(value, dict)
                or value.get("bomFormat") != "CycloneDX"
            ):
                raise ValueError("not CycloneDX")
            if not self._bounded_json(value):
                raise ValueError("build SBOM structure exceeds limit")
            self._build_cache = value
            return value
        except Exception:
            self._build_cache = None
            self._build_failure_reason = "invalid_build_sbom"
            reasons.add(self._build_failure_reason)
            return None

    @staticmethod
    def _bounded_json(
        value: Any, depth: int = 0, count: list[int] | None = None
    ) -> bool:
        if count is None:
            count = [0]
        if depth > 64:
            return False
        count[0] += 1
        if count[0] > 100000:
            return False
        if isinstance(value, dict):
            return all(
                _BuildSupport._bounded_json(key, depth + 1, count)
                and _BuildSupport._bounded_json(item, depth + 1, count)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return (
                all(
                    _BuildSupport._bounded_json(item, depth + 1, count)
                    for item in value[:100000]
                )
                and len(value) <= 100000
            )
        return isinstance(value, (str, int, float, bool)) or value is None

    def _merge_build(
        self,
        records: dict[str, dict[str, Any]],
        build: dict[str, Any] | None,
        app_ref: str,
        reasons: set[str],
    ) -> list[dict[str, Any]]:
        if not build:
            return []
        purl_matches: dict[str, list[str]] = defaultdict(list)
        for ref, record in records.items():
            purl = record.get("purl")
            if purl:
                purl_matches[purl].append(ref)
        references: dict[str, str] = {}
        metadata = (
            build.get("metadata")
            if isinstance(build.get("metadata"), dict)
            else {}
        )
        root = (
            metadata.get("component")
            if isinstance(metadata.get("component"), dict)
            else {}
        )
        root_ref = _bounded(root.get("bom-ref"), _MAX_TEXT)
        if root_ref:
            references[root_ref] = app_ref
        components = (
            build.get("components")
            if isinstance(build.get("components"), list)
            else []
        )
        for index, value in enumerate(components[:_MAX_DECLARED_COMPONENTS]):
            if not isinstance(value, dict):
                reasons.add("invalid_declared_component")
                continue
            old_ref = _bounded(value.get("bom-ref"), _MAX_TEXT)
            purl = _bounded(value.get("purl"), _MAX_TEXT)
            matches = purl_matches.get(purl, []) if purl else []
            if len(matches) == 1:
                target = records[matches[0]]
                _property(
                    target["properties"],
                    "beacon:security:sbom:declared",
                    "true",
                )
                if value.get("licenses") and not target.get("licenses"):
                    target["licenses"] = self._declared_licenses(
                        value.get("licenses")
                    )
                    _property(
                        target["properties"],
                        "beacon:security:sbom:license-source",
                        "build-sbom-declaration",
                    )
                if old_ref:
                    if (
                        old_ref in references
                        and references[old_ref] != matches[0]
                    ):
                        reasons.add("ambiguous_declared_component")
                        references.pop(old_ref, None)
                    else:
                        references[old_ref] = matches[0]
                continue
            if len(matches) > 1:
                reasons.add("ambiguous_declared_component")
            declared = self._declared_record(value, old_ref or str(index))
            # max.entries belongs to metadata/archive discovery; the emitted
            # component inventory uses the remaining max_components budget
            # after the metadata application component is reserved.
            if len(records) >= self.max_record_components:
                reasons.add("component_count_limit")
                break
            records[declared["bom-ref"]] = declared
            # A declaration without a PURL has no stable mapping to a runtime
            # component; it is retained for auditability but cannot authorize a
            # dependency edge.  An unmatched PURL maps to exactly this one
            # declared component, which is an explicit unique declaration.
            if old_ref and not matches and purl:
                if old_ref in references:
                    reasons.add("ambiguous_declared_dependency")
                    references.pop(old_ref, None)
                else:
                    references[old_ref] = declared["bom-ref"]
        if len(components) > _MAX_DECLARED_COMPONENTS:
            reasons.add("declared_component_limit")

        edges: dict[str, set[str]] = defaultdict(set)
        dependency_list = (
            build.get("dependencies")
            if isinstance(build.get("dependencies"), list)
            else []
        )
        for value in dependency_list[:_MAX_DECLARED_COMPONENTS]:
            if not isinstance(value, dict):
                continue
            source = references.get(_bounded(value.get("ref"), _MAX_TEXT))
            targets = value.get("dependsOn")
            if source is None or not isinstance(targets, list):
                reasons.add("unresolved_declared_dependency")
                continue
            for target in targets[:_MAX_DECLARED_COMPONENTS]:
                mapped = references.get(_bounded(target, _MAX_TEXT))
                if mapped is None:
                    reasons.add("unresolved_declared_dependency")
                    continue
                edges[source].add(mapped)
        return [
            {"ref": source, "dependsOn": sorted(targets)}
            for source, targets in sorted(edges.items())
            if targets
        ]

    @staticmethod
    def _declared_licenses(value: Any) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        if not isinstance(value, list):
            return result
        for item in value[:_MAX_LICENSES]:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("license"), dict):
                name = _bounded(
                    item["license"].get("name") or item["license"].get("id"),
                    512,
                )
                if name:
                    result.append({"license": {"name": name}})
            elif item.get("expression"):
                result.append(
                    {"expression": _bounded(item.get("expression"), 512)}
                )
        return result

    @staticmethod
    def _declared_record(value: dict[str, Any], scope: str) -> dict[str, Any]:
        name = _bounded(value.get("name"), 512) or "unknown-declared-component"
        group = _bounded(value.get("group"), 512)
        version = _bounded(value.get("version"), 256)
        purl = _bounded(value.get("purl"), _MAX_TEXT)
        ref = "urn:beacon:security:declared:" + _sha256(
            "|".join((purl, group, name, version, scope))
        )
        properties = [
            {
                "name": "beacon:security:sbom:identity-source",
                "value": "build-sbom",
            },
            {"name": "beacon:security:sbom:deployed", "value": "unknown"},
            {"name": "beacon:security:sbom:declared", "value": "true"},
            {"name": "beacon:security:sbom:lifecycle", "value": "current"},
            {"name": "beacon:security:sbom:loaded", "value": "false"},
        ]
        if not version:
            properties.append(
                {
                    "name": "beacon:security:sbom:version-status",
                    "value": "unknown",
                }
            )
        result: dict[str, Any] = {
            "type": _bounded(value.get("type"), 64) or "library",
            "bom-ref": ref,
            "name": name,
            "properties": properties,
        }
        if group:
            result["group"] = group
        if version:
            result["version"] = version
        if purl.startswith("pkg:"):
            result["purl"] = purl
        licenses = _BuildSupport._declared_licenses(value.get("licenses"))
        if licenses:
            result["licenses"] = licenses
            properties.append(
                {
                    "name": "beacon:security:sbom:license-source",
                    "value": "build-sbom-declaration",
                }
            )
        return result

    def _document(
        self,
        revision: int,
        application: dict[str, Any],
        tools: list[dict[str, Any]],
        records: dict[str, dict[str, Any]],
        dependencies: list[dict[str, Any]],
        reasons: set[str],
        release_id: str,
        release_status: str,
        quality: dict[str, int],
        stable_digest: str,
    ) -> dict[str, Any]:
        properties = [
            {"name": "source", "value": "beacon_security"},
            {
                "name": "beacon:security:application-id",
                "value": self.application_id,
            },
            {"name": "beacon:security:release-id", "value": release_id},
            {
                "name": "beacon:security:release:identity-status",
                "value": release_status,
            },
            {
                "name": "beacon:security:sbom:quality",
                "value": json.dumps(
                    quality, sort_keys=True, separators=(",", ":")
                ),
            },
            {
                "name": "beacon:security:process-instance-id",
                "value": self.instance_id,
            },
            {
                "name": "beacon:security:sbom:completeness-reasons",
                "value": ",".join(sorted(reasons)),
            },
            {
                "name": "beacon:security:sbom:loaded-semantics",
                "value": "runtime_load_observed_not_execution",
            },
            {
                "name": "beacon:security:sbom:content-sha256",
                "value": stable_digest,
            },
        ]
        metadata: dict[str, Any] = {
            "timestamp": _iso_now(),
            "lifecycles": [{"phase": "operations"}],
            "component": application,
            "tools": {"components": tools},
        }
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": self.sbom_id,
            "version": revision,
            "metadata": metadata,
            "components": list(records.values()),
            "dependencies": dependencies,
            "compositions": [
                {
                    "aggregate": "incomplete",
                    "assemblies": [self.application_id],
                }
            ],
            "properties": properties,
        }
