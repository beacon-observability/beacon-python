"""Bounded, process-local Python runtime SBOM inventory.

The inventory deliberately observes ``sys.modules`` and distribution metadata in
one background worker.  Resolving a component is a read-only lookup against the
last complete snapshot; it never imports a module, walks the filesystem, or
hashes an artifact on an application hot path.
"""

from __future__ import annotations

import copy
import json
import os
import platform
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from . import config
from ._sbom_build import _BuildSupport
from ._sbom_metadata import (
    _archive_path,
    _bounded,
    _canonical_json,
    _component_ref,
    _display_origin,
    _Distribution,
    _iso_now,
    _MetadataCache,
    _MetadataSupport,
    _normalize_origin_for_lookup,
    _outer_origin,
    _path_fingerprint,
    _property,
    _resolve_archive_for_origin,
    _setting_int,
    _sha256,
)
from .schema import component_reference, event_record


class SbomInventory(_MetadataSupport, _BuildSupport):
    """Maintain a bounded runtime CycloneDX 1.7 snapshot.

    ``output`` is the process output directory.  A configured
    ``BEACON_SECURITY_SBOM_OUTPUT`` may instead name the final JSON file (or a
    directory, in which case ``application.cdx.json`` is appended).
    """

    def __init__(
        self,
        identity: dict[str, Any],
        output: Path,
        emit_callback: Callable[[dict[str, Any]], Any] | None,
    ):
        self.identity = copy.deepcopy(identity or {})
        self.emit_callback = emit_callback
        self.max_components = _setting_int(
            "beacon.security.sbom.max.components", 10000
        )
        # CycloneDX carries the application component in metadata, so reserve
        # one output-budget slot before admitting runtime/build components.
        self.max_record_components = max(0, self.max_components - 1)
        self.cache_seconds = _setting_int(
            "beacon.security.sbom.cache.seconds", 300
        )
        self.refresh_seconds = _setting_int(
            "beacon.security.sbom.refresh.seconds", 5
        )
        self.max_archive_bytes = _setting_int(
            "beacon.security.sbom.max.archive.bytes", 64 * 1024 * 1024
        )
        # Entry budgets constrain discovery work; emitted component records use
        # max_components, including build-SBOM declarations.
        self.max_entries = _setting_int(
            "beacon.security.sbom.max.entries", 100000
        )
        self.max_scan_bytes = _setting_int(
            "beacon.security.sbom.max.scan.bytes", 512 * 1024 * 1024
        )
        self.max_build_bytes = _setting_int(
            "beacon.security.sbom.max.build.bytes", 1024 * 1024
        )
        self.max_modules = _setting_int(
            "beacon.security.sbom.max.modules", 100000
        )

        self.application_id = self._application_id()
        self.instance_id = _bounded(
            self.identity.get("instance_id")
            or self.identity.get("instanceId")
            or uuid.uuid4(),
            1024,
        )
        self.sbom_id = "urn:uuid:" + str(uuid.uuid4())
        self.output = self._output_path(output)
        self.history_path = self.output.with_name("sbom-history.json")
        self.local_output_enabled = config.flag(
            "beacon.security.local-output.enabled", False
        )
        self.build_file = _bounded(
            config.text("beacon.security.sbom.build.file", ""), 4096
        ).strip()

        self._metadata = _MetadataCache()
        self._metadata_failure_reason = ""
        self._metadata_limit_reason = ""
        self._build_cache_key: tuple[Any, ...] | None = None
        self._build_cache_at = 0.0
        self._build_cache: dict[str, Any] | None = None
        self._build_failure_reason = ""
        self._archive_cache: dict[
            str, tuple[tuple[Any, ...] | None, float, str]
        ] = {}
        self._origin_fingerprints: dict[str, tuple[Any, ...] | None] = {}

        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._started = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_failure_at = ""
        self._last_refresh_at = ""
        self._last_error_type = ""
        self._last_success_monotonic = 0.0
        self._last_failure_monotonic = 0.0
        self._history: dict[str, dict[str, Any]] = {}
        self._published: dict[str, Any] = {
            "revision": 0,
            "release_id": "unresolved",
            "record_digests": {},
            "module_map": {},
            "stable_digest": "",
            "reasons": {"runtime_dependency_graph_incomplete"},
            "quality": {
                "components": 0,
                "with_purl": 0,
                "with_version": 0,
                "with_hash": 0,
                "with_license": 0,
                "loaded_components": 0,
            },
        }

    def _application_id(self) -> str:
        value = _bounded(
            self.identity.get("application_id")
            or self.identity.get("applicationId"),
            1024,
        ).strip()
        if value:
            return value
        service = (
            self.identity.get("service")
            if isinstance(self.identity.get("service"), dict)
            else {}
        )
        namespace = _bounded(service.get("service.namespace"), 512)
        name = (
            _bounded(service.get("service.name"), 512)
            or "unknown_service:python"
        )
        return "app-" + _sha256(namespace + "|" + name)

    def _output_path(self, output: Path) -> Path:
        configured = config.text("beacon.security.sbom.output", "").strip()
        value = Path(configured).expanduser() if configured else Path(output)
        if configured and value.suffix.lower() == ".json":
            return value.absolute()
        if value.suffix.lower() == ".json":
            return value.absolute()
        return (value / "application.cdx.json").absolute()

    def start(self) -> None:
        """Start the one daemon worker; repeated calls are harmless."""

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._started.clear()
            try:
                self._thread = threading.Thread(
                    target=self._run, name="BeaconSecurity-sbom", daemon=True
                )
                self._thread.start()
            except Exception as error:
                self._thread = None
                self._last_failure_at = _iso_now()
                self._last_error_type = type(error).__name__
                self._last_failure_monotonic = time.monotonic()
                self._emit(
                    {
                        "event_name": "beacon.security.sbom.update_failed",
                        "sbom_id": self.sbom_id,
                        "revision": self._published["revision"],
                        "error_type": _bounded(type(error).__name__, 256),
                    }
                )

    def close(self, timeout: float = 3.0) -> None:
        self._stop.set()
        thread = self._thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=max(0.0, timeout))
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            self._refresh_safely()
            self._started.set()
            if self._stop.wait(self.refresh_seconds):
                break

    def refresh(self) -> None:
        """Run one refresh synchronously for embedding diagnostics or QA."""

        self._refresh_safely()

    def _refresh_safely(self) -> None:
        try:
            with self._refresh_lock:
                self._refresh_once()
        except Exception as error:
            with self._lock:
                self._last_failure_at = _iso_now()
                self._last_error_type = type(error).__name__
                self._last_failure_monotonic = time.monotonic()
                revision = self._published["revision"]
            self._emit(
                {
                    "event_name": "beacon.security.sbom.update_failed",
                    "sbom_id": self.sbom_id,
                    "revision": revision,
                    "error_type": _bounded(type(error).__name__, 256),
                }
            )
            self._emit(self.health())

    def _refresh_once(self) -> None:
        now = time.monotonic()
        metadata_cache = self._load_metadata(now)
        observations = self._loaded_modules()
        reasons: set[str] = {"runtime_dependency_graph_incomplete"}
        if self._metadata_failure_reason:
            reasons.add(self._metadata_failure_reason)
        if self._metadata_limit_reason:
            reasons.add(self._metadata_limit_reason)

        distributions = metadata_cache.distributions
        package_map = metadata_cache.package_map
        for distribution in distributions:
            # The metadata objects are cached for five minutes, but loaded is
            # an observation of this refresh, not a sticky distribution fact.
            distribution.loaded = False
        by_name: dict[str, list[_Distribution]] = defaultdict(list)
        for distribution in distributions:
            by_name[distribution.normalized_name].append(distribution)

        matched_origins: dict[int, set[str]] = defaultdict(set)
        archive_paths: dict[int, set[Path]] = defaultdict(set)
        # A refresh observes one set of roots. Do not retain resolved symlinks
        # or file types across refreshes, where deployments can replace them.
        roots: dict[
            tuple[Path | None, Path | None], list[tuple[Path, bool]]
        ] = {}
        distribution_matches = {}
        for observation in observations:
            if (
                observation.origin is None
                or observation.namespace
                or observation.builtin
            ):
                continue
            candidates = self._candidates(
                observation.name, package_map, by_name
            )
            matches = []
            for item in candidates:
                key = (item.root, item.source_root)
                if key not in roots:
                    roots[key] = self._distribution_roots(item)
                if self._origin_matches(
                    item, observation.origin, observation.name, roots[key]
                ):
                    matches.append(item)
            distribution_matches[id(observation)] = (candidates, matches)
            archive = (
                _resolve_archive_for_origin(observation.origin)
                if matches
                else None
            )
            for distribution in matches:
                matched_origins[id(distribution)].add(observation.origin)
                if archive is not None:
                    archive_paths[id(distribution)].add(archive)
            for distribution in candidates:
                if distribution.root is not None:
                    archive = _archive_path(distribution.root)
                    if archive is not None:
                        archive_paths[id(distribution)].add(archive)

        scan_bytes = [0]
        for distribution in distributions:
            # A cached metadata descriptor is reused across refreshes, but an
            # artifact hash describes this refresh's observed bytes.  Do not
            # retain a prior digest when the archive is gone or unreadable.
            distribution.artifact_hash = ""
            paths = archive_paths.get(id(distribution), set())
            hashes: set[str] = set()
            for archive in sorted(paths, key=str):
                digest = self._archive_digest(
                    archive, now, scan_bytes, reasons
                )
                if digest:
                    hashes.add(digest)
            if len(hashes) == 1:
                distribution.artifact_hash = next(iter(hashes))
            elif len(hashes) > 1:
                reasons.add("ambiguous_artifact_origin")
                distribution.artifact_hash = ""
            elif distribution.root is not None:
                archive = _archive_path(distribution.root)
                if archive is not None:
                    distribution.artifact_hash = self._archive_digest(
                        archive, now, scan_bytes, reasons
                    )
            distribution.origins = set(
                matched_origins.get(id(distribution), set())
            )
            distribution.ref = _component_ref(
                distribution.name or "unknown-component",
                distribution.version,
                "metadata-distribution",
                distribution.identity_scope,
                distribution.artifact_hash,
            )

        stdlib_ref = _component_ref(
            "cpython-stdlib",
            platform.python_version(),
            "interpreter",
            platform.python_implementation().lower(),
        )
        records: dict[str, dict[str, Any]] = {}
        if self.max_record_components > 0:
            records[stdlib_ref] = self._stdlib_record(stdlib_ref)
        else:
            reasons.add("component_count_limit")
        for distribution in sorted(
            distributions,
            key=lambda item: (
                item.normalized_name,
                item.version,
                item.identity_scope,
            ),
        ):
            if distribution.infrastructure:
                continue
            if len(records) >= self.max_record_components:
                reasons.add("component_count_limit")
                break
            records[distribution.ref] = self._distribution_record(distribution)

        previous_fingerprints = self._origin_fingerprints
        current_fingerprints: dict[str, tuple[Any, ...] | None] = {}
        replaced_origins: set[str] = set()
        for observation in observations:
            if observation.origin is None:
                continue
            key = _outer_origin(observation.origin)
            fingerprint = _path_fingerprint(observation.origin)
            current_fingerprints[key] = fingerprint
            if (
                key in previous_fingerprints
                and previous_fingerprints[key] != fingerprint
            ):
                replaced_origins.add(key)
        if replaced_origins:
            reasons.add("artifact_replaced_loaded_mapping_invalidated")

        module_map: dict[str, dict[str, Any]] = {}
        app_ref = self.application_id
        for observation in observations:
            if len(module_map) >= self.max_modules:
                reasons.add("loaded_module_observation_limit")
                break
            module_map[observation.name] = self._resolve_observation(
                observation,
                distributions,
                package_map,
                by_name,
                records,
                stdlib_ref,
                app_ref,
                replaced_origins,
                reasons,
                distribution_matches.get(id(observation)),
            )

        for distribution in distributions:
            if distribution.infrastructure:
                continue
            if distribution.ref in records:
                record = records[distribution.ref]
                _property(
                    record["properties"],
                    "beacon:security:sbom:loaded",
                    "true" if distribution.loaded else "false",
                )
                if distribution.origins:
                    occurrences = [
                        {"location": _display_origin(item)}
                        for item in sorted(distribution.origins)[:32]
                    ]
                    if occurrences:
                        record["evidence"] = {"occurrences": occurrences}

        build = self._load_build(now, reasons)
        if self._build_failure_reason:
            reasons.add(self._build_failure_reason)
        dependencies = self._merge_build(records, build, app_ref, reasons)
        application = self._application_record()
        tools = self._tools(distributions)
        release_id, release_status = self._release_id(records)
        quality = self._quality(records)
        stable_value = {
            "application": application,
            "tools": tools,
            "components": records,
            "dependencies": dependencies,
            "reasons": sorted(reasons),
            "release_id": release_id,
            "module_map": {
                name: {
                    "status": item.get("status"),
                    "bom-ref": item.get("bom-ref", ""),
                    "reason": item.get("reason", ""),
                    "source": item.get("source", ""),
                }
                for name, item in sorted(module_map.items())
            },
        }
        stable_digest = _sha256(_canonical_json(stable_value))

        with self._lock:
            old = self._published
            if stable_digest == old["stable_digest"]:
                self._origin_fingerprints = current_fingerprints
                self._published = {
                    **old,
                    "reasons": reasons,
                    "quality": quality,
                }
                self._last_refresh_at = _iso_now()
                self._last_success_monotonic = time.monotonic()
                unchanged_health = self.health()
            else:
                unchanged_health = None
                revision = int(old["revision"]) + 1
                history = copy.deepcopy(self._history)

        if unchanged_health is not None:
            self._emit(unchanged_health)
            return

        document = self._document(
            revision,
            application,
            tools,
            records,
            dependencies,
            reasons,
            release_id,
            release_status,
            quality,
            stable_digest,
        )
        from ._sbom_events import dependency_snapshot

        snapshot_events = dependency_snapshot(
            {
                "event_name": "beacon.security.sbom.snapshot",
                "sbom_id": self.sbom_id,
                "revision": revision,
                "application_id": self.application_id,
                "release_id": release_id,
                "instance_id": self.instance_id,
                "status": "current",
                "completeness": "incomplete",
                "reasons": sorted(reasons),
            },
            records.values(),
            self.identity,
        )
        record_digests = {
            ref: _sha256(_canonical_json(record))
            for ref, record in records.items()
        }
        next_history = self._next_history(history, record_digests)
        if self.local_output_enabled:
            self._write_pair(document, revision, release_id, next_history)

        with self._lock:
            self._origin_fingerprints = current_fingerprints
            self._history = next_history
            self._last_refresh_at = _iso_now()
            self._last_success_monotonic = time.monotonic()
            self._published = {
                "revision": revision,
                "release_id": release_id,
                "record_digests": record_digests,
                "module_map": copy.deepcopy(module_map),
                "stable_digest": stable_digest,
                "reasons": reasons,
                "quality": quality,
            }
        for event in snapshot_events:
            self._emit(event)
        self._emit(self.health())

    def _next_history(
        self,
        history: dict[str, dict[str, Any]],
        record_digests: dict[str, str],
    ) -> dict[str, dict[str, Any]]:
        now = _iso_now()
        previous = self._published["record_digests"]
        for ref, digest in sorted(record_digests.items()):
            if previous.get(ref) == digest:
                continue
            historical = history.get(ref)
            if (
                historical is None
                and len(history) < self.max_record_components
            ):
                historical = {"bom-ref": ref, "first_seen": now}
                history[ref] = historical
            if historical is not None:
                historical["state"] = "current"
                historical["last_changed_at"] = now
        for ref in sorted(previous):
            if ref in record_digests:
                continue
            historical = history.get(ref)
            if historical is not None:
                historical["state"] = "removed"
                historical["last_changed_at"] = now
        return history

    def _write_pair(
        self,
        document: dict[str, Any],
        revision: int,
        release_id: str,
        history: dict[str, dict[str, Any]],
    ) -> None:
        parent = self.output.parent
        parent.mkdir(parents=True, exist_ok=True)
        history_document = {
            "schema_version": 1,
            "source": "beacon_security",
            "sbom_id": self.sbom_id,
            "revision": revision,
            "application_id": self.application_id,
            "release_id": release_id,
            "updated_at": _iso_now(),
            "entries": list(history.values()),
            "history_limit": self.max_record_components,
            "history_complete": len(history) < self.max_record_components,
        }
        app_tmp: Path | None = None
        history_tmp: Path | None = None
        app_backup: Path | None = None
        history_backup: Path | None = None
        app_installed = False
        history_installed = False
        try:
            app_tmp = self._write_temp(document, parent, ".sbom-")
            history_tmp = self._write_temp(
                history_document, parent, ".sbom-history-"
            )
            app_backup = self._move_to_backup(
                self.output, parent, ".sbom-old-"
            )
            history_backup = self._move_to_backup(
                self.history_path, parent, ".sbom-history-old-"
            )
            os.replace(app_tmp, self.output)
            app_tmp = None
            app_installed = True
            os.replace(history_tmp, self.history_path)
            history_tmp = None
            history_installed = True
        except Exception:
            if app_installed:
                try:
                    self.output.unlink(missing_ok=True)
                except OSError:
                    pass
            if history_installed:
                try:
                    self.history_path.unlink(missing_ok=True)
                except OSError:
                    pass
            if app_backup is not None:
                try:
                    os.replace(app_backup, self.output)
                    app_backup = None
                except OSError:
                    pass
            if history_backup is not None:
                try:
                    os.replace(history_backup, self.history_path)
                    history_backup = None
                except OSError:
                    pass
            raise
        finally:
            for path in (app_tmp, history_tmp, app_backup, history_backup):
                if path is not None:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass

    @staticmethod
    def _write_temp(value: dict[str, Any], parent: Path, prefix: str) -> Path:
        descriptor, name = tempfile.mkstemp(
            prefix=prefix, suffix=".json", dir=parent
        )
        path = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return path

    @staticmethod
    def _move_to_backup(
        target: Path, parent: Path, prefix: str
    ) -> Path | None:
        if not target.exists():
            return None
        descriptor, name = tempfile.mkstemp(
            prefix=prefix, suffix=".json", dir=parent
        )
        os.close(descriptor)
        backup = Path(name)
        try:
            backup.unlink(missing_ok=True)
            os.replace(target, backup)
            return backup
        except Exception:
            try:
                backup.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def resolve(
        self, module_name: str, filename: str | None = None
    ) -> dict[str, Any]:
        """Resolve a loaded module against one immutable published snapshot."""

        name = _bounded(module_name, 512)
        with self._lock:
            snapshot = self._published
            result: dict[str, Any] = {
                "sbom_id": self.sbom_id,
                "revision": snapshot["revision"],
                "release_id": snapshot["release_id"],
                "status": "unresolved",
            }
            item = snapshot["module_map"].get(name)
            if item is None:
                result["reason"] = "unknown_module"
                return component_reference(result, self.application_id)
            expected = item.get("source")
            if filename is not None:
                actual = _normalize_origin_for_lookup(filename)
                if expected and actual != expected:
                    result["reason"] = "module_source_mismatch"
                    return component_reference(result, self.application_id)
            result.update(
                {
                    key: value
                    for key, value in item.items()
                    if key in {"status", "bom-ref", "reason"}
                }
            )
            return component_reference(result, self.application_id)

    def health(self) -> dict[str, Any]:
        with self._lock:
            snapshot = self._published
            if snapshot["revision"] == 0:
                status = (
                    "degraded"
                    if self._last_failure_monotonic
                    else "initializing"
                )
            elif self._last_failure_monotonic > self._last_success_monotonic:
                status = "degraded"
            else:
                status = "current"
            return {
                "event_name": "beacon.security.sbom.health",
                "status": status,
                "sbom_id": self.sbom_id,
                "revision": snapshot["revision"],
                "application_id": self.application_id,
                "release_id": snapshot["release_id"],
                "instance_id": self.instance_id,
                "last_refresh_at": self._last_refresh_at or None,
                "last_failure_at": self._last_failure_at or None,
                "last_error_type": self._last_error_type or None,
                "current_components": len(snapshot["record_digests"]),
                "history_count": len(self._history),
                "completeness": "incomplete",
                "reasons": sorted(snapshot["reasons"]),
            }

    def _emit(self, event: dict[str, Any]) -> None:
        callback = self.emit_callback
        if callback is None:
            return
        try:
            callback(event_record(event, self.identity))
        except Exception:
            # Export callbacks are outside the inventory's persistence contract.
            # A broken observer must not stop refreshes or invalidate a snapshot.
            return
