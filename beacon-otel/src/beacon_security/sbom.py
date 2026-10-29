"""Bounded, process-local Python runtime SBOM inventory.

The inventory deliberately observes ``sys.modules`` and distribution metadata in
one background worker.  Resolving a component is a read-only lookup against the
last complete snapshot; it never imports a module, walks the filesystem, or
hashes an artifact on an application hot path.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import platform
import sys
import tempfile
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

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
from .schema import component_reference


def _process_started() -> tuple[str, float]:
    """Use the process start tick where available, falling back to activation time."""

    now = time.monotonic()
    try:
        fields = Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()
        started = int(fields[19]) / os.sysconf("SC_CLK_TCK")
        if not 0 <= started <= now:
            raise ValueError("invalid_process_start")
    except (OSError, ValueError, IndexError):
        started = now
    wall = time.time() - (now - started)
    return (
        time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(wall)) + ".%03dZ" % int((wall - int(wall)) * 1000),
        started,
    )


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
        self.max_components = _setting_int("beacon.security.sbom.max.components", 10000)
        # CycloneDX carries the application component in metadata, so reserve
        # one output-budget slot before admitting runtime/build components.
        self.max_record_components = max(0, self.max_components - 1)
        self.cache_seconds = _setting_int("beacon.security.sbom.cache.seconds", 300)
        self.refresh_seconds = _setting_int("beacon.security.sbom.refresh.seconds", 300)
        self.max_archive_bytes = _setting_int("beacon.security.sbom.max.archive.bytes", 64 * 1024 * 1024)
        # Entry budgets constrain discovery work; emitted component records use
        # max_components, including build-SBOM declarations.
        self.max_entries = _setting_int("beacon.security.sbom.max.entries", 100000)
        self.max_scan_bytes = _setting_int("beacon.security.sbom.max.scan.bytes", 512 * 1024 * 1024)
        self.max_build_bytes = _setting_int("beacon.security.sbom.max.build.bytes", 1024 * 1024)
        self.max_modules = _setting_int("beacon.security.sbom.max.modules", 100000)

        self.instance_id = _bounded(
            self.identity.get("instance_id") or self.identity.get("instanceId") or config.identity()["instance_id"],
            1024,
        )
        self.started_at, self.started_monotonic = _process_started()
        self.output = self._output_path(output)
        self.local_output_enabled = config.flag("beacon.security.local-output.enabled", False)
        self.build_file = _bounded(config.text("beacon.security.sbom.build.file", ""), 4096).strip()

        self._metadata = _MetadataCache()
        self._metadata_failure_reason = ""
        self._metadata_limit_reason = ""
        self._build_cache_key: tuple[Any, ...] | None = None
        self._build_cache_at = 0.0
        self._build_cache: dict[str, Any] | None = None
        self._build_failure_reason = ""
        self._archive_cache: dict[str, tuple[tuple[Any, ...] | None, float, str]] = {}
        self._origin_fingerprints: dict[str, tuple[Any, ...] | None] = {}

        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._started = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_failure_at = ""
        self._last_refresh_at = ""
        self._last_inventory_observed_at = ""
        self._last_error_type = ""
        self._last_success_monotonic = 0.0
        self._last_failure_monotonic = 0.0
        self._last_warning_monotonic = -30.0
        self._published: dict[str, Any] = {
            "module_map": {},
            "components": {},
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
                self._thread = threading.Thread(target=self._run, name="BeaconSecurity-sbom", daemon=True)
                self._thread.start()
            except Exception as error:
                self._thread = None
                self._last_failure_at = _iso_now()
                self._last_error_type = type(error).__name__
                self._last_failure_monotonic = time.monotonic()
                self._warn_failure(error)

    def close(self, timeout: float = 3.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
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
            # The previous successful inventory remains authoritative.
            self._warn_failure(error)

    def _warn_failure(self, error: Exception) -> None:
        now = time.monotonic()
        if now - self._last_warning_monotonic < 30:
            return
        self._last_warning_monotonic = now
        try:
            print(
                "[Beacon Security] SBOM update failed: " + type(error).__name__,
                file=sys.stderr,
            )
        except BaseException:
            pass

    def _refresh_once(self) -> None:
        now = time.monotonic()
        observed_at = _iso_now()
        if observed_at <= self._last_inventory_observed_at:
            previous = dt.datetime.fromisoformat(self._last_inventory_observed_at.replace("Z", "+00:00"))
            observed_at = (
                (previous + dt.timedelta(milliseconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            )
        uptime_ms = max(0, int((now - self.started_monotonic) * 1000))
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
        roots: dict[tuple[Path | None, Path | None], list[tuple[Path, bool]]] = {}
        distribution_matches = {}
        for observation in observations:
            if observation.origin is None or observation.namespace or observation.builtin:
                continue
            candidates = self._candidates(observation.name, package_map, by_name)
            matches = []
            for item in candidates:
                key = (item.root, item.source_root)
                if key not in roots:
                    roots[key] = self._distribution_roots(item)
                if self._origin_matches(item, observation.origin, observation.name, roots[key]):
                    matches.append(item)
            distribution_matches[id(observation)] = (candidates, matches)
            archive = _resolve_archive_for_origin(observation.origin) if matches else None
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
            paths = archive_paths.get(id(distribution), set()) if self.local_output_enabled else set()
            hashes: set[str] = set()
            for archive in sorted(paths, key=str):
                digest = self._archive_digest(archive, now, scan_bytes, reasons)
                if digest:
                    hashes.add(digest)
            if len(hashes) == 1:
                distribution.artifact_hash = next(iter(hashes))
            elif len(hashes) > 1:
                reasons.add("ambiguous_artifact_origin")
                distribution.artifact_hash = ""
            elif self.local_output_enabled and distribution.root is not None:
                archive = _archive_path(distribution.root)
                if archive is not None:
                    distribution.artifact_hash = self._archive_digest(archive, now, scan_bytes, reasons)
            distribution.origins = set(matched_origins.get(id(distribution), set()))
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
            if key in previous_fingerprints and previous_fingerprints[key] != fingerprint:
                replaced_origins.add(key)
        if replaced_origins:
            reasons.add("artifact_replaced_loaded_mapping_invalidated")

        module_map: dict[str, dict[str, Any]] = {}
        app_ref = self.instance_id
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
                    occurrences = [{"location": _display_origin(item)} for item in sorted(distribution.origins)[:32]]
                    if occurrences:
                        record["evidence"] = {"occurrences": occurrences}

        build = self._load_build(now, reasons) if self.local_output_enabled else None
        if self._build_failure_reason:
            reasons.add(self._build_failure_reason)
        if self.local_output_enabled:
            dependencies = self._merge_build(records, build, app_ref, reasons)
            application = self._application_record()
            tools = self._tools(distributions)
            quality = self._quality(records)
        else:
            dependencies, application, tools = [], {}, []
            quality = {}
        stable_digest = (
            _sha256(
                _canonical_json(
                    {
                        "application": application,
                        "tools": tools,
                        "components": records,
                        "dependencies": dependencies,
                        "reasons": sorted(reasons),
                        "module_map": module_map,
                    }
                )
            )
            if self.local_output_enabled
            else ""
        )

        if any(
            reason.endswith("_limit")
            or reason.startswith("artifact_scan_")
            or reason in {"distribution_metadata_unavailable", "artifact_unreadable"}
            for reason in reasons
        ):
            raise ValueError("incomplete_dependency_inventory")

        from ._sbom_events import dependency_snapshot

        snapshot_events = dependency_snapshot(
            {
                "event_name": "beacon.security.sbom.inventory",
                "instance_id": self.instance_id,
                "observed_at": observed_at,
                "started_at": self.started_at,
                "uptime_ms": uptime_ms,
            },
            records.values(),
            self.identity,
        )
        from ._sbom_events import component_identity

        components = {
            ref: component_identity(record["name"], record.get("version", ""))
            for ref, record in records.items()
            if record.get("type") == "library"
        }
        if self.local_output_enabled:
            document = self._document(
                application,
                tools,
                records,
                dependencies,
                reasons,
                quality,
                stable_digest,
            )
            self.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._write_temp(document, self.output.parent, ".sbom-")
            try:
                os.replace(temporary, self.output)
            finally:
                temporary.unlink(missing_ok=True)
        with self._lock:
            self._origin_fingerprints = current_fingerprints
            self._last_refresh_at = _iso_now()
            self._last_success_monotonic = time.monotonic()
            self._published = {
                "module_map": module_map,
                "components": components,
                "reasons": reasons,
                "quality": quality,
            }
        for event in snapshot_events:
            self._emit(event)
        self._last_inventory_observed_at = observed_at

    @staticmethod
    def _write_temp(value: dict[str, Any], parent: Path, prefix: str) -> Path:
        descriptor, name = tempfile.mkstemp(prefix=prefix, suffix=".json", dir=parent)
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

    def resolve(self, module_name: str, filename: str | None = None) -> dict[str, Any]:
        """Resolve a loaded module against one immutable published snapshot."""

        name = _bounded(module_name, 512)
        with self._lock:
            snapshot = self._published
            item = snapshot["module_map"].get(name)
            if item is None:
                return {}
            expected = item.get("source")
            if filename is not None:
                actual = _normalize_origin_for_lookup(filename)
                if expected and actual != expected:
                    return {}
            return component_reference(snapshot["components"].get(item.get("bom-ref")))

    def health(self) -> dict[str, Any]:
        with self._lock:
            snapshot = self._published
            if not self._last_success_monotonic:
                status = "degraded" if self._last_failure_monotonic else "initializing"
            elif self._last_failure_monotonic > self._last_success_monotonic:
                status = "degraded"
            else:
                status = "current"
            return {
                "event_name": "beacon.security.sbom.health",
                "status": status,
                "instance_id": self.instance_id,
                "last_refresh_at": self._last_refresh_at or None,
                "last_failure_at": self._last_failure_at or None,
                "last_error_type": self._last_error_type or None,
                "current_components": len(snapshot["components"]),
                "completeness": "incomplete",
                "reasons": sorted(snapshot["reasons"]),
            }

    def _emit(self, event: dict[str, Any]) -> None:
        callback = self.emit_callback
        if callback is None:
            return
        try:
            callback(event)
        except Exception:
            # Export callbacks are outside the inventory's persistence contract.
            # A broken observer must not stop refreshes or invalidate a snapshot.
            return
