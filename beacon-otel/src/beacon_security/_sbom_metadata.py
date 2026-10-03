"""Distribution metadata and loaded-module origin resolution for the SBOM.

This module owns the filesystem and import-metadata observations used by the
background inventory.  The public inventory only consumes the resulting
bounded descriptors; request-time resolution never calls these helpers.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as importlib_metadata
import json
import os
import platform
import sys
import time
import zipfile
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

try:
    from packaging.utils import canonicalize_name
except (
    ImportError
):  # pragma: no cover - packaging is a declared runtime dependency.

    def canonicalize_name(value: str) -> str:
        return "-".join(
            str(value).lower().replace("_", "-").replace(".", "-").split()
        )


from . import config

_ARCHIVE_SUFFIXES = (".whl", ".zip", ".egg", ".pyz", ".jar")
_INFRASTRUCTURE_PREFIXES = ("opentelemetry", "beacon_security")
_MAX_TEXT = 2048
_MAX_LICENSES = 16
_MAX_REASONS = 128
_MAX_DECLARED_COMPONENTS = 10000
_UNRESOLVED_ORIGINS = {
    "",
    "built-in",
    "frozen",
    "namespace",
    "<built-in>",
    "<frozen>",
}


def _bounded(value: Any, limit: int = _MAX_TEXT) -> str:
    if value is None:
        return ""
    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _setting_int(key: str, default: int) -> int:
    try:
        return max(1, int(config.text(key, str(default))))
    except (TypeError, ValueError, OverflowError):
        return default


def _iso_now() -> str:
    value = time.time()
    return time.strftime(
        "%Y-%m-%dT%H:%M:%S", time.gmtime(value)
    ) + ".%03dZ" % int((value - int(value)) * 1000)


def _sha256(value: str | bytes) -> str:
    data = (
        value.encode("utf-8", "surrogatepass")
        if isinstance(value, str)
        else value
    )
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8", "surrogatepass")


def _canonical_distribution_name(value: Any) -> str:
    text = _bounded(value, 512).strip()
    if not text:
        return ""
    try:
        return _bounded(canonicalize_name(text), 512)
    except Exception:
        return text.lower().replace("_", "-").replace(".", "-")


def _is_infrastructure_distribution(name: str) -> bool:
    normalized = _canonical_distribution_name(name)
    return any(
        normalized == prefix or normalized.startswith(prefix + "-")
        for prefix in _INFRASTRUCTURE_PREFIXES
    )


def _pypi_purl(name: str, version: str) -> str:
    normalized = _canonical_distribution_name(name)
    if not normalized:
        return ""
    # PEP 503 names use a conservative ASCII alphabet.  Metadata names with
    # unusual characters are retained in the component but do not get a false
    # PURL.
    if any(
        char not in "abcdefghijklmnopqrstuvwxyz0123456789-._"
        for char in normalized
    ):
        return ""
    result = "pkg:pypi/" + normalized
    return result + (
        "@" + quote(_bounded(version, 256), safe="-._~") if version else ""
    )


def _path_from_value(value: Any) -> Path | None:
    if value is None:
        return None
    try:
        text = os.fspath(value)
    except (TypeError, ValueError):
        return None
    if not isinstance(text, str) or not text or text.startswith("<"):
        return None
    try:
        parsed = urlparse(text)
        if parsed.scheme == "file":
            text = unquote(parsed.path)
        return Path(text).expanduser().absolute()
    except (OSError, ValueError):
        return None


def _archive_path(value: Any) -> Path | None:
    """Return an outer archive only when its path is a real local file."""

    text = _bounded(value, 16384).replace("\\", "/")
    if not text or text.startswith("<"):
        return None
    lower = text.lower()
    candidates: list[Path] = []
    for suffix in _ARCHIVE_SUFFIXES:
        start = 0
        while True:
            index = lower.find(suffix, start)
            if index < 0:
                break
            candidates.append(Path(text[: index + len(suffix)]))
            start = index + len(suffix)
    direct = _path_from_value(text.split("!/", 1)[0])
    if direct is not None:
        candidates.append(direct)
    for candidate in candidates:
        try:
            if (
                candidate.suffix.lower() in _ARCHIVE_SUFFIXES
                and candidate.is_file()
            ):
                return Path(os.path.realpath(candidate))
        except OSError:
            continue
    return None


def _normalize_origin(value: Any) -> str | None:
    text = _bounded(value, 16384).strip()
    if not text or text in _UNRESOLVED_ORIGINS or text.startswith("<"):
        return None
    archive = _archive_path(text)
    if archive is not None:
        lower = text.lower().replace("\\", "/")
        marker = str(archive).replace("\\", "/")
        index = lower.find(marker.lower())
        if index >= 0:
            suffix = (
                text[index + len(marker) :].replace("\\", "/").lstrip("/!")
            )
            return str(archive) + ("!/" + suffix if suffix else "")
        return str(archive)
    path = _path_from_value(text)
    if path is None:
        return None
    try:
        return os.path.realpath(path)
    except OSError:
        return str(path)


def _normalize_origin_for_lookup(value: Any) -> str | None:
    """Normalize a caller-provided filename without touching the filesystem."""

    text = _bounded(value, 16384).strip()
    if not text or text in _UNRESOLVED_ORIGINS or text.startswith("<"):
        return None
    parsed = urlparse(text)
    if parsed.scheme == "file":
        text = unquote(parsed.path)
    text = text.replace("\\", "/")
    lower = text.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        index = lower.find(suffix)
        if index < 0:
            continue
        outer = os.path.abspath(text[: index + len(suffix)])
        nested = text[index + len(suffix) :].lstrip("/!")
        return os.path.normpath(outer) + (("!/" + nested) if nested else "")
    return os.path.abspath(os.path.normpath(text))


def _outer_origin(origin: str) -> str:
    return origin.split("!/", 1)[0]


def _display_origin(origin: str) -> str:
    outer, separator, nested = origin.partition("!/")
    display = Path(outer).name or outer
    return _bounded(
        display + (("!/" + nested) if separator else ""), _MAX_TEXT
    )


def _path_fingerprint(origin: str) -> tuple[Any, ...] | None:
    target = _outer_origin(origin)
    try:
        stat = os.stat(target)
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    except OSError:
        return None


def _metadata_value(metadata: Any, key: str) -> str:
    try:
        value = metadata.get(key, "") if metadata is not None else ""
    except Exception:
        value = ""
    return _bounded(value, _MAX_TEXT).strip()


def _metadata_values(metadata: Any, key: str) -> list[str]:
    if metadata is None:
        return []
    try:
        values = metadata.get_all(key, [])
    except Exception:
        value = _metadata_value(metadata, key)
        values = [value] if value else []
    result: list[str] = []
    for value in values or []:
        value = _bounded(value, 512).strip()
        if (
            value
            and value.lower() not in {"unknown", "none", "n/a"}
            and value not in result
        ):
            result.append(value)
        if len(result) >= _MAX_LICENSES:
            break
    return result


def _licenses_from_metadata(metadata: Any) -> list[dict[str, Any]]:
    expressions = _metadata_values(metadata, "License-Expression")
    names = _metadata_values(metadata, "License")
    for classifier in _metadata_values(metadata, "Classifier"):
        if classifier.startswith("License ::"):
            name = classifier.split("::")[-1].strip()
            if name and name not in names:
                names.append(name)
    values: list[dict[str, Any]] = []
    for expression in expressions:
        values.append({"expression": expression})
    for name in names:
        values.append({"license": {"name": name}})
    return values[:_MAX_LICENSES]


def _property(properties: list[dict[str, str]], name: str, value: Any) -> None:
    properties[:] = [item for item in properties if item.get("name") != name]
    properties.append({"name": name, "value": _bounded(value, _MAX_TEXT)})


def _component_ref(
    name: str, version: str, source: str, scope: str, artifact_hash: str = ""
) -> str:
    if artifact_hash:
        return "urn:beacon:security:component:" + artifact_hash
    return "urn:beacon:security:component:" + _sha256(
        "|".join((_canonical_distribution_name(name), version, source, scope))
    )


def _safe_module_origin(module: Any) -> str | None:
    try:
        value = getattr(module, "__file__", None)
        if value:
            return _normalize_origin(value)
        spec = getattr(module, "__spec__", None)
        return _normalize_origin(getattr(spec, "origin", None))
    except Exception:
        return None


def _is_namespace_module(module: Any) -> bool:
    try:
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        if origin == "namespace":
            return True
        return origin is None and getattr(module, "__path__", None) is not None
    except Exception:
        return False


def _included_module(name: str) -> bool:
    try:
        return bool(config.included(name))
    except Exception:
        try:
            prefixes = getattr(config, "prefixes")
            return any(
                name == prefix or name.startswith(prefix + ".")
                for prefix in prefixes("beacon.security.python.include")
            )
        except Exception:
            return False


def _resolve_archive_for_origin(origin: str) -> Path | None:
    return _archive_path(_outer_origin(origin))


@dataclass
class _Distribution:
    name: str
    normalized_name: str
    version: str
    root: Path | None
    source_root: Path | None
    editable: bool
    package_names: set[str] = field(default_factory=set)
    licenses: list[dict[str, Any]] = field(default_factory=list)
    infrastructure: bool = False
    identity_scope: str = ""
    artifact_hash: str = ""
    archive_paths: set[Path] = field(default_factory=set)
    ref: str = ""
    loaded: bool = False
    origins: set[str] = field(default_factory=set)


@dataclass
class _ModuleObservation:
    name: str
    origin: str | None
    namespace: bool = False
    builtin: bool = False


@dataclass
class _MetadataCache:
    loaded_at: float = 0.0
    distributions: list[_Distribution] = field(default_factory=list)
    package_map: dict[str, list[str]] = field(default_factory=dict)


class _MetadataSupport:
    """Mixin for bounded distribution discovery and module mapping."""

    def _load_metadata(self, now: float) -> _MetadataCache:
        if (
            self._metadata.loaded_at
            and now - self._metadata.loaded_at < self.cache_seconds
        ):
            self._metadata_failure_reason = ""
            return self._metadata
        try:
            self._metadata_limit_reason = ""
            raw_distributions = importlib_metadata.distributions()
            try:
                raw_package_map = importlib_metadata.packages_distributions()
            except Exception:
                raw_package_map = {}
            descriptors: list[_Distribution] = []
            seen: set[tuple[str, str, str]] = set()
            # Metadata enumeration is discovery work, not the document
            # component budget.  Build declarations are capped separately by
            # max_components during document assembly.
            distribution_limit = min(self.max_components * 4, self.max_entries)
            for index, raw in enumerate(raw_distributions):
                if index >= distribution_limit:
                    self._metadata_limit_reason = "metadata_entry_limit"
                    break
                metadata = getattr(raw, "metadata", None)
                name = _metadata_value(metadata, "Name")
                if not name:
                    try:
                        name = _bounded(getattr(raw, "name", ""), 512)
                    except Exception:
                        name = ""
                version = _metadata_value(metadata, "Version")
                if not version:
                    try:
                        version = _bounded(getattr(raw, "version", ""), 256)
                    except Exception:
                        version = ""
                normalized = _canonical_distribution_name(name)
                root = self._distribution_root(raw)
                source_root, editable = self._direct_url(raw, root)
                scope = _sha256(
                    "|".join(
                        (
                            normalized,
                            version,
                            str(root or ""),
                            str(source_root or ""),
                        )
                    )
                )[:32]
                key = (normalized, version, str(root or ""))
                if key in seen:
                    continue
                seen.add(key)
                package_names = set(self._top_level_names(raw))
                descriptors.append(
                    _Distribution(
                        name=name,
                        normalized_name=normalized,
                        version=version,
                        root=root,
                        source_root=source_root,
                        editable=editable,
                        package_names=package_names,
                        licenses=_licenses_from_metadata(metadata),
                        infrastructure=_is_infrastructure_distribution(name),
                        identity_scope=scope,
                    )
                )
            package_map: dict[str, list[str]] = defaultdict(list)
            descriptors_by_name: dict[str, list[_Distribution]] = defaultdict(
                list
            )
            for descriptor in descriptors:
                descriptors_by_name[descriptor.normalized_name].append(
                    descriptor
                )
            package_entries = 0
            for package, names in (raw_package_map or {}).items():
                if package_entries >= self.max_entries:
                    self._metadata_limit_reason = "metadata_entry_limit"
                    break
                package_name = _canonical_distribution_name(package)
                for name in names or []:
                    if package_entries >= self.max_entries:
                        self._metadata_limit_reason = "metadata_entry_limit"
                        break
                    package_entries += 1
                    normalized = _canonical_distribution_name(name)
                    if (
                        normalized
                        and normalized not in package_map[package_name]
                    ):
                        package_map[package_name].append(normalized)
                        for descriptor in descriptors_by_name.get(
                            normalized, ()
                        ):
                            descriptor.package_names.add(package_name)
            mapping_entries = 0
            for descriptor in descriptors:
                for package_name in descriptor.package_names:
                    if mapping_entries >= self.max_entries:
                        self._metadata_limit_reason = "metadata_entry_limit"
                        break
                    mapping_entries += 1
                    if (
                        descriptor.normalized_name
                        not in package_map[package_name]
                    ):
                        package_map[package_name].append(
                            descriptor.normalized_name
                        )
                if mapping_entries >= self.max_entries:
                    break
            self._metadata = _MetadataCache(
                now, descriptors, dict(package_map)
            )
            self._metadata_failure_reason = ""
        except Exception:
            self._metadata_failure_reason = "distribution_metadata_unavailable"
            if not self._metadata.distributions:
                self._metadata = _MetadataCache(now, [], {})
        return self._metadata

    @staticmethod
    def _distribution_root(distribution: Any) -> Path | None:
        try:
            path = _path_from_value(distribution.locate_file(""))
        except Exception:
            path = None
        if path is None:
            try:
                path = _path_from_value(getattr(distribution, "_path", None))
            except Exception:
                path = None
        if path is None:
            return None
        try:
            if path.name.endswith((".dist-info", ".egg-info")):
                return path.parent
            return path
        except OSError:
            return path

    def _top_level_names(self, distribution: Any) -> list[str]:
        try:
            value = distribution.read_text("top_level.txt")
        except Exception:
            value = None
        if not value:
            return []
        result: list[str] = []
        for index, line in enumerate(_bounded(value, 65536).splitlines()):
            if index >= min(4096, self.max_entries):
                self._metadata_limit_reason = "metadata_entry_limit"
                break
            name = _canonical_distribution_name(line.strip())
            if name and name not in result:
                result.append(name)
        return result

    @staticmethod
    def _direct_url(
        distribution: Any, root: Path | None
    ) -> tuple[Path | None, bool]:
        text = None
        try:
            text = distribution.read_text("direct_url.json")
        except Exception:
            pass
        if not text:
            try:
                info_path = Path(getattr(distribution, "_path"))
                candidate = info_path / "direct_url.json"
                if candidate.is_file() and candidate.stat().st_size <= 65536:
                    text = candidate.read_text(encoding="utf-8")
            except Exception:
                pass
        if not text:
            return None, False
        try:
            value = json.loads(text)
            url = _bounded(value.get("url"), 4096)
            source = _path_from_value(url)
            editable = bool(
                (value.get("dir_info") or {}).get("editable", False)
            )
            return source, editable
        except Exception:
            return None, False

    def _candidates(
        self,
        module_name: str,
        package_map: dict[str, list[str]],
        by_name: dict[str, list[_Distribution]],
    ) -> list[_Distribution]:
        root = _canonical_distribution_name(module_name.partition(".")[0])
        names = package_map.get(root, [])
        candidates: list[_Distribution] = []
        for name in names:
            candidates.extend(by_name.get(name, []))
        if candidates:
            return candidates
        for distribution in by_name.get(root, []):
            if root in distribution.package_names:
                candidates.append(distribution)
        return candidates

    @staticmethod
    def _distribution_roots(
        distribution: _Distribution,
    ) -> list[tuple[Path, bool]]:
        roots = []
        for value in (distribution.root, distribution.source_root):
            if value is not None:
                try:
                    root = Path(os.path.realpath(value))
                    roots.append((root, root.is_file()))
                except (OSError, ValueError):
                    continue
        return roots

    @staticmethod
    def _origin_matches(
        distribution: _Distribution,
        origin: str,
        module_name: str,
        roots: list[tuple[Path, bool]] | None = None,
    ) -> bool:
        outer = _outer_origin(origin)
        outer_path = _path_from_value(outer)
        if outer_path is None:
            return False
        module_root = module_name.partition(".")[0]
        if roots is None:
            roots = _MetadataSupport._distribution_roots(distribution)
        if not roots:
            return False
        try:
            outer_path = Path(os.path.realpath(outer_path))
        except (OSError, ValueError):
            return False
        for root, is_file in roots:
            try:
                if is_file:
                    if root == outer_path:
                        return True
                    continue
                relative = outer_path.relative_to(root)
                parts = relative.parts
                if not parts:
                    continue
                if (
                    module_root in parts
                    or relative.name == module_root + ".py"
                    or relative.name.startswith(module_root + ".")
                ):
                    return True
                # Editable projects frequently use ``src/<package>``; the
                # source root is explicit in direct_url.json, so this is not a
                # guess from an arbitrary parent directory.
            except (OSError, ValueError):
                continue
        return False

    def _archive_digest(
        self,
        archive: Path,
        now: float,
        scan_bytes: list[int],
        reasons: set[str],
    ) -> str:
        key = str(archive)
        try:
            stat = archive.stat()
            fingerprint = (
                stat.st_dev,
                stat.st_ino,
                stat.st_size,
                stat.st_mtime_ns,
            )
        except OSError:
            reasons.add("artifact_unreadable")
            return ""
        cached = self._archive_cache.get(key)
        if (
            cached is not None
            and cached[0] == fingerprint
            and now - cached[1] < self.cache_seconds
        ):
            return cached[2]
        if (
            fingerprint[2] > self.max_archive_bytes
            or scan_bytes[0] + fingerprint[2] > self.max_scan_bytes
        ):
            reasons.add("artifact_hash_byte_limit")
            return ""
        if (
            archive.suffix.lower() in _ARCHIVE_SUFFIXES
            and not self._archive_entries_within_budget(archive, reasons)
        ):
            return ""
        digest = hashlib.sha256()
        try:
            with archive.open("rb") as stream:
                while True:
                    chunk = stream.read(
                        min(1024 * 1024, self.max_archive_bytes + 1)
                    )
                    if not chunk:
                        break
                    scan_bytes[0] += len(chunk)
                    if scan_bytes[0] > self.max_scan_bytes:
                        reasons.add("artifact_hash_byte_limit")
                        return ""
                    digest.update(chunk)
        except OSError:
            reasons.add("artifact_unreadable")
            return ""
        value = digest.hexdigest()
        self._archive_cache[key] = (fingerprint, now, value)
        return value

    def _archive_entries_within_budget(
        self, archive: Path, reasons: set[str]
    ) -> bool:
        """Bound archive directory enumeration before accepting its digest."""

        try:
            with zipfile.ZipFile(archive) as container:
                entries = container.infolist()
        except zipfile.BadZipFile:
            # The suffix is only an artifact hint.  A real file can still have
            # a meaningful content digest even when it is not a readable ZIP.
            return True
        except (OSError, ValueError):
            reasons.add("artifact_unreadable")
            return False
        if len(entries) > self.max_entries:
            reasons.add("archive_entry_limit")
            return False
        return True

    @staticmethod
    def _loaded_modules() -> list[_ModuleObservation]:
        result: list[_ModuleObservation] = []
        try:
            items = list(sys.modules.items())
        except Exception:
            items = []
        for name, module in sorted(items, key=lambda item: str(item[0])):
            name = _bounded(name, 512)
            if not name or module is None:
                continue
            try:
                namespace = _is_namespace_module(module)
                spec = getattr(module, "__spec__", None)
                raw_origin = getattr(module, "__file__", None) or getattr(
                    spec, "origin", None
                )
                builtin = (
                    raw_origin in _UNRESOLVED_ORIGINS
                    and raw_origin not in {"namespace", None}
                )
                origin = _normalize_origin(raw_origin)
                if origin is not None or namespace or builtin:
                    result.append(
                        _ModuleObservation(name, origin, namespace, builtin)
                    )
            except Exception:
                continue
        return result

    def _resolve_observation(
        self,
        observation: _ModuleObservation,
        distributions: list[_Distribution],
        package_map: dict[str, list[str]],
        by_name: dict[str, list[_Distribution]],
        records: dict[str, dict[str, Any]],
        stdlib_ref: str,
        app_ref: str,
        replaced_origins: set[str],
        reasons: set[str],
        distribution_match: tuple[list[_Distribution], list[_Distribution]]
        | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "unresolved",
            "reason": "unknown_module_origin",
        }
        if observation.builtin or observation.name.partition(".")[
            0
        ] in getattr(sys, "stdlib_module_names", set()):
            if stdlib_ref in records:
                result.update(
                    {
                        "status": "resolved",
                        "bom-ref": stdlib_ref,
                        "source": observation.origin or observation.name,
                    }
                )
            else:
                reasons.add("component_count_limit")
                result["reason"] = "component_count_limit"
            return result
        if observation.namespace:
            reasons.add("namespace_package_ambiguity")
            result["reason"] = "namespace_package_ambiguity"
            return result
        origin = observation.origin
        if origin is None:
            reasons.add("unknown_module_origin")
            return result
        if _outer_origin(origin) in replaced_origins:
            reasons.add("artifact_replaced_loaded_mapping_invalidated")
            result["reason"] = "artifact_replaced_loaded_mapping_invalidated"
            result["source"] = origin
            return result

        if distribution_match is None:
            candidates = self._candidates(
                observation.name, package_map, by_name
            )
            matches = [
                item
                for item in candidates
                if self._origin_matches(item, origin, observation.name)
            ]
        else:
            candidates, matches = distribution_match
        infrastructure = [item for item in matches if item.infrastructure]
        if infrastructure:
            result.update(
                {
                    "status": "infrastructure",
                    "reason": "instrumentation_distribution",
                    "source": origin,
                }
            )
            return result
        if len(matches) == 1:
            distribution = matches[0]
            if distribution.ref not in records:
                reasons.add("component_count_limit")
                result["reason"] = "component_count_limit"
                result["source"] = origin
                return result
            distribution.loaded = True
            distribution.origins.add(origin)
            result.update(
                {
                    "status": "resolved",
                    "bom-ref": distribution.ref,
                    "source": origin,
                }
            )
            return result
        if len(matches) > 1 or (
            candidates and len(matches) == 0 and len(candidates) > 1
        ):
            reasons.add("ambiguous_module_distribution")
            result["reason"] = (
                "ambiguous_editable_installation"
                if any(item.editable for item in candidates)
                else "ambiguous_module_distribution"
            )
            result["source"] = origin
            return result
        if candidates:
            reasons.add("module_origin_unmatched_metadata")
            result["reason"] = "module_origin_unmatched_metadata"
            result["source"] = origin
            return result
        if _included_module(observation.name):
            result.update(
                {"status": "resolved", "bom-ref": app_ref, "source": origin}
            )
            return result
        reasons.add("unknown_module_origin")
        result["source"] = origin
        return result

    @staticmethod
    def _stdlib_record(ref: str) -> dict[str, Any]:
        properties = [
            {
                "name": "beacon:security:sbom:identity-source",
                "value": "interpreter",
            },
            {"name": "beacon:security:sbom:deployed", "value": "true"},
            {"name": "beacon:security:sbom:declared", "value": "false"},
            {"name": "beacon:security:sbom:lifecycle", "value": "current"},
            {"name": "beacon:security:sbom:loaded", "value": "true"},
            {
                "name": "beacon:security:sbom:runtime",
                "value": platform.python_implementation(),
            },
        ]
        return {
            "type": "framework",
            "bom-ref": ref,
            "name": "Python standard library",
            "version": platform.python_version(),
            "properties": properties,
        }

    @staticmethod
    def _distribution_record(distribution: _Distribution) -> dict[str, Any]:
        name = distribution.name or "unknown-component"
        properties = [
            {
                "name": "beacon:security:sbom:identity-source",
                "value": "metadata-distribution",
            },
            {
                "name": "beacon:security:sbom:deployed",
                "value": "unknown"
                if distribution.editable or distribution.root is None
                else "true",
            },
            {"name": "beacon:security:sbom:declared", "value": "false"},
            {"name": "beacon:security:sbom:lifecycle", "value": "current"},
            {"name": "beacon:security:sbom:loaded", "value": "false"},
        ]
        if distribution.editable:
            properties.append(
                {
                    "name": "beacon:security:sbom:install-status",
                    "value": "editable",
                }
            )
            properties.append(
                {
                    "name": "beacon:security:sbom:resolution",
                    "value": "editable_source",
                }
            )
        if not distribution.version:
            properties.append(
                {
                    "name": "beacon:security:sbom:version-status",
                    "value": "unknown",
                }
            )
        if not distribution.normalized_name:
            properties.append(
                {
                    "name": "beacon:security:sbom:resolution",
                    "value": "metadata_identity_unknown",
                }
            )
        record: dict[str, Any] = {
            "type": "library",
            "bom-ref": distribution.ref,
            "name": name,
            "properties": properties,
        }
        if distribution.version:
            record["version"] = distribution.version
        purl = (
            _pypi_purl(name, distribution.version)
            if distribution.normalized_name
            else ""
        )
        if purl:
            record["purl"] = purl
        if distribution.artifact_hash:
            record["hashes"] = [
                {"alg": "SHA-256", "content": distribution.artifact_hash}
            ]
        if distribution.licenses:
            record["licenses"] = deepcopy(distribution.licenses)
        return record
