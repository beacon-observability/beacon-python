"""Runtime SBOM contracts for Python v0.2.0."""

from __future__ import annotations

import importlib.metadata
import json
import time
import zipfile
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator
from jsonschema import Draft202012Validator, FormatChecker

_EVENT_SCHEMA = json.loads(
    (Path(__file__).resolve().parent / "fixtures/spec/beacon-security-event-v2.schema.json").read_text()
)
_EVENT_VALIDATOR = Draft202012Validator(_EVENT_SCHEMA, format_checker=FormatChecker())


def _sbom_env(monkeypatch, output: Path, **values):
    defaults = {
        "BEACON_SECURITY_ENABLED": "true",
        "BEACON_SECURITY_PYTHON_INCLUDE": "security_sample",
        "BEACON_SECURITY_PYTHON_EXCLUDE": "",
        "BEACON_SECURITY_SBOM_OUTPUT": str(output / "application.cdx.json"),
        "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED": "true",
        "BEACON_SECURITY_SBOM_CACHE_SECONDS": "1",
        "BEACON_SECURITY_SBOM_REFRESH_SECONDS": "300",
    }
    defaults.update({key: str(value) for key, value in values.items()})
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)


def _properties(component: dict) -> dict[str, str]:
    return {
        str(item.get("name")): str(item.get("value"))
        for item in component.get("properties", [])
        if isinstance(item, dict)
    }


def _document(output: Path) -> dict:
    return json.loads((output / "application.cdx.json").read_text(encoding="utf-8"))


def _refresh(monkeypatch, tmp_path, **values):
    output = tmp_path / "sbom"
    output.mkdir()
    _sbom_env(monkeypatch, output, **values)
    from beacon_security.sbom import SbomInventory

    events: list[dict] = []
    inventory = SbomInventory(
        {
            "application_id": "qa-sbom-app",
            "instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268",
            "service": {"service.name": "qa-sbom"},
            "runtime": {"language": "python"},
        },
        output,
        events.append,
    )
    inventory.refresh()
    return output, inventory, events


def _validate_official_schema(document: Path) -> list[object]:
    errors = JsonValidator(SchemaVersion.V1_7).validate_str(document.read_text(encoding="utf-8"), all_errors=True)
    return list(errors or ())


def test_distribution_licenses_survive_cached_and_expired_metadata(monkeypatch, tmp_path):
    from beacon_security import _sbom_metadata

    metadata_path = tmp_path / "licensed_demo-1.0.dist-info"
    metadata_path.mkdir()
    (metadata_path / "top_level.txt").write_text("licensed_demo\n")

    def write_metadata(expression):
        (metadata_path / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: licensed-demo\nVersion: 1.0\n"
            f"License-Expression: {expression}\nLicense: Demo License\n"
            "Classifier: License :: OSI Approved :: MIT License\n\n" + "Long project description. " * 10000
        )

    write_metadata("MIT")
    distribution = importlib.metadata.PathDistribution(metadata_path)
    monkeypatch.setattr(
        _sbom_metadata.importlib_metadata,
        "distributions",
        lambda: [distribution],
    )
    monkeypatch.setattr(
        _sbom_metadata.importlib_metadata,
        "packages_distributions",
        lambda: {"licensed_demo": ["licensed-demo"]},
    )
    clock = [100.0]
    monkeypatch.setattr(_sbom_metadata.time, "monotonic", lambda: clock[0])
    output, inventory, _ = _refresh(monkeypatch, tmp_path)

    def licenses():
        return next(c for c in _document(output)["components"] if c["name"] == "licensed-demo")["licenses"]

    expected = [
        {"expression": "MIT"},
        {"license": {"name": "Demo License"}},
        {"license": {"name": "MIT License"}},
    ]
    assert licenses() == expected
    write_metadata("Apache-2.0")
    clock[0] += 0.5
    inventory.refresh()
    assert licenses() == expected
    clock[0] += 2
    inventory.refresh()
    expected[0] = {"expression": "Apache-2.0"}
    assert licenses() == expected
    inventory.close()


def test_fresh_metadata_loaded_deployed_and_v2_inventory_with_current_document(monkeypatch, tmp_path):
    """A fresh pip distribution is represented without synthetic wheel/RECORD hashes."""

    import pytest as loaded_pytest  # noqa: F401 - make the loaded observation explicit

    import opentelemetry  # noqa: F401 - namespace ambiguity boundary

    output, inventory, events = _refresh(monkeypatch, tmp_path)
    document = _document(output)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert isinstance(document["version"], int) and document["version"] >= 1
    assert document["serialNumber"] == "urn:uuid:" + inventory.instance_id

    validation_errors = _validate_official_schema(output / "application.cdx.json")
    assert not validation_errors, validation_errors

    expected_version = importlib.metadata.version("pytest")
    component = next(item for item in document["components"] if item.get("name") == "pytest")
    properties = _properties(component)
    assert component["version"] == expected_version
    assert component["purl"] == f"pkg:pypi/pytest@{expected_version}"
    assert properties["beacon:security:sbom:identity-source"] == "metadata-distribution"
    assert properties["beacon:security:sbom:loaded"] == "true"
    assert properties["beacon:security:sbom:deployed"] == "true"
    assert "hashes" not in component
    assert "RECORD" not in json.dumps(component, ensure_ascii=False)

    resolved = inventory.resolve("pytest")
    assert resolved["name"] == "pytest"
    assert resolved["version"] == expected_version
    assert len(resolved["hash"]) == 32

    namespace = inventory.resolve("opentelemetry")
    assert namespace == {}
    snapshots = [item for item in events if item.get("event_name") == "beacon.security.sbom.inventory"]
    assert snapshots and snapshots[-1]["started_at"] == inventory.started_at
    for snapshot in snapshots:
        _EVENT_VALIDATOR.validate(snapshot)
    dependencies = [row for part in snapshots for row in part["dependencies"]]
    assert resolved in dependencies
    assert all(set(row) <= {"name", "version", "hash"} for row in dependencies)


def test_inventory_envelope_failure_emits_nothing_and_allows_retry(monkeypatch, tmp_path):
    from beacon_security.sbom import SbomInventory

    output = tmp_path / "sbom"
    _sbom_env(monkeypatch, output, BEACON_SECURITY_EVIDENCE_MAX_BYTES=1)
    events = []
    inventory = SbomInventory({"application_id": "qa-small-envelope"}, output, events.append)
    try:
        inventory.refresh()
        assert events == []
        assert not (output / "application.cdx.json").exists()
        monkeypatch.setenv("BEACON_SECURITY_EVIDENCE_MAX_BYTES", "65536")
        inventory.refresh()
        assert _document(output)["version"] == 1
        assert any(event["event_name"] == "beacon.security.sbom.inventory" for event in events)
    finally:
        inventory.close()


def test_inventory_chunks_preserve_loaded_identities_and_metadata_hash(
    monkeypatch,
):
    from beacon_security._sbom_events import dependency_snapshot

    monkeypatch.setenv("BEACON_SECURITY_EVIDENCE_MAX_BYTES", "2048")
    properties = [{"name": "beacon:security:sbom:loaded", "value": "true"}]
    records = [
        {
            "type": "library",
            "name": f"package-{index}-中文",
            "version": "1.0",
            "purl": f"pkg:pypi/package-{index}",
            "properties": properties,
        }
        for index in range(150)
    ]
    fallback = {
        "type": "library",
        "name": "unknown",
        "hashes": [{"alg": "SHA-256", "content": "abcd"}],
        "properties": properties,
    }
    records.extend(
        [
            fallback,
            fallback,
            {"type": "library", "name": "not-loaded", "version": "2.0"},
        ]
    )
    envelope = {
        "instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268",
        "observed_at": "2026-10-29T00:00:00.000Z",
        "started_at": "2026-10-29T00:00:00.000Z",
        "uptime_ms": 1000,
    }
    parts = dependency_snapshot(envelope, records, {})
    assert len(parts) > 1
    for index, part in enumerate(parts):
        _EVENT_VALIDATOR.validate(part)
        assert len(json.dumps(part, ensure_ascii=False, separators=(",", ":")).encode()) <= 2048
        assert part["part_index"] == index and part["part_count"] == len(parts)
    dependencies = [row for part in parts for row in part["dependencies"]]
    assert len(dependencies) == 151
    from beacon_security._sbom_events import component_identity

    assert component_identity("unknown", "") in dependencies
    assert dependency_snapshot(envelope, [], {})[0]["dependencies"] == []
    assert "part_count" not in dependency_snapshot(envelope, [], {})[0]


def test_build_declared_component_is_explicitly_mapped_without_implicit_runtime_edges(monkeypatch, tmp_path):
    """Only explicit build PURL/bom-ref declarations create SBOM dependency edges."""

    import pytest as loaded_pytest  # noqa: F401

    output, _inventory, _events = _refresh(monkeypatch, tmp_path)
    runtime_only = _document(output)
    assert runtime_only["dependencies"] == []

    declared_output = tmp_path / "declared"
    declared_output.mkdir()
    version = importlib.metadata.version("pytest")
    build_file = tmp_path / "build-sbom.json"
    build_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {"component": {"bom-ref": "declared-application"}},
                "components": [
                    {
                        "bom-ref": "declared-pytest",
                        "name": "pytest",
                        "version": version,
                        "purl": f"pkg:pypi/pytest@{version}",
                    }
                ],
                "dependencies": [
                    {
                        "ref": "declared-application",
                        "dependsOn": ["declared-pytest"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _sbom_env(
        monkeypatch,
        declared_output,
        BEACON_SECURITY_SBOM_BUILD_FILE=build_file,
    )
    from beacon_security.sbom import SbomInventory

    inventory = SbomInventory(
        {
            "application_id": "qa-sbom-app",
            "instance_id": "qa-sbom-instance-2",
            "service": {"service.name": "qa-sbom"},
            "runtime": {"language": "python"},
        },
        declared_output,
        None,
    )
    inventory.refresh()
    document = _document(declared_output)
    component = next(item for item in document["components"] if item.get("name") == "pytest")
    properties = _properties(component)
    assert properties["beacon:security:sbom:declared"] == "true"
    assert properties["beacon:security:sbom:loaded"] == "true"
    assert properties["beacon:security:sbom:deployed"] == "true"
    app_ref = document["metadata"]["component"]["bom-ref"]
    assert document["dependencies"] == [{"ref": app_ref, "dependsOn": [component["bom-ref"]]}]


def test_sbom_max_components_prevents_incomplete_publication(monkeypatch, tmp_path):
    """The component budget includes the metadata application component."""

    output = tmp_path / "bounded"
    output.mkdir()
    build_file = tmp_path / "oversized-build.json"
    build_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {
                        "bom-ref": name,
                        "name": name,
                        "version": "1",
                        "purl": f"pkg:pypi/{name}@1",
                    }
                    for name in ("qa-one", "qa-two", "qa-three")
                ],
            }
        ),
        encoding="utf-8",
    )
    _sbom_env(
        monkeypatch,
        output,
        BEACON_SECURITY_SBOM_MAX_COMPONENTS=1,
        BEACON_SECURITY_SBOM_BUILD_FILE=build_file,
    )
    from beacon_security.sbom import SbomInventory

    inventory = SbomInventory(
        {
            "application_id": "qa-sbom-bounded",
            "instance_id": "qa-sbom-bounded-instance",
            "service": {"service.name": "qa-sbom"},
        },
        output,
        None,
    )
    inventory.refresh()
    assert not (output / "application.cdx.json").exists()


def test_sbom_max_entries_bounds_archive_entry_scan_without_hash(monkeypatch, tmp_path):
    """The entry budget bounds archive inspection, not emitted component count."""

    output = tmp_path / "archive-budget"
    output.mkdir()
    _sbom_env(monkeypatch, output, BEACON_SECURITY_SBOM_MAX_ENTRIES=1)
    archive = tmp_path / "oversized.whl"
    with zipfile.ZipFile(archive, "w") as container:
        for name in ("one.py", "two.py", "three.py"):
            container.writestr(name, "pass\n")

    from beacon_security.sbom import SbomInventory

    inventory = SbomInventory(
        {
            "application_id": "qa-sbom-archive",
            "instance_id": "qa-sbom-archive-instance",
        },
        output,
        None,
    )
    reasons: set[str] = set()
    scan_bytes = [0]
    digest = inventory._archive_digest(archive, time.monotonic(), scan_bytes, reasons)
    assert digest == ""
    assert "archive_entry_limit" in reasons
    assert scan_bytes == [0]
    assert inventory._archive_cache == {}


def test_sbom_replacement_invalidates_loaded_module_mapping(monkeypatch, tmp_path):
    """A changed loaded origin cannot retain its previous distribution mapping."""

    output = tmp_path / "replacement"
    output.mkdir()
    _sbom_env(monkeypatch, output, BEACON_SECURITY_SBOM_MAX_COMPONENTS=16)
    module_path = tmp_path / "qa_replace.py"
    module_path.write_text("VALUE = 'first'\n", encoding="utf-8")

    from beacon_security._sbom_metadata import (
        _Distribution,
        _MetadataCache,
        _ModuleObservation,
    )
    from beacon_security.sbom import SbomInventory

    distribution = _Distribution(
        name="qa-replace",
        normalized_name="qa-replace",
        version="1",
        root=tmp_path,
        source_root=None,
        editable=False,
        package_names={"qa_replace"},
        identity_scope="qa-replacement-scope",
    )
    cache = _MetadataCache(
        loaded_at=time.monotonic(),
        distributions=[distribution],
        package_map={"qa-replace": ["qa-replace"]},
    )
    inventory = SbomInventory(
        {
            "application_id": "qa-sbom-replacement",
            "instance_id": "qa-sbom-replacement-instance",
        },
        output,
        None,
    )
    monkeypatch.setattr(inventory, "_load_metadata", lambda _now: cache)
    monkeypatch.setattr(
        SbomInventory,
        "_loaded_modules",
        staticmethod(lambda: [_ModuleObservation("qa_replace", str(module_path))]),
    )

    inventory.refresh()
    first = inventory.resolve("qa_replace")
    assert first["name"] == "qa-replace"

    module_path.write_text("VALUE = 'replacement-with-different-size'\n", encoding="utf-8")
    inventory.refresh()
    replaced = inventory.resolve("qa_replace")
    assert replaced == {}


def test_sbom_rechecks_editable_root_symlinks_on_each_refresh(monkeypatch, tmp_path):
    from beacon_security._sbom_metadata import (
        _Distribution,
        _MetadataCache,
        _ModuleObservation,
    )
    from beacon_security.sbom import SbomInventory

    first, second, linked = (
        tmp_path / "first",
        tmp_path / "second",
        tmp_path / "current",
    )
    first.mkdir()
    second.mkdir()
    module = first / "qa_editable.py"
    module.write_text("VALUE = 1\n")
    linked.symlink_to(first, target_is_directory=True)
    distribution = _Distribution(
        name="qa-editable",
        normalized_name="qa-editable",
        version="1",
        root=linked,
        source_root=None,
        editable=True,
        package_names={"qa_editable"},
        identity_scope="editable",
    )
    metadata = _MetadataCache(
        distributions=[distribution],
        package_map={"qa-editable": ["qa-editable"]},
    )
    output = tmp_path / "sbom"
    _sbom_env(monkeypatch, output)
    inventory = SbomInventory({"application_id": "qa", "instance_id": "qa"}, output, None)
    monkeypatch.setattr(inventory, "_load_metadata", lambda _now: metadata)
    monkeypatch.setattr(
        inventory,
        "_loaded_modules",
        lambda: [_ModuleObservation("qa_editable", str(module))],
    )
    inventory.refresh()
    assert inventory.resolve("qa_editable")["name"] == "qa-editable"
    linked.unlink()
    linked.symlink_to(second, target_is_directory=True)
    inventory.refresh()
    assert inventory.resolve("qa_editable") == {}
    linked.unlink()
    linked.symlink_to(first, target_is_directory=True)
    inventory.refresh()
    assert inventory.resolve("qa_editable")["name"] == "qa-editable"


def test_unchanged_inventory_republishes_without_history(monkeypatch, tmp_path):
    from beacon_security._sbom_metadata import _MetadataCache
    from beacon_security.sbom import SbomInventory

    output = tmp_path / "inventory"
    _sbom_env(monkeypatch, output, BEACON_SECURITY_LOCAL_OUTPUT_ENABLED="false")
    events = []
    inventory = SbomInventory(
        {"instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268"},
        output,
        events.append,
    )
    monkeypatch.setattr(inventory, "_loaded_modules", list)
    monkeypatch.setattr(inventory, "_load_metadata", lambda now: _MetadataCache(now, [], {}))
    inventory.refresh()
    inventory.refresh()
    assert len(events) == 2
    assert all(event["event_name"] == "beacon.security.sbom.inventory" for event in events)
    assert all(event["dependencies"] == [] for event in events)
    assert events[0]["observed_at"] < events[1]["observed_at"]
    assert events[0]["started_at"] == events[1]["started_at"]
    assert not (output / "sbom-history.json").exists()
    assert not (output / "application.cdx.json").exists()
    inventory.close()


def test_failed_collection_keeps_last_inventory_until_recovery(monkeypatch, tmp_path):
    from beacon_security._sbom_events import component_identity
    from beacon_security._sbom_metadata import _MetadataCache
    from beacon_security.sbom import SbomInventory

    assert component_identity("org.example:library-a", "1.0.0")["hash"] == ("b783176a5feb4aafd51a712235824a9c")
    output = tmp_path / "inventory"
    _sbom_env(monkeypatch, output, BEACON_SECURITY_LOCAL_OUTPUT_ENABLED="false")
    monkeypatch.delenv("BEACON_SECURITY_SBOM_REFRESH_SECONDS")
    events = []
    inventory = SbomInventory(
        {"instance_id": "233cf30d-c73b-4365-b052-0e7159ee6268"},
        output,
        events.append,
    )
    assert inventory.refresh_seconds == 300
    monkeypatch.setenv("BEACON_SECURITY_SBOM_REFRESH_SECONDS", "0")
    assert SbomInventory(inventory.identity, output, None).refresh_seconds == 300
    monkeypatch.setattr(inventory, "_loaded_modules", list)
    monkeypatch.setattr(inventory, "_load_metadata", lambda now: _MetadataCache(now, [], {}))
    inventory.refresh()
    assert len(events) == 1 and events[0]["dependencies"] == []
    inventory._metadata_limit_reason = "declared_component_limit"
    inventory.refresh()
    assert len(events) == 1
    inventory._metadata_limit_reason = ""
    monkeypatch.setattr(
        inventory,
        "_load_metadata",
        lambda _now: (_ for _ in ()).throw(OSError("metadata unavailable")),
    )
    inventory.refresh()
    assert len(events) == 1
    assert inventory.health()["status"] == "degraded"
    monkeypatch.setattr(inventory, "_load_metadata", lambda now: _MetadataCache(now, [], {}))
    inventory.refresh()
    assert len(events) == 2
    assert events[1]["observed_at"] > events[0]["observed_at"]
    inventory.close()
