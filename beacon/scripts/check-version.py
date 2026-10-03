#!/usr/bin/env python3
"""Keep Beacon package versions and the adopted OTel baseline in sync."""

import argparse
import hashlib
import json
import re
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
VERSION_FILE = ROOT / "beacon/version.properties"
PACKAGE_VERSION_FILES = (
    ROOT
    / "sdk-extension/beacon-profiling/src/opentelemetry/sdk/extension"
    / "profiling/version.py",
    ROOT / "beacon-otel/src/beacon_otel/version.py",
)
BEACON_OTEL_PYPROJECT = ROOT / "beacon-otel/pyproject.toml"
SECURITY_MIGRATION_FILE = ROOT / "beacon/security-migration.lock.json"
SECURITY_PROPERTIES_FILE = (
    ROOT / "beacon-otel/src/beacon_security/security-spec.properties"
)
SECURITY_FIXTURES = {
    "schemaSha256": (
        ROOT
        / "beacon-otel/tests/security/fixtures/spec"
        / "beacon-security-event-v1.schema.json"
    ),
    "fingerprintSha256": (
        ROOT / "beacon-otel/tests/security/fixtures/spec/fingerprint-v1.json"
    ),
}
WHEEL_NAMES = {"beacon-otel", "beacon-profiling"}
VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:(?:a|b|rc)[0-9]+|\.dev[0-9]+)?"
)
CORE_URL = "https://github.com/open-telemetry/opentelemetry-python"
SOURCE_PATTERN = re.compile(
    r'^opentelemetry-[\w-]+\s*=\s*\{\s*git\s*=\s*"'
    + re.escape(CORE_URL)
    + r'",\s*tag\s*=\s*"([^"]+)"',
    re.MULTILINE,
)
LOCK_PATTERN = re.compile(
    re.escape(CORE_URL)
    + r"\?subdirectory=[^\"\s]+?&tag=([^#\"\s]+)#([0-9a-f]{40})"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def product_version() -> str:
    lines = [
        line.strip()
        for line in VERSION_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    require(
        len(lines) == 1 and lines[0].startswith("version="),
        f"{VERSION_FILE}: expected one version= entry",
    )
    version = lines[0].partition("=")[2]
    require(
        VERSION_PATTERN.fullmatch(version) is not None,
        f"Invalid Beacon Python version: {version}",
    )
    return version


def package_version_source(version: str) -> str:
    return (
        "# Generated from beacon/version.properties by "
        "beacon/scripts/check-version.py.\n"
        f'__version__ = "{version}"\n'
    )


def check_baseline() -> tuple[str, str]:
    baseline = json.loads(
        (ROOT / "beacon/upstream.lock.json").read_text(encoding="utf-8")
    )
    contrib = baseline["upstream"]
    core = baseline["core"]
    require(
        contrib["repository"]
        == (
            "https://github.com/open-telemetry/"
            "opentelemetry-python-contrib.git"
        ),
        "Unexpected OTel Contrib repository",
    )
    require(
        core["repository"] == CORE_URL + ".git",
        "Unexpected OTel Core repository",
    )
    require(
        re.fullmatch(
            r"v[0-9]+\.[0-9]+(?:b[0-9]+|\.[0-9]+)", contrib["releaseTag"]
        )
        is not None,
        "Invalid OTel Contrib release tag",
    )
    require(
        re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", core["releaseTag"])
        is not None,
        "Invalid OTel Core release tag",
    )
    for name, source in (("Contrib", contrib), ("Core", core)):
        require(
            re.fullmatch(r"[0-9a-f]{40}", source["releaseCommit"]) is not None,
            f"Invalid OTel {name} release commit",
        )

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    source_tags = SOURCE_PATTERN.findall(pyproject)
    require(
        len(source_tags) >= 4 and set(source_tags) == {core["releaseTag"]},
        "Root pyproject.toml OTel Core sources disagree with baseline",
    )

    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    locked_core = LOCK_PATTERN.findall(lock)
    require(
        len(locked_core) >= 4
        and set(locked_core) == {(core["releaseTag"], core["releaseCommit"])},
        "uv.lock OTel Core sources disagree with baseline",
    )

    profiling = (
        ROOT / "sdk-extension/beacon-profiling/pyproject.toml"
    ).read_text(encoding="utf-8")
    beacon_otel = BEACON_OTEL_PYPROJECT.read_text(encoding="utf-8")
    contrib_version = contrib["releaseTag"].removeprefix("v")
    core_version = core["releaseTag"].removeprefix("v")
    instrumentation = (
        ROOT
        / "opentelemetry-instrumentation/src/opentelemetry/instrumentation"
        / "version.py"
    ).read_text(encoding="utf-8")
    require(
        f'__version__ = "{contrib_version}"' in instrumentation,
        "opentelemetry-instrumentation version differs from Contrib baseline",
    )
    for requirement in (
        f"opentelemetry-api == {core_version}",
        f"opentelemetry-sdk == {core_version}",
        f"opentelemetry-instrumentation == {contrib_version}",
        f"opentelemetry-exporter-otlp == {core_version}",
    ):
        require(
            f'"{requirement}"' in profiling,
            "beacon-profiling dependency differs from baseline: "
            f"{requirement}",
        )
        require(
            f'"{requirement}"' in beacon_otel,
            f"beacon-otel dependency differs from baseline: {requirement}",
        )
    for package in ("requests", "flask", "fastapi", "django"):
        requirement = (
            f"opentelemetry-instrumentation-{package} == {contrib_version}"
        )
        require(
            f'"{requirement}"' in beacon_otel,
            f"beacon-otel extra differs from baseline: {requirement}",
        )
    threading_requirement = (
        f"opentelemetry-instrumentation-threading == {contrib_version}"
    )
    require(
        f'"{threading_requirement}"' in beacon_otel,
        "beacon-otel Security threading dependency differs from baseline",
    )
    return contrib_version, core_version


def check_security_provenance() -> None:
    migration = json.loads(SECURITY_MIGRATION_FILE.read_text(encoding="utf-8"))
    source = migration["source"]
    contract = migration["contract"]
    require(
        migration["schemaVersion"] == 1, "Invalid Security migration schema"
    )
    require(
        source["repository"]
        == "https://github.com/GuanceCloud/SecurityContext.git",
        "Unexpected Security migration source repository",
    )
    require(source["subdirectory"] == "python", "Invalid Security source path")
    require(
        re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None,
        "Invalid Security migration source commit",
    )
    require(
        contract["repository"]
        == "https://github.com/beacon-observability/beacon-security-spec",
        "Unexpected Security contract repository",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", contract["commit"]) is not None,
        "Invalid Security contract commit",
    )
    require(
        contract["schemaVersion"] == contract["fingerprintVersion"] == 1,
        "Beacon Security must use schema and fingerprint version 1",
    )

    properties = dict(
        line.split("=", 1)
        for line in SECURITY_PROPERTIES_FILE.read_text(
            encoding="utf-8"
        ).splitlines()
        if line and not line.startswith("#")
    )
    require(
        properties
        == {
            "repository": contract["repository"],
            "revision": contract["commit"],
            "schemaVersion": str(contract["schemaVersion"]),
            "fingerprintVersion": str(contract["fingerprintVersion"]),
        },
        "Packaged Security contract pin differs from migration lock",
    )
    for field, path in SECURITY_FIXTURES.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(
            digest == contract[field],
            f"Security fixture differs from pinned contract: {path}",
        )


def check_wheel(path: Path, version: str, baseline: tuple[str, str]) -> None:
    require(path.is_file() and path.suffix == ".whl", f"Not a wheel: {path}")
    with ZipFile(path) as archive:
        metadata_files = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")
        ]
        require(
            len(metadata_files) == 1,
            f"Expected exactly one wheel METADATA file: {path}",
        )
        metadata = BytesParser().parsebytes(archive.read(metadata_files[0]))
        wheel_files = set(archive.namelist())
    name = metadata["Name"]
    require(name in WHEEL_NAMES, f"Unexpected wheel package: {name}")
    require(
        metadata["Version"] == version,
        f"Wheel version {metadata['Version']} differs from {version}",
    )
    requirements = metadata.get_all("Requires-Dist", [])
    for package, expected in (
        ("opentelemetry-api", baseline[1]),
        ("opentelemetry-sdk", baseline[1]),
        ("opentelemetry-instrumentation", baseline[0]),
        ("opentelemetry-exporter-otlp", baseline[1]),
    ):
        require(
            any(
                re.fullmatch(
                    re.escape(package) + r"\s*==\s*" + re.escape(expected),
                    item,
                )
                for item in requirements
            ),
            f"Wheel dependency differs from baseline: {package} == {expected}",
        )
    if name == "beacon-otel":
        require(
            any(
                re.fullmatch(
                    r"beacon-profiling\s*==\s*"
                    + re.escape(version)
                    + r"\s*;\s*extra\s*==\s*['\"]profiling['\"]",
                    item,
                )
                for item in requirements
            ),
            f"Wheel profiling extra differs from Beacon Python {version}",
        )
        require(
            any(
                re.fullmatch(
                    r"opentelemetry-instrumentation-threading\s*==\s*"
                    + re.escape(baseline[0]),
                    item,
                )
                for item in requirements
            ),
            "Wheel Security threading dependency differs from Contrib baseline",
        )
        for packaged in (
            "beacon_security/__init__.py",
            "beacon_security/security-spec.properties",
        ):
            require(packaged in wheel_files, f"Wheel is missing {packaged}")
        require(
            "beacon_security/cli.py" not in wheel_files,
            "Wheel must not publish the migration-only Security CLI",
        )
        entry_point_files = [
            item
            for item in wheel_files
            if item.endswith(".dist-info/entry_points.txt")
        ]
        require(
            len(entry_point_files) == 1,
            "Expected one wheel entry_points.txt",
        )
        with ZipFile(path) as archive:
            entry_points = archive.read(entry_point_files[0]).decode("utf-8")
        for expected in (
            "[opentelemetry_instrumentor]",
            "beacon_security = beacon_security:SecurityInstrumentor",
            "[opentelemetry_pre_instrument]",
            "beacon_security = beacon_security:bootstrap",
        ):
            require(
                expected in entry_points,
                f"Wheel is missing Security entry point: {expected}",
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sync",
        action="store_true",
        help="update the package-local version copy",
    )
    parser.add_argument(
        "--wheel",
        type=Path,
        action="append",
        help="also check a built Beacon wheel (repeat for both packages)",
    )
    parser.add_argument(
        "--tag",
        help="also verify a Beacon release tag against the product version",
    )
    args = parser.parse_args()

    version = product_version()
    if args.tag is not None:
        require(
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:rc[0-9]+)?", version)
            is not None,
            "Only RC and final Beacon versions may be published",
        )
        require(
            args.tag == f"v{version}",
            f"Tag {args.tag} does not match Beacon Python {version}",
        )
    expected = package_version_source(version)
    for package_version_file in PACKAGE_VERSION_FILES:
        if (
            args.sync
            and package_version_file.read_text(encoding="utf-8") != expected
        ):
            package_version_file.write_text(expected, encoding="utf-8")
        require(
            package_version_file.read_text(encoding="utf-8") == expected,
            f"{package_version_file}: stale; run check-version.py --sync",
        )
    beacon_otel = BEACON_OTEL_PYPROJECT.read_text(encoding="utf-8")
    profiling_requirement = re.compile(r"beacon-profiling == [^\"]+")
    require(
        len(profiling_requirement.findall(beacon_otel)) == 1,
        "beacon-otel must declare one exact beacon-profiling extra",
    )
    synced_pyproject = profiling_requirement.sub(
        f"beacon-profiling == {version}", beacon_otel
    )
    if args.sync and beacon_otel != synced_pyproject:
        BEACON_OTEL_PYPROJECT.write_text(synced_pyproject, encoding="utf-8")
    require(
        beacon_otel == synced_pyproject or args.sync,
        "beacon-otel profiling extra is stale; run check-version.py --sync",
    )
    baseline = check_baseline()
    check_security_provenance()
    for wheel in args.wheel or []:
        check_wheel(wheel, version, baseline)
    print(
        f"Beacon Python {version}: Contrib {baseline[0]}, "
        f"Core {baseline[1]} OK"
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError) as error:
        raise SystemExit(f"Version check failed: {error}") from error
