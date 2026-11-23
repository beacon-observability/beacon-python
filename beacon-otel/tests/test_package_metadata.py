"""Beacon distribution metadata and entry points."""

from __future__ import annotations

from importlib.metadata import distribution

from beacon_otel import __version__
from packaging.requirements import Requirement


def test_beacon_otel_distribution_identity() -> None:
    package = distribution("beacon-otel")
    assert package.metadata["Name"] == "beacon-otel"
    assert package.version == __version__
    for group, name in (
        ("console_scripts", "beacon"),
        ("opentelemetry_distro", "beacon"),
        ("opentelemetry_configurator", "beacon"),
        ("opentelemetry_instrumentor", "beacon_security"),
        ("opentelemetry_pre_instrument", "beacon_security"),
    ):
        assert any(
            entry_point.group == group and entry_point.name == name
            for entry_point in package.entry_points
        )


def active_dependencies(extra: str) -> set[str]:
    requirements = (
        Requirement(item)
        for item in distribution("beacon-otel").requires or []
    )
    return {
        requirement.name
        for requirement in requirements
        if requirement.marker is None
        or requirement.marker.evaluate({"extra": extra})
    }


def test_default_install_keeps_instrumentation_optional() -> None:
    dependencies = active_dependencies("")
    assert {
        name
        for name in dependencies
        if name.startswith("opentelemetry-instrumentation-")
    } == {"opentelemetry-instrumentation-threading"}
    assert "beacon-profiling" not in dependencies


def test_selected_extra_does_not_enable_all_plugins() -> None:
    assert active_dependencies("redis") - active_dependencies("") == {
        "opentelemetry-instrumentation-redis"
    }


def test_all_extra_keeps_profiling_separate() -> None:
    dependencies = active_dependencies("all")
    assert "opentelemetry-instrumentation-redis" in dependencies
    assert "opentelemetry-instrumentation-fastapi" in dependencies
    assert "beacon-profiling" not in dependencies
    assert active_dependencies("profiling") - active_dependencies("") == {
        "beacon-profiling"
    }
