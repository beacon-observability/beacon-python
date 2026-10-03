from __future__ import annotations

import hashlib
import importlib
import os
import threading
from pathlib import Path
from types import SimpleNamespace


def _security_threads() -> set[tuple[str, int | None]]:
    return {
        (thread.name, thread.ident)
        for thread in threading.enumerate()
        if thread.name.startswith("BeaconSecurity-")
    }


def test_disabled_by_default_has_no_runtime_loader_threads_or_files(
    monkeypatch, tmp_path
) -> None:
    for name in (
        "BEACON_SECURITY_ENABLED",
        "BEACON_SECURITY_PYTHON_INCLUDE",
        "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))

    from beacon_security import (
        SecurityInstrumentor,
        bootstrap,
        loader,
        runtime,
    )

    loader.uninstall()
    runtime.stop()
    runtime = importlib.reload(runtime)
    before = _security_threads()
    instrumentor = SecurityInstrumentor()
    try:
        bootstrap()
        instrumentor.instrument()
        assert loader._finder is None
        assert runtime._runtime is None
        assert _security_threads() == before
        assert not tmp_path.exists() or not any(tmp_path.iterdir())
    finally:
        instrumentor.uninstrument()


def test_enabled_runtime_keeps_local_output_off_by_default(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path / "snapshots"))
    monkeypatch.setenv(
        "BEACON_SECURITY_EVIDENCE_FILE", str(tmp_path / "evidence.jsonl")
    )
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.delenv("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", raising=False)
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")

    from beacon_security import runtime

    runtime.stop()
    runtime = importlib.reload(runtime)
    current = runtime.start([])
    try:
        current.exporter.emit(
            {
                "event_name": "beacon.security.health",
                "status": "no_traffic",
            },
            evidence=True,
        )
        assert current.exporter.flush(timeout=5.0)
    finally:
        runtime.stop()

    assert not (tmp_path / "evidence.jsonl").exists()
    assert not (tmp_path / "snapshots").exists()


def test_enabled_lifecycle_starts_without_transform_selector(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.delenv("BEACON_SECURITY_PYTHON_INCLUDE", raising=False)
    monkeypatch.delenv("BEACON_SECURITY_SBOM_ENABLED", raising=False)
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")

    from beacon_security import SecurityInstrumentor, loader, runtime

    instrumentor = SecurityInstrumentor()
    if instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.uninstrument()
    loader.uninstall()
    runtime.stop()
    runtime = importlib.reload(runtime)

    try:
        instrumentor.instrument()
        assert instrumentor._active
        assert runtime._runtime is not None
        assert not runtime._runtime.closed
        assert runtime._runtime.inventory is not None
        assert loader._finder is None
        assert not runtime._runtime.exporter.ledger.enabled()
    finally:
        instrumentor.uninstrument()

    assert runtime._runtime is not None
    assert runtime._runtime.closed
    assert not tmp_path.exists() or not any(tmp_path.iterdir())


def test_application_id_uses_otel_namespace_and_service_name(
    monkeypatch,
) -> None:
    from beacon_security import config

    resource = SimpleNamespace(
        attributes={
            "service.namespace": "shop",
            "service.name": "orders",
        }
    )
    provider = SimpleNamespace(resource=resource)
    monkeypatch.setattr(
        "opentelemetry.trace.get_tracer_provider", lambda: provider
    )
    identity = config.identity()

    expected = hashlib.sha256(b"shop|orders").hexdigest()
    assert identity["application_id"] == "app-" + expected
    assert identity["identity_status"] == "configured"


def test_uninstrument_restores_owned_integrations(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")

    from beacon_security import (
        SecurityInstrumentor,
        frameworks,
        loader,
        runtime,
        sinks,
    )

    from opentelemetry.instrumentation.threading import ThreadingInstrumentor

    instrumentor = SecurityInstrumentor()
    threading_instrumentor = ThreadingInstrumentor()
    if instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.uninstrument()
    if threading_instrumentor.is_instrumented_by_opentelemetry:
        threading_instrumentor.uninstrument()
    frameworks.uninstall()
    sinks.uninstall()
    loader.uninstall()
    runtime.stop()

    try:
        instrumentor.instrument()
        assert instrumentor._active
        assert instrumentor._owns_threading
        assert frameworks._patches is not None
        assert sinks._INSTALLED
        assert loader._finder is not None
        assert threading_instrumentor.is_instrumented_by_opentelemetry
    finally:
        instrumentor.uninstrument()

    assert not instrumentor._active
    assert not instrumentor._owns_threading
    assert frameworks._patches is None
    assert not sinks._INSTALLED
    assert loader._finder is None
    assert not threading_instrumentor.is_instrumented_by_opentelemetry
    assert runtime._runtime is None or runtime._runtime.closed


def test_uninstrument_preserves_preexisting_threading(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")

    from beacon_security import SecurityInstrumentor

    from opentelemetry.instrumentation.threading import ThreadingInstrumentor

    instrumentor = SecurityInstrumentor()
    threading_instrumentor = ThreadingInstrumentor()
    if instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.uninstrument()
    if not threading_instrumentor.is_instrumented_by_opentelemetry:
        threading_instrumentor.instrument()

    try:
        instrumentor.instrument()
        assert not instrumentor._owns_threading
        instrumentor.uninstrument()
        assert threading_instrumentor.is_instrumented_by_opentelemetry
    finally:
        if instrumentor.is_instrumented_by_opentelemetry:
            instrumentor.uninstrument()
        if threading_instrumentor.is_instrumented_by_opentelemetry:
            threading_instrumentor.uninstrument()


def test_gunicorn_post_fork_selects_beacon_defaults(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("OTEL_PYTHON_DISTRO", raising=False)
    monkeypatch.delenv("OTEL_PYTHON_CONFIGURATOR", raising=False)
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    initialized: list[bool] = []
    monkeypatch.setattr(
        "opentelemetry.instrumentation.auto_instrumentation.initialize",
        lambda: initialized.append(True),
    )

    from beacon_security.gunicorn import post_fork

    server = SimpleNamespace(cfg=SimpleNamespace(preload_app=False))
    post_fork(server, object())

    assert initialized == [True]
    assert os.environ["OTEL_PYTHON_DISTRO"] == "beacon"
    assert os.environ["OTEL_PYTHON_CONFIGURATOR"] == "beacon"
    assert Path(os.environ["BEACON_SECURITY_OUTPUT"]).parent == tmp_path
