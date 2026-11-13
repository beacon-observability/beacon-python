from __future__ import annotations

import pytest

from opentelemetry.sdk.extension.profiling.export.file import (
    FileProfileExporter,
)
from opentelemetry.sdk.extension.profiling.export.pprof_http import (
    PPROFHTTPExporter,
)
from opentelemetry.sdk.extension.profiling.model.pprof_builder import (
    CompatiblePprofProfileBuilder,
    PprofProfileBuilder,
)
from opentelemetry.sdk.extension.profiling.runtime import Profiler


@pytest.mark.parametrize("name", [None, "otlp", "datakit", "pprof_http"])
def test_runtime_keeps_compatible_upload_for_otlp_name(monkeypatch, name):
    monkeypatch.delenv("OTEL_PROFILING_PPROF_UPLOAD_URL", raising=False)
    if name is None:
        monkeypatch.delenv("OTEL_PROFILING_EXPORTER", raising=False)
    else:
        monkeypatch.setenv("OTEL_PROFILING_EXPORTER", name)
    monkeypatch.setenv(
        "OTEL_PROFILING_ENDPOINT", "http://127.0.0.1:9529/profiling/v1/input"
    )
    exporter = Profiler._create_exporter_from_env()
    assert isinstance(exporter, PPROFHTTPExporter)
    assert exporter._url == "http://127.0.0.1:9529/profiling/v1/input"
    assert isinstance(
        Profiler(exporter=exporter)._builder, CompatiblePprofProfileBuilder
    )
    exporter.shutdown()


def test_file_ignores_all_endpoint_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("OTEL_PROFILING_EXPORTER", "file")
    monkeypatch.setenv("OTEL_PROFILING_FILE_PATH", str(tmp_path))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT", "not a URL")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL", "invalid")
    exporter = Profiler._create_exporter_from_env()
    assert isinstance(exporter, FileProfileExporter)
    assert isinstance(
        Profiler(exporter=exporter)._builder, PprofProfileBuilder
    )
    exporter.export(b"profile")
    assert next(tmp_path.glob("*.pprof")).read_bytes() == b"profile"


@pytest.mark.parametrize("name", ["unknown", "pprof", "none"])
def test_unsupported_exporter_names_rejected(monkeypatch, name):
    monkeypatch.setenv("OTEL_PROFILING_EXPORTER", name)
    with pytest.raises(ValueError, match="Unsupported profiling exporter"):
        Profiler._create_exporter_from_env()


def test_runtime_defaults_to_sixty_second_intervals(monkeypatch):
    monkeypatch.delenv("OTEL_PROFILING_EXPORT_INTERVAL", raising=False)
    monkeypatch.delenv("OTEL_PROFILING_MEMORY_INTERVAL", raising=False)

    profiler = Profiler(exporter=object())

    assert profiler._export_interval == 60.0
    assert profiler._memory_interval == 60.0


def test_runtime_interval_environment_variables_override_defaults(
    monkeypatch,
):
    monkeypatch.setenv("OTEL_PROFILING_EXPORT_INTERVAL", "17.5")
    monkeypatch.setenv("OTEL_PROFILING_MEMORY_INTERVAL", "23.5")

    profiler = Profiler(exporter=object())

    assert profiler._export_interval == 17.5
    assert profiler._memory_interval == 23.5


def test_runtime_interval_arguments_override_environment(monkeypatch):
    monkeypatch.setenv("OTEL_PROFILING_EXPORT_INTERVAL", "17.5")
    monkeypatch.setenv("OTEL_PROFILING_MEMORY_INTERVAL", "23.5")

    profiler = Profiler(
        exporter=object(),
        export_interval=31.5,
        memory_interval=37.5,
    )

    assert profiler._export_interval == 31.5
    assert profiler._memory_interval == 37.5
