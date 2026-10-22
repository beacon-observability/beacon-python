from __future__ import annotations

import errno
from unittest.mock import Mock

import pytest

from opentelemetry.sdk.extension.profiling.export.pprof_http import (
    PPROFHTTPExporter,
)
from opentelemetry.sdk.resources import Resource


def test_pprof_http_exporter_posts_multipart_payload(monkeypatch, tmp_path):
    session = Mock()
    session.post.return_value = Mock(status_code=202, text="ok")
    monkeypatch.setenv(
        "OTEL_PROFILING_PPROF_HEADERS",
        "X-API-Key:api-key",
    )
    monkeypatch.setenv(
        "OTEL_PROFILING_PPROF_UPLOAD_URL",
        "http://agent:8126/profiling/v1/input",
    )
    exporter = PPROFHTTPExporter(
        session=session,
        pprof_path=str(tmp_path / "prof"),
    )
    payload = b"foo"
    resource = Resource.create(
        {
            "service.name": "svc",
            "service.version": "1.2.3",
            "deployment.environment.name": "prod",
        }
    )

    result = exporter.export(
        payload,
        resource=resource,
        start_time_unix_nano=1_700_000_000_000_000_000,
        end_time_unix_nano=1_700_000_060_000_000_000,
    )

    assert result.name == "SUCCESS"
    session.post.assert_called_once()
    kwargs = session.post.call_args.kwargs
    assert kwargs["url"] == "http://agent:8126/profiling/v1/input"
    assert kwargs["headers"]["X-API-Key"] == "api-key"
    assert kwargs["headers"]["Content-Type"].startswith(
        "multipart/form-data; boundary="
    )
    body = kwargs["data"]
    assert b'filename="event.json"' in body
    assert b'filename="auto.pprof"' in body
    assert b'"family": "python"' in body
    assert b"service:svc" in body
    assert b"env:prod" in body
    assert b"version:1.2.3" in body
    assert payload in body
    files = list(tmp_path.glob("prof*.pprof"))
    assert files


def test_pprof_http_exporter_handles_failure(monkeypatch, tmp_path):
    session = Mock()
    session.post.side_effect = Exception("boom")
    exporter = PPROFHTTPExporter(
        session=session,
        pprof_path=str(tmp_path / "prof"),
    )

    result = exporter.export(b"bar")

    assert result.name == "FAILURE"
    files = list(tmp_path.glob("prof*.pprof"))
    assert files


def test_http_upload_does_not_require_a_writable_directory(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OTEL_PROFILING_PPROF_PATH", raising=False)
    session = Mock()
    session.post.return_value = Mock(status_code=202)
    exporter = PPROFHTTPExporter(session=session)
    assert exporter.export(b"payload").name == "SUCCESS"
    assert list(tmp_path.iterdir()) == []
    session.post.assert_called_once()


@pytest.mark.parametrize("error_number", [errno.EACCES, errno.ENOSPC])
def test_local_write_failure_still_uploads_and_recovers(
    monkeypatch, tmp_path, error_number: int, caplog
) -> None:
    session = Mock()
    session.post.return_value = Mock(status_code=202)
    exporter = PPROFHTTPExporter(
        session=session, pprof_path=str(tmp_path / "profile")
    )
    write = exporter._write_payload

    def fail(payload: bytes) -> None:
        raise OSError(error_number, "write unavailable")

    monkeypatch.setattr(exporter, "_write_payload", fail)
    assert exporter.export(b"first").name == "SUCCESS"
    assert "Cannot save local pprof" in caplog.text
    monkeypatch.setattr(exporter, "_write_payload", write)
    assert exporter.export(b"second").name == "SUCCESS"
    assert session.post.call_count == 2
    assert next(tmp_path.glob("*.pprof")).read_bytes() == b"second"


def test_http_local_copies_have_bounded_instance_retention(
    monkeypatch, tmp_path
) -> None:
    session = Mock()
    session.post.return_value = Mock(status_code=202)
    monkeypatch.setenv("OTEL_PROFILING_PPROF_MAX_FILES", "2")
    exporter = PPROFHTTPExporter(
        session=session, pprof_path=str(tmp_path / "profile")
    )
    other = tmp_path / "profile.other-process.pprof"
    other.write_bytes(b"keep")
    for index in range(5):
        assert exporter.export(str(index).encode()).name == "SUCCESS"
    copies = [path for path in tmp_path.glob("*.pprof") if path != other]
    assert {path.read_bytes() for path in copies} == {b"3", b"4"}
    assert other.read_bytes() == b"keep"


def test_explicit_empty_path_disables_environment_local_copies(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("OTEL_PROFILING_PPROF_PATH", str(tmp_path / "profile"))
    session = Mock()
    session.post.return_value = Mock(status_code=202)
    exporter = PPROFHTTPExporter(session=session, pprof_path="")
    assert exporter.export(b"payload").name == "SUCCESS"
    assert list(tmp_path.iterdir()) == []


def test_build_failure_returns_failure_and_next_export_recovers(
    monkeypatch,
) -> None:
    session = Mock()
    session.post.return_value = Mock(status_code=202)
    exporter = PPROFHTTPExporter(session=session, pprof_path="")
    build = exporter._build_request
    monkeypatch.setattr(
        exporter, "_build_request", Mock(side_effect=ValueError("bad build"))
    )
    assert exporter.export(b"first").name == "FAILURE"
    session.post.assert_not_called()
    monkeypatch.setattr(exporter, "_build_request", build)
    assert exporter.export(b"second").name == "SUCCESS"
