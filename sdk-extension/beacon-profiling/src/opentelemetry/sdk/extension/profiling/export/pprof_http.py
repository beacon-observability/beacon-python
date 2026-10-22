from __future__ import annotations

import binascii
import datetime
import json
import logging
import os
import platform
from collections import deque
from itertools import count
from os import environ
from typing import Dict, Optional
from uuid import uuid4

import requests

from opentelemetry.sdk.extension.profiling.environment_variables import (
    OTEL_PROFILING_PPROF_HEADERS,
    OTEL_PROFILING_PPROF_MAX_FILES,
    OTEL_PROFILING_PPROF_PATH,
    OTEL_PROFILING_PPROF_UPLOAD_URL,
)
from opentelemetry.sdk.extension.profiling.export.result import (
    ProfileExportResult,
)
from opentelemetry.sdk.extension.profiling.version import __version__
from opentelemetry.sdk.resources import Resource

_logger = logging.getLogger(__name__)

_DEFAULT_AGENT_BASE_URL = "http://localhost:8126"
_DEFAULT_AGENT_PATH = "profiling/v1/input"


class PPROFHTTPExporter:
    def __init__(
        self,
        *,
        upload_url: str | None = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        session: Optional[requests.Session] = None,
        pprof_path: str | None = None,
        max_files: int | None = None,
        service: str | None = None,
        env_name: str | None = None,
        version: str | None = None,
    ) -> None:
        self._url = upload_url or _resolve_upload_url()
        self._headers = _resolve_headers(headers)
        self._timeout = timeout
        self._session = session or requests.Session()
        self._pprof_path = (
            pprof_path
            if pprof_path is not None
            else environ.get(OTEL_PROFILING_PPROF_PATH)
        )
        self._max_files = (
            max_files
            if max_files is not None
            else int(environ.get(OTEL_PROFILING_PPROF_MAX_FILES, "3"))
        )
        if self._max_files < 1:
            raise ValueError("max_files must be >= 1")
        self._written_paths: deque[str] = deque()
        self._service = service
        self._env = env_name
        self._version = version
        self._runtime_id = uuid4().hex
        self._host = platform.node()
        self._runtime = platform.python_implementation()
        self._runtime_version = platform.python_version()
        self._pid = os.getpid()
        self._counter = count()

    def export(
        self,
        payload: bytes,
        *,
        resource: Resource | None = None,
        start_time_unix_nano: int | None = None,
        end_time_unix_nano: int | None = None,
    ) -> ProfileExportResult:
        try:
            filename = self._write_payload(payload)
        except OSError as exc:
            # Local copies are diagnostic output, not a prerequisite for
            # upload. Read-only/full disks must not discard a valid profile.
            _logger.warning("Cannot save local pprof payload: %s", exc)
            filename = None
        try:
            request_headers = dict(self._headers)
            content_type, body = self._build_request(
                payload=payload,
                resource=resource,
                start_time_unix_nano=start_time_unix_nano,
                end_time_unix_nano=end_time_unix_nano,
            )
            request_headers["Content-Type"] = content_type
            response = self._session.post(
                url=self._url,
                data=body,
                headers=request_headers,
                timeout=self._timeout,
            )
        except Exception as exc:
            _logger.error("pprof HTTP export failed: %s", exc)
            return ProfileExportResult.FAILURE

        if response.status_code not in (200, 202):
            _logger.error(
                "pprof HTTP export failed status %s: %s",
                response.status_code,
                response.text,
            )
            return ProfileExportResult.FAILURE

        _logger.debug(
            "pprof payload saved to %s and posted to %s",
            filename,
            self._url,
        )
        return ProfileExportResult.SUCCESS

    def _build_request(
        self,
        *,
        payload: bytes,
        resource: Resource | None,
        start_time_unix_nano: int | None,
        end_time_unix_nano: int | None,
    ) -> tuple[str, bytes]:
        service = self._resolve_service(resource)
        event = {
            "version": "4",
            "family": "python",
            "attachments": ["auto.pprof"],
            "tags_profiler": self._format_tags(service, resource),
            "start": _format_timestamp(
                start_time_unix_nano
                or datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
                * 1_000_000_000
            ),
            "end": _format_timestamp(
                end_time_unix_nano
                or start_time_unix_nano
                or datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
                * 1_000_000_000
            ),
        }
        files = [
            {
                "name": "auto",
                "filename": "auto.pprof",
                "content_type": "application/octet-stream",
                "data": payload,
            }
        ]
        return _encode_multipart_formdata(event=event, files=files)

    def _format_tags(self, service: str, resource: Resource | None) -> str:
        tags = {
            "service": service,
            "runtime-id": self._runtime_id,
            "host": self._host,
            "language": "python",
            "runtime": self._runtime,
            "runtime_version": self._runtime_version,
            "profiler_version": __version__,
        }
        env_name = self._resolve_env(resource)
        if env_name:
            tags["env"] = env_name
        version = self._resolve_version(resource)
        if version:
            tags["version"] = version
        return ",".join(f"{key}:{value}" for key, value in tags.items())

    def _resolve_service(self, resource: Resource | None) -> str:
        return (
            _resource_attribute(resource, "service.name")
            or self._service
            or "unknown_service"
        )

    def _resolve_env(self, resource: Resource | None) -> str | None:
        return (
            _resource_attribute(
                resource,
                "deployment.environment.name",
                "deployment.environment",
            )
            or self._env
        )

    def _resolve_version(self, resource: Resource | None) -> str | None:
        return (
            _resource_attribute(resource, "service.version") or self._version
        )

    def _write_payload(self, payload: bytes) -> str | None:
        if not self._pprof_path:
            return None
        filename = (
            f"{self._pprof_path}.{self._pid}.{next(self._counter)}.pprof"
        )
        os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
        with open(filename, "wb") as handle:
            handle.write(payload)
        self._written_paths.append(filename)
        while len(self._written_paths) > self._max_files:
            previous = self._written_paths.popleft()
            try:
                os.remove(previous)
            except OSError as exc:
                _logger.warning("Cannot remove local pprof payload: %s", exc)
        return filename

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        del timeout_millis
        return True

    def shutdown(self) -> None:
        self._session.close()


def _resolve_headers(
    headers: Optional[Dict[str, str]],
) -> Dict[str, str]:
    resolved = _parse_headers(environ.get(OTEL_PROFILING_PPROF_HEADERS, ""))
    if headers is not None:
        resolved.update(headers)
    return resolved


def _resolve_upload_url() -> str:
    explicit = environ.get(OTEL_PROFILING_PPROF_UPLOAD_URL)
    if explicit:
        return explicit
    return f"{_DEFAULT_AGENT_BASE_URL}/{_DEFAULT_AGENT_PATH}"


def _parse_headers(value: str) -> Dict[str, str]:
    headers = {}
    for header in value.split(","):
        if ":" not in header:
            continue
        key, header_value = header.split(":", 1)
        key = key.strip()
        header_value = header_value.strip()
        if key:
            headers[key] = header_value
    return headers


def _resource_attribute(resource: Resource | None, *keys: str) -> str | None:
    if resource is None:
        return None
    for key in keys:
        value = resource.attributes.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _format_timestamp(timestamp_unix_nano: float | int) -> str:
    timestamp = datetime.datetime.fromtimestamp(
        float(timestamp_unix_nano) / 1e9,
        tz=datetime.timezone.utc,
    )
    return timestamp.replace(microsecond=0).isoformat()[0:-6] + "Z"


def _encode_multipart_formdata(
    *,
    event: dict[str, str | list[str]],
    files: list[dict[str, str | bytes]],
) -> tuple[str, bytes]:
    boundary = binascii.hexlify(os.urandom(16)).decode("ascii")
    boundary_bytes = boundary.encode("ascii")
    body = (
        (b"--%s\r\n" % boundary_bytes)
        + b'Content-Disposition: form-data; name="event"; filename="event.json"\r\n'
        + b"Content-Type: application/json\r\n\r\n"
        + _encode_json(event)
        + b"\r\n"
        + b"".join(
            (b"--%s\r\n" % boundary_bytes)
            + (
                b'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                % (
                    str(item["name"]).encode("utf-8"),
                    str(item["filename"]).encode("utf-8"),
                )
            )
            + (
                b"Content-Type: %s\r\n\r\n"
                % str(item["content_type"]).encode("utf-8")
            )
            + bytes(item["data"])
            + b"\r\n"
            for item in files
        )
        + b"--%s--\r\n" % boundary_bytes
    )
    return f"multipart/form-data; boundary={boundary}", body


def _encode_json(payload: dict[str, str | list[str]]) -> bytes:
    return json.dumps(payload).encode("utf-8")
