"""Exercise the installed public artifacts in a non-root, read-only container."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

HERE = Path(__file__).resolve().parent
BUNDLE = Path("/opt/beacon-python")


def main() -> None:
    version = sys.argv[1]
    assert os.getuid() == 65532
    assert sys.version_info[:2] == (3, 13)
    metadata = BUNDLE / "metadata"
    provenance = json.loads((metadata / "provenance.json").read_text())
    assert provenance["version"] == version
    assert (
        hashlib.sha256(
            (metadata / "requirements.lock").read_bytes()
        ).hexdigest()
        == provenance["dependency_lock_sha256"]
    )
    for artifact in provenance["artifacts"]:
        dist = importlib.metadata.distribution(artifact["name"])
        assert dist.version == version
        wheel = metadata / "release" / artifact["file"]
        assert (
            hashlib.sha256(wheel.read_bytes()).hexdigest()
            == artifact["sha256"]
        )
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if not name.endswith("/") and ".dist-info/" not in name:
                    assert Path(
                        dist.locate_file(name)
                    ).read_bytes() == archive.read(name), name
    assert (
        subprocess.check_output(["beacon", "--version"], text=True).strip()
        == f"Beacon Python {version}"
    )
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.headers.get("traceparent", "").encode())

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(
                (self.path, self.headers.get("Content-Type", ""), body)
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    try:
        with tempfile.TemporaryDirectory(
            prefix="beacon-image-smoke-"
        ) as scratch:
            for enabled in (False, True):
                received.clear()
                env = {
                    **os.environ,
                    "OTEL_SERVICE_NAME": "beacon-python-image-smoke",
                    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
                    "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
                    "OTEL_TRACES_EXPORTER": "otlp",
                    "OTEL_METRICS_EXPORTER": "none",
                    "OTEL_LOGS_EXPORTER": "otlp" if enabled else "none",
                    "OTEL_BSP_SCHEDULE_DELAY": "100",
                    "OTEL_BLRP_SCHEDULE_DELAY": "100",
                    "OTEL_PROFILING_EXPORT_INTERVAL": "1",
                    "OTEL_PROFILING_EXPORTER": "otlp",
                    "OTEL_PROFILING_ENDPOINT": endpoint
                    + "/profiling/v1/input",
                    # The image fixture uses immutable public wheels, including
                    # versions released before the shared endpoint alias.
                    "OTEL_PROFILING_PPROF_UPLOAD_URL": endpoint
                    + "/profiling/v1/input",
                    "BEACON_SECURITY_PYTHON_INCLUDE": "fixture",
                    "BEACON_SECURITY_OUTPUT": scratch + "/security-output",
                }
                # The first run leaves optional-feature switches unset to test defaults.
                for key in (
                    "BEACON_SECURITY_ENABLED",
                    "OTEL_PROFILING_ENABLED",
                    "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED",
                    "BEACON_SECURITY_EVIDENCE_FILE",
                ):
                    env.pop(key, None)
                if enabled:
                    env.update(
                        BEACON_SECURITY_ENABLED="true",
                        OTEL_PROFILING_ENABLED="true",
                    )
                result = subprocess.run(
                    ["beacon", "python", str(HERE / "fixture.py"), endpoint],
                    cwd=scratch,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=45,
                )
                assert result.returncode == 0, result.stdout + result.stderr
                traceparent = re.search(
                    r"TRACEPARENT 00-([0-9a-f]{32})-([0-9a-f]{16})-",
                    result.stdout,
                )
                assert traceparent, result.stdout + result.stderr
                spans = []
                for path, _, body in received:
                    if path == "/v1/traces":
                        request = ExportTraceServiceRequest.FromString(body)
                        for resource in request.resource_spans:
                            assert any(
                                a.key == "service.name"
                                and a.value.string_value
                                == "beacon-python-image-smoke"
                                for a in resource.resource.attributes
                            )
                            spans.extend(
                                s
                                for scope in resource.scope_spans
                                for s in scope.spans
                            )
                assert any(
                    s.trace_id.hex() == traceparent[1]
                    and s.span_id.hex() == traceparent[2]
                    for s in spans
                )
                profiles = [
                    (kind, body)
                    for path, kind, body in received
                    if path == "/profiling/v1/input"
                ]
                logs = [
                    body for path, _, body in received if path == "/v1/logs"
                ]
                if enabled:
                    assert any(
                        "multipart/form-data" in kind
                        and b'filename="auto.pprof"' in body
                        for kind, body in profiles
                    ), result.stderr
                    records = [
                        record
                        for body in logs
                        for resource in ExportLogsServiceRequest.FromString(
                            body
                        ).resource_logs
                        for scope in resource.scope_logs
                        for record in scope.log_records
                    ]
                    assert any(
                        "beacon.security.sbom.inventory" in str(record)
                        for record in records
                    ), result.stderr
                else:
                    assert not profiles and not logs
                assert not Path(scratch, "security-output").exists()
                print(
                    f"PASS: Beacon {version}; {platform.machine()}; correlated OTLP trace; "
                    + (
                        "pprof upload and Security SBOM"
                        if enabled
                        else "optional features disabled by default"
                    ),
                    flush=True,
                )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
