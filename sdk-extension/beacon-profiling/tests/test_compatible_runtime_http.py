from __future__ import annotations

import gzip
import json
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from time import sleep

from opentelemetry.sdk.extension.profiling.export import pprof_pb2
from opentelemetry.sdk.extension.profiling.runtime import Profiler
from opentelemetry.sdk.resources import Resource


def test_otlp_environment_name_keeps_real_multipart_pprof_upload(monkeypatch):
    received = {}
    ready = Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {self.headers['Content-Type']}\r\n\r\n".encode()
                + body
            )
            received["path"] = self.path
            received["parts"] = {
                part.get_filename(): part.get_payload(decode=True)
                for part in message.iter_parts()
            }
            self.send_response(200)
            self.end_headers()
            ready.set()

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("OTEL_PROFILING_EXPORTER", "otlp")
    monkeypatch.delenv("OTEL_PROFILING_PPROF_UPLOAD_URL", raising=False)
    monkeypatch.setenv(
        "OTEL_PROFILING_ENDPOINT",
        f"http://127.0.0.1:{server.server_port}/profiling/v1/input",
    )
    profiler = Profiler(
        sample_interval=0.005,
        export_interval=3600,
        exception_enabled=False,
        lock_enabled=False,
        memory_enabled=False,
        resource=Resource.create({"service.name": "multipart-regression"}),
    )
    try:
        profiler.start()
        sleep(0.1)
        profiler.stop()
        assert ready.wait(3)
        assert received["path"] == "/profiling/v1/input"
        event = json.loads(received["parts"]["event.json"])
        assert event["family"] == "python"
        assert event["attachments"] == ["auto.pprof"]
        assert "service:multipart-regression" in event["tags_profiler"]
        profile = pprof_pb2.Profile.FromString(
            gzip.decompress(received["parts"]["auto.pprof"])
        )
        assert profile.sample
        assert profile.function
    finally:
        profiler.stop()
        server.shutdown()
        server.server_close()
        worker.join(3)
