from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("backend", [None, "python", "upb"])
@pytest.mark.parametrize("protobuf_first", [False, True])
def test_profiling_import_preserves_protobuf_selection(
    backend: str | None, protobuf_first: bool
) -> None:
    environment = dict(os.environ)
    # Integration tests can leave auto-instrumentation enabled/PYTHONPATH set.
    # Probe import behavior without starting exporters in either process.
    environment["OTEL_PROFILING_ENABLED"] = "false"
    environment["OTEL_TRACES_EXPORTER"] = "none"
    environment["OTEL_METRICS_EXPORTER"] = "none"
    environment["OTEL_LOGS_EXPORTER"] = "none"
    key = "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"
    environment.pop(key, None)
    if backend is not None:
        environment[key] = backend
    script = r"""
import gzip
import json
import os
import subprocess
import sys

if sys.argv[1] == "True":
    from google.protobuf.internal import api_implementation

import opentelemetry.sdk.extension.profiling
from google.protobuf.internal import api_implementation
from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedFrame, CapturedSample,
)
from opentelemetry.sdk.extension.profiling.export.pprof_pb2 import Profile
from opentelemetry.sdk.extension.profiling.model.pprof_builder import (
    PprofProfileBuilder,
)
sample = CapturedSample(100, 1, "worker", (CapturedFrame("leaf", "app.py", 1),))
payload = PprofProfileBuilder().build(samples=[sample], sample_period_ns=10)
profile = Profile.FromString(gzip.decompress(payload))
assert list(profile.sample[0].value) == [1]
child = subprocess.check_output([
    sys.executable, "-c",
    "from google.protobuf.internal import api_implementation; print(api_implementation.Type())"
], text=True).strip()
print(json.dumps({
    "env": os.environ.get("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"),
    "parent": api_implementation.Type(), "child": child,
}))
"""
    process = subprocess.run(
        [sys.executable, "-c", script, str(protobuf_first)],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    observed = json.loads(process.stdout)
    assert observed["env"] == backend
    assert observed["child"] == observed["parent"]
    if backend is not None:
        assert observed["parent"] == backend
