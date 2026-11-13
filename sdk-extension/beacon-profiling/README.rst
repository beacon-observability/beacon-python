Beacon Profiling for Python
===========================

The current stable version is ``beacon-profiling==1.2.1``.

This package provides a Python profiling runtime for OpenTelemetry
auto-instrumentation. The current implementation exports profiles via OTLP
or local pprof files and supports multiple collector types:

* stack sampling
* handled exceptions
* threading and asyncio lock contention
* threading and asyncio condition wait time
* heap snapshots via ``tracemalloc``
* child-process restart after ``fork()``

Handled-exception collection requires Python ``sys.monitoring`` (Python
3.12+); on Python 3.10/3.11 the other collectors remain available.

Trace-correlated samples retain the current span ID separately from the
local root span ID. Endpoint and span kind come from that local root, so a
database child span does not replace the request endpoint. Root identity
travels with the OpenTelemetry context across tasks and propagated threads.
If profiling starts inside a pre-existing local child span whose root was
not observed, the root and endpoint remain unknown.

Usage
-----

Enable profiling for applications launched via ``beacon`` after installing
``beacon-otel[profiling]``:

::

    export OTEL_PROFILING_ENABLED=true
    beacon python app.py

Programmatic usage:

.. code-block:: python

    from opentelemetry.sdk.extension.profiling import Profiler

    profiler = Profiler()
    profiler.start()

Configuration
-------------

The following environment variables are supported:

* ``OTEL_PROFILING_ENABLED``
* ``OTEL_PROFILING_EXPORTER`` (``otlp`` or ``file``; defaults to ``otlp``;
  legacy ``datakit`` and ``pprof_http`` names remain aliases)
* ``OTEL_PROFILING_ENDPOINT`` (defaults to
  ``http://127.0.0.1:9529/profiling/v1/input``)
* ``OTEL_PROFILING_PPROF_UPLOAD_URL`` (legacy explicit endpoint; takes precedence)
* ``OTEL_PROFILING_PPROF_HEADERS`` (legacy upload headers)
* ``OTEL_PROFILING_SAMPLE_INTERVAL``
* ``OTEL_PROFILING_EXPORT_INTERVAL`` (defaults to 60 seconds and can be
  overridden by the ``Profiler(export_interval=...)`` argument)
* ``OTEL_PROFILING_MAX_FRAMES``
* ``OTEL_PROFILING_MAX_BUFFER_SAMPLES`` (defaults to 10000)
* ``OTEL_PROFILING_MAX_BUFFER_BYTES`` (defaults to 8388608 accounted bytes)
* ``OTEL_PROFILING_INCLUDE_TRACE_CONTEXT``
* ``OTEL_PROFILING_EXCEPTION_ENABLED``
* ``OTEL_PROFILING_EXCEPTION_SAMPLING_INTERVAL``
* ``OTEL_PROFILING_EXCEPTION_COLLECT_MESSAGE``
* ``OTEL_PROFILING_LOCK_ENABLED``
* ``OTEL_PROFILING_LOCK_SAMPLING_INTERVAL`` (defaults to 100; one in N
  short acquisitions is sampled; 1 records every operation)
* ``OTEL_PROFILING_LOCK_MIN_DURATION_NS`` (defaults to 1000000; operations
  at or above this duration are recorded without probabilistic sampling)
* ``OTEL_PROFILING_MEMORY_ENABLED``
* ``OTEL_PROFILING_MEMORY_INTERVAL`` (defaults to the profile export interval
  and can be overridden by the ``Profiler(memory_interval=...)`` argument)
* ``OTEL_PROFILING_MEMORY_TOP_STATS``
* ``OTEL_PROFILING_MEMORY_IGNORE_PROFILER``
* ``OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL``
* ``OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT``
* ``OTEL_EXPORTER_OTLP_PROFILES_HEADERS``
* ``OTEL_EXPORTER_OTLP_PROFILES_TIMEOUT``
* ``OTEL_EXPORTER_OTLP_PROFILES_COMPRESSION``
* ``OTEL_EXPORTER_OTLP_PROFILES_CERTIFICATE``
* ``OTEL_EXPORTER_OTLP_PROFILES_CLIENT_KEY``
* ``OTEL_EXPORTER_OTLP_PROFILES_CLIENT_CERTIFICATE``
* ``OTEL_PROFILING_FILE_PATH`` (directory; defaults to ``otel-profiles``)

Service metadata should be configured with standard OpenTelemetry
resource settings such as ``OTEL_SERVICE_NAME`` and
``OTEL_RESOURCE_ATTRIBUTES``.

Short lock acquisition/hold pairs share one sampling decision. Slow holds
and waits are retained even when their acquisition was not sampled. Sampling
is decided before stack walking and trace lookup; filename normalization
uses a bounded cache. OTLP samples carry their interval as ``period`` and
``lock.sampling.interval``. Compatible pprof lock counts and durations are
weighted by that interval; they are estimates when the interval exceeds 1.

One profiler-wide budget covers raw samples in all collectors and the
pending export buffer. Both limits also accept ``Profiler(max_buffer_samples=,
max_buffer_bytes=)`` arguments. Excess samples are dropped, counted in
``profiler.buffer_statistics``, and reported in a warning at flush. The next
window can collect again after draining; delivery is bounded, not lossless.
Retained samples preserve their individual timestamps, trace identity, values,
and CPU deltas. Immutable stack frames use a bounded cache.

Byte accounting conservatively includes sample metadata and frame references,
including shared objects. It bounds queued raw data, not total process RSS;
heap snapshots and serialization also need temporary memory. Capture/build/
export work is excluded from the profiler's own exception and lock collection.
``memory_interval=0`` keeps manual memory capture available on each call;
periodic memory scheduling uses the positive export cadence instead of spinning.

Examples
--------

Collect stack, exception, lock, and heap profiles and upload them over HTTP
using the existing DataKit-compatible multipart/pprof format:

::

    export OTEL_PROFILING_ENABLED=true
    export OTEL_PROFILING_EXCEPTION_ENABLED=true
    export OTEL_PROFILING_LOCK_ENABLED=true
    export OTEL_PROFILING_MEMORY_ENABLED=true
    export OTEL_PROFILING_EXPORTER=otlp
    export OTEL_PROFILING_ENDPOINT=http://127.0.0.1:9529/profiling/v1/input
    beacon python app.py

To dump pprof files instead of uploading them, set:

::

    export OTEL_PROFILING_EXPORTER=file
    export OTEL_PROFILING_FILE_PATH=/tmp/otel-profiles

The ``file`` exporter ignores all OTLP endpoint and transport settings.
It writes gzip pprof files to the configured directory, without network uploads.

The ``otlp`` configuration name selects the existing multipart/pprof uploader,
not the standard OTLP Profiles wire protocol. Sampling and profile encoding are
unchanged. This uploader does not inherit the trace exporter's protocol or shared
OTLP endpoint. A gRPC traces endpoint is not a profiling upload endpoint.

The ``OTEL_EXPORTER_OTLP_PROFILES_*`` settings above apply only when explicitly
constructing the low-level OTLP exporters; the environment-selected compatible
uploader uses ``OTEL_PROFILING_ENDPOINT``. These source changes require a new
Beacon release.
