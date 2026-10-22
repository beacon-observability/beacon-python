Beacon Profiling for Python
===========================

The current stable version is ``beacon-profiling==1.1.0``.

This package provides a Python profiling runtime for OpenTelemetry
auto-instrumentation. The current implementation exports profiles via OTLP
or a compatible pprof endpoint and supports multiple collector types:

* stack sampling
* handled exceptions
* threading and asyncio lock contention
* threading and asyncio condition wait time
* heap snapshots via ``tracemalloc``
* child-process restart after ``fork()``

Handled-exception collection requires Python ``sys.monitoring`` (Python
3.12+); on Python 3.10/3.11 the other collectors remain available.

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
* ``OTEL_PROFILING_EXPORTER`` (``otlp`` or ``pprof``)
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
* ``OTEL_PROFILING_PPROF_PATH``
* ``OTEL_PROFILING_PPROF_UPLOAD_URL``
* ``OTEL_PROFILING_PPROF_HEADERS``

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

Collect stack, exception, lock, and heap profiles and export them with
OTLP/HTTP:

::

    export OTEL_PROFILING_ENABLED=true
    export OTEL_PROFILING_EXCEPTION_ENABLED=true
    export OTEL_PROFILING_LOCK_ENABLED=true
    export OTEL_PROFILING_MEMORY_ENABLED=true
    export OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=http/protobuf
    export OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT=http://localhost:4318/v1development/profiles
    beacon python app.py

To dump pprof files instead of OTLP, set:

::

    export OTEL_PROFILING_EXPORTER=pprof
    export OTEL_PROFILING_PPROF_PATH=/tmp/otel-profile

To POST pprof directly to a compatible agent endpoint and keep a local
copy:

::

    export OTEL_PROFILING_PPROF_UPLOAD_URL=http://localhost:9529/profiling/v1/input
    export OTEL_PROFILING_PPROF_HEADERS="X-API-Key:xxx"
    beacon python app.py

When ``OTEL_PROFILING_EXPORTER`` is unset and
``OTEL_PROFILING_PPROF_UPLOAD_URL`` is configured, the runtime
defaults to a legacy-compatible ``pprof`` upload layout. Set
``OTEL_PROFILING_EXPORTER=otlp`` to force OTLP profile export.
