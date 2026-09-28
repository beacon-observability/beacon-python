Beacon Profiling for Python
===========================

The current stable version is ``beacon-profiling==1.0.0``.
The previously published Guance profiling package is a separate legacy
release; see ``../../beacon/README.md`` in this repository for status.

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
* ``OTEL_PROFILING_INCLUDE_TRACE_CONTEXT``
* ``OTEL_PROFILING_EXCEPTION_ENABLED``
* ``OTEL_PROFILING_EXCEPTION_SAMPLING_INTERVAL``
* ``OTEL_PROFILING_EXCEPTION_COLLECT_MESSAGE``
* ``OTEL_PROFILING_LOCK_ENABLED``
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
