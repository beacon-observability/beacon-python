# Beacon Python FastAPI Demo

This demo uses `beacon-otel 1.0.0` to validate:

- FastAPI server auto-instrumentation;
- `requests` client auto-instrumentation;
- trace and profile context correlation;
- CPU stack sampling, with controlled workloads for memory, lock contention, and handled-exception sampling.

`/work` calls the service's own `/health` endpoint, so one request produces both server and client spans and generates a bounded profiling workload.

## Installation

Run the following commands in this directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
beacon --version
```

The output should be `Beacon Python 1.0.0`.

## Connecting to DataKit

The following example uses a local DataKit OTLP/gRPC trace endpoint at `127.0.0.1:4317` and a pprof endpoint at `127.0.0.1:9529`:

```bash
export OTEL_SERVICE_NAME=beacon-python-demo
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=demo
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc

export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_PPROF_UPLOAD_URL=http://127.0.0.1:9529/profiling/v1/input
```

Profiles are aggregated and exported every 60 seconds by default. Set
`OTEL_PROFILING_EXPORT_INTERVAL` to shorten or extend the interval.

Start with the default CPU stack sampling for basic acceptance. Enable the other collectors individually when validating them:

```bash
export OTEL_PROFILING_LOCK_ENABLED=true
export OTEL_PROFILING_MEMORY_ENABLED=true

# Handled-exception collection requires Python 3.12 or later.
export OTEL_PROFILING_EXCEPTION_ENABLED=true
```

The memory collection interval follows the profile export interval by default. It can also be adjusted independently with
`OTEL_PROFILING_MEMORY_INTERVAL`.

Start the application:

```bash
beacon uvicorn app:app --host 127.0.0.1 --port 8000
```

Generate load in another terminal:

```bash
for index in $(seq 1 20); do
  curl -fsS 'http://127.0.0.1:8000/work?rounds=100000&memory_kb=512&lock_ms=50'
  echo
done
```

After waiting for at least one export interval, query the observability backend for the service name `beacon-python-demo`. Use the `trace_id` and `span_id` in the `/work` response to locate the corresponding trace.

## Local Smoke Test Without a Backend

You can write traces to the terminal and profiles to local pprof files:

```bash
export OTEL_SERVICE_NAME=beacon-python-demo
export OTEL_TRACES_EXPORTER=console
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none

export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=pprof
export OTEL_PROFILING_PPROF_PATH=otel-profiles/demo
export OTEL_PROFILING_INCLUDE_TRACE_CONTEXT=false

beacon uvicorn app:app --host 127.0.0.1 --port 8000
```

After requesting `/work`, FastAPI and `requests` spans should appear in the terminal and `.pprof` files should be created under `otel-profiles/`. The local pprof encoder cannot represent some unsigned trace and span IDs, so this local-file-only validation mode disables trace context in profiles. The DataKit pprof upload path does not require this workaround.
