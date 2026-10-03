# Beacon Python

`beacon-otel` is the main Beacon Python installation package. The current stable version is `1.0.1`.

Install the main package together with the auto-instrumentation plugins required by your framework. For example, a FastAPI application can install the current stable version with:

```bash
pip install 'beacon-otel[fastapi]==1.0.1'
```

To enable profiling, install:

```bash
pip install 'beacon-otel[fastapi,profiling]==1.0.1'
```

Activate the virtual environment where Beacon is installed, configure the OTLP endpoint, and then start the application. You can also pass the full path of an executable in that virtual environment after `beacon`:

```bash
export OTEL_SERVICE_NAME=my-service
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
beacon uvicorn myapp:app
```

`beacon --version` displays the Beacon Python product version. Optional dependencies are currently provided for `requests`, `flask`, `fastapi`, and `django`; auto-instrumentation packages for other frameworks can be installed separately according to the official OpenTelemetry documentation. Package availability does not mean that every framework and runtime environment is supported by a stable Beacon release. Refer to the release notes and acceptance records for the supported scope of each version.

Optional dependencies install only the corresponding auto-instrumentation plugins; the application must install the framework itself. Do not install another profiling distribution that registers a conflicting auto-instrumentation entry point in the same Python environment.

By default, `beacon` selects the Beacon OpenTelemetry distro and configurator and uses the standard `OTEL_*` environment variables. Explicitly configured `OTEL_PYTHON_DISTRO` or `OTEL_PYTHON_CONFIGURATOR` values are not overwritten. Profiling is disabled by default; see the [profiling documentation](../sdk-extension/beacon-profiling/README.rst) to enable it.

## Beacon Security (next release)

The source tree now includes opt-in Beacon Security in the same `beacon-otel`
wheel and command. It is not part of the published `1.0.1` package. A future
Beacon Python release will not require a second Security distribution or a
second version lifecycle.

Security currently supports standard-GIL CPython 3.11 through 3.14. The master
switch enables its lifecycle and runtime SBOM; an application-module prefix is
also required for modeled data-flow collection:

```bash
export BEACON_SECURITY_ENABLED=true
export BEACON_SECURITY_PYTHON_INCLUDE=orders
export OTEL_SERVICE_NAME=orders
export OTEL_RESOURCE_ATTRIBUTES=service.namespace=shop
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317

beacon uvicorn orders.asgi:application --host 0.0.0.0 --port 8000
```

`BEACON_SECURITY_PYTHON_INCLUDE` contains Python module prefixes, not file-system
paths. Without it, the enabled lifecycle can report the runtime SBOM but does
not transform application code or collect findings. The runtime transforms only
included application modules and excludes the standard library, OpenTelemetry,
Beacon Security itself, and explicitly configured prefixes. Findings are
bounded modeled-flow observations or candidate risks, not confirmed
vulnerability reports.

Runtime SBOM collection is enabled by default only after Security itself is
enabled. Findings and SBOM snapshots use the existing OpenTelemetry Logs
pipeline. Local files are off by default:

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `BEACON_SECURITY_ENABLED` | `false` | Enable the Security lifecycle and its runtime SBOM. |
| `BEACON_SECURITY_PYTHON_INCLUDE` | empty | Comma-separated application module prefixes required for finding collection. |
| `BEACON_SECURITY_PYTHON_EXCLUDE` | empty | Comma-separated exclusions, which take precedence. |
| `BEACON_SECURITY_SBOM_ENABLED` | `true` | Enable runtime SBOM within an enabled lifecycle. |
| `BEACON_SECURITY_LOCAL_OUTPUT_ENABLED` | `false` | Enable process-local diagnostic files. |
| `BEACON_SECURITY_OUTPUT` | `./beacon-security-output/<instance-id>` | Diagnostic snapshot directory. |
| `BEACON_SECURITY_EVIDENCE_FILE` | unset | Optional diagnostic JSONL file. |

For local inspection without an OTLP backend, additionally set
`BEACON_SECURITY_LOCAL_OUTPUT_ENABLED=true`, choose the output paths, and set
`OTEL_LOGS_EXPORTER=none`. Local files are diagnostic evidence, not durable or
cluster-wide delivery.

Gunicorn must initialize OpenTelemetry after each worker fork. Do not prefix
this command with `beacon` or `opentelemetry-instrument`, and do not enable
`preload_app`:

```bash
gunicorn -c python:beacon_security.gunicorn orders.wsgi:application
```

For Kubernetes, bake the future `beacon-otel` release into the application
image and use the checked-in [Deployment example](examples/kubernetes/deployment.yaml).
The example needs only the normal application command, environment variables,
and an OTLP Collector endpoint; it deliberately leaves local output disabled.

The language-neutral event, identity, configuration, fingerprint, and runtime
SBOM contract is maintained in
[beacon-security-spec](https://github.com/beacon-observability/beacon-security-spec).
This wheel carries an immutable contract revision in
[`security-spec.properties`](src/beacon_security/security-spec.properties).
