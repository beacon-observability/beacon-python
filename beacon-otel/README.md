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

`beacon --version` displays the Beacon Python product version. Optional dependencies are currently provided for `requests`, `flask`, and `fastapi`; auto-instrumentation packages for other frameworks can be installed separately according to the official OpenTelemetry documentation. Package availability does not mean that every framework and runtime environment is supported by a stable Beacon release. Refer to the release notes and acceptance records for the supported scope of each version.

Optional dependencies install only the corresponding auto-instrumentation plugins; the application must install the framework itself. Do not install another profiling distribution that registers a conflicting auto-instrumentation entry point in the same Python environment.

By default, `beacon` selects the Beacon OpenTelemetry distro and configurator and uses the standard `OTEL_*` environment variables. Explicitly configured `OTEL_PYTHON_DISTRO` or `OTEL_PYTHON_CONFIGURATOR` values are not overwritten. Profiling is disabled by default; see the [profiling documentation](../sdk-extension/beacon-profiling/README.rst) to enable it.
