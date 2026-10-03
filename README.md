# Beacon Python

Beacon Python is a Python auto-instrumentation and enhancement project based on the complete OpenTelemetry Python Contrib source. It preserves upstream history and is developed and released independently for each language.

The source tree is preparing the `1.1.0` release of [`beacon-otel`](https://pypi.org/project/beacon-otel/) and [`beacon-profiling`](https://pypi.org/project/beacon-profiling/). The current public stable version remains `1.0.1` until the release workflow and public-artifact acceptance complete. Download links and support statements for upstream OpenTelemetry packages do not represent Beacon Python release status.

## Development Resources

- [Development guide and project layout](beacon/README.md)
- [Source provenance and upstream baseline](beacon/upstream.lock.json)
- [Synchronizing OpenTelemetry](beacon/UPSTREAM.md)
- [Release preparation](beacon/RELEASING.md)
- [Main Beacon package](beacon-otel/)
- [Upstream auto-instrumentation distribution](opentelemetry-distro/)
- [Profiling extension](sdk-extension/beacon-profiling/)
- [Contributing guide](CONTRIBUTING.md)

The primary development branch is `main`. Run `uvx --from uv==0.12.1 uv lock --check` from the repository root to verify the development dependency lock. See the [development guide](beacon/README.md) for first-party package tests and the full upstream test matrix. Successful dependency resolution, builds, or local tests do not constitute formal release acceptance.

## Beacon Contributors

<p align="center">
  <a href="https://github.com/lrwh">
    <img src="https://avatars.githubusercontent.com/u/17264378?v=4" width="96" height="96" alt="Reid Liu">
    <br>
    Reid Liu
  </a>
</p>

## Product and Upstream

- [Beacon product home](https://github.com/beacon-observability/beacon)
- [OpenTelemetry Python Contrib](https://github.com/open-telemetry/opentelemetry-python-contrib)

The upstream source layout, package names, and [license](LICENSE) are preserved. `beacon-otel` and `beacon-profiling` are released as independent packages and do not overwrite artifacts published by other projects.
