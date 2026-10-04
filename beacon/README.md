# Beacon Python Development Guide

This standalone repository maintains the complete [OpenTelemetry Python Contrib](https://github.com/open-telemetry/opentelemetry-python-contrib) source and history; it is not a GitHub fork. The main product repository is [beacon-observability/beacon](https://github.com/beacon-observability/beacon). The current public stable version is `1.1.0`; its release and public-artifact validation are recorded in [`validation/1.1.0.md`](validation/1.1.0.md).

The primary development branch is `main`. The initial import preserved the legacy `gtrace` commit history and merged the official `v0.65b0` release tag. The [version file](version.properties) is the only manually maintained source for the Beacon Python development version. The tags and full commits for Contrib `v0.65b0` and the corresponding Core `v1.44.0` are recorded in the [baseline record](upstream.lock.json). Actual Core development dependencies remain defined by the root [pyproject.toml](../pyproject.toml) and [uv.lock](../uv.lock) and are verified by the version-check script. See [upstream synchronization](UPSTREAM.md) for future upgrades.

## Code and Validation Resources

| Item | Location |
| --- | --- |
| Main Beacon installation package, `beacon` command, and opt-in Security source | [beacon-otel](../beacon-otel/) |
| Upstream auto-instrumentation distribution | [opentelemetry-distro](../opentelemetry-distro/) |
| First-party profiling extension | [beacon-profiling](../sdk-extension/beacon-profiling/) |
| Upstream auto-instrumentation and tests | [instrumentation](../instrumentation/) |
| Build and contribution guidelines | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Beacon version and upstream baseline checks | [check-version.py](scripts/check-version.py) |
| FastAPI Demo | [examples/fastapi-demo](examples/fastapi-demo/) |
| Release preparation | [RELEASING.md](RELEASING.md) |

Run the following development checks from the repository root. The full upstream matrix still requires an environment prepared according to the [contributing guide](../CONTRIBUTING.md):

```bash
python beacon/scripts/check-version.py
python -m unittest discover -s beacon/tests
uvx --from uv==0.12.1 uv lock --check
uvx --from uv==0.12.1 uv run --frozen --package beacon-otel --with pytest pytest -q beacon-otel/tests
uvx --from uv==0.12.1 uv run --frozen --package beacon-profiling --with pytest pytest -q sdk-extension/beacon-profiling/tests
```

The repository currently provides `beacon-otel`, the `beacon` command, and `beacon-profiling`. Stable release `1.1.0` embeds opt-in Beacon Security in `beacon-otel`. Security remains disabled by default, follows the pinned schema and fingerprint version 1 contract, and does not create local files unless explicitly enabled. Its migration and contract provenance are recorded in [`security-migration.lock.json`](security-migration.lock.json), while language-specific use and Kubernetes configuration are documented in the [`beacon-otel` README](../beacon-otel/README.md#beacon-security). The default profile export interval is configurable and set to 60 seconds. See [`validation/1.1.0.md`](validation/1.1.0.md) for the release acceptance record and [`validation/0.1.0rc2.md`](validation/0.1.0rc2.md) for backend evidence. The legacy `gtrace` distribution has been removed from this repository. Inherited upstream or legacy-repository release workflows must not be treated as Beacon release entry points.
