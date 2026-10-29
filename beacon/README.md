# Beacon Python Development Guide

This standalone repository maintains the complete [OpenTelemetry Python Contrib](https://github.com/open-telemetry/opentelemetry-python-contrib) source and history; it is not a GitHub fork. The main product repository is [beacon-observability/beacon](https://github.com/beacon-observability/beacon). The current public stable version is `1.2.2`; its release and public-artifact validation are recorded in [`validation/1.2.2.md`](validation/1.2.2.md).

The primary development branch is `main`. The initial import preserved the legacy `gtrace` commit history and merged the official `v0.65b0` release tag. The [version file](version.properties) is the only manually maintained source for the Beacon Python development version. The tags and full commits for Contrib `v0.66b1` and the corresponding Core `v1.45.1` are recorded in the [baseline record](upstream.lock.json). Actual Core development dependencies remain defined by the root [pyproject.toml](../pyproject.toml) and [uv.lock](../uv.lock) and are verified by the version-check script. See [upstream synchronization](UPSTREAM.md) for future upgrades.

Stable release `1.2.1` fixes Security request lifecycles, propagation and SQL analysis, and bounds Profiling collection, shutdown and export overhead. See [release notes](releases/1.2.1.md) for all fixes.

Stable release `1.2.2` publishes the Contrib `v0.66b1` / Core `v1.45.1` baseline while preserving Beacon Security and Profiling. See [release notes](releases/1.2.2.md) and the [public-artifact acceptance record](validation/1.2.2.md).

Version `1.2.3` prepares Security telemetry schema v2 after [PR #66](https://github.com/beacon-observability/beacon-python/pull/66). It is pending publication; see [candidate release notes](releases/1.2.3.md).

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

The repository currently provides `beacon-otel`, the `beacon` command, and `beacon-profiling`. Security is embedded in `beacon-otel`, remains disabled by default, and does not create local files unless explicitly enabled. The `1.2.3` source follows the pinned Security schema v2 and fingerprint v1 contract. Its migration and contract provenance are recorded in [`security-migration.lock.json`](security-migration.lock.json), while language-specific use and Kubernetes configuration are documented in the [`beacon-otel` README](../beacon-otel/README.md#beacon-security). The default profile export interval is configurable and set to 60 seconds. See [`validation/1.2.2.md`](validation/1.2.2.md) for the current public release acceptance record and [`validation/0.1.0rc2.md`](validation/0.1.0rc2.md) for backend evidence. The legacy `gtrace` distribution has been removed from this repository. Inherited upstream or legacy-repository release workflows must not be treated as Beacon release entry points.
