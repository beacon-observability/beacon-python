# Beacon Python container distribution

This directory prepares `ghcr.io/beacon-observability/beacon-python:1.2.4` from the
existing public `beacon-otel` and `beacon-profiling` wheels. The image contains
no application. Security and Profiling remain disabled by default. The image
workflow is independent of PyPI publication and never rebuilds Beacon wheels.

Only the language product version is tagged: no `v`, `latest`, runtime, or
architecture suffix. Linux amd64 and arm64 share one manifest list. Version
tags must never be overwritten; pin the published manifest digest in production.

## Runtime boundary

The initial image targets standard-GIL CPython 3.13 on Debian bookworm glibc.
It includes requests auto-instrumentation, the profiling component, and their
hash-locked dependencies. Other frameworks require their matching instrumentation
and application dependencies. The package's wider runtime support is separate
from the container acceptance scope; Alpine/musl, other Python minor versions,
and other architectures are not implied.

The image runs as `65532:65532`. The virtual environment is installed at
`/opt/beacon-python`, with original release wheels, dependency lock, and source
provenance under `metadata/`. Python wheel license metadata is retained.
No credentials, receiver endpoints, or application source are baked in.

## Application image

```dockerfile
FROM ghcr.io/beacon-observability/beacon-python:1.2.4
USER root
COPY requirements.txt /tmp/application-requirements.txt
RUN /opt/beacon-python/bin/pip install --no-cache-dir -r /tmp/application-requirements.txt \
    && /opt/beacon-python/bin/pip check
WORKDIR /srv/app
COPY . .
USER 65532:65532
CMD ["beacon", "python", "app.py"]
```

Application dependency installation must preserve the pinned Beacon and OTel
versions; resolve and check compatibility before deploying. Configure service
identity and receivers through `OTEL_*` environment variables. Explicitly enable
optional features as described in the [package guide](../../../beacon-otel/README.md).
Python applications use the bundled virtual environment and launch through
`beacon`; copying this virtual environment into arbitrary application images or
using it as a cross-runtime initContainer is outside this initial scope.

## Build and publish

1. Accept the stable public PyPI packages and matching GitHub Release first.
2. Run **Beacon Python image** from `main` with the existing `X.Y.Z` input. No source
   files, dependency locks, workflow defaults, or examples need updating for a
   routine version release. The `beacon-release` environment permits only `main`
   and requires maintainer approval.
3. One preparation job compares both public wheel hashes and bytes with the stable
   Release attachments, records the exact source commit, and uses uv to generate
   one universal CPython 3.13 dependency lock with hashes. Both architecture jobs
   consume the same checksummed Dockerfile and build-context snapshot.
4. Native amd64/arm64 jobs install only hash-locked binary wheels, then verify
   installed Beacon files, version, correlated OTLP HTTP/protobuf client traces,
   disabled optional features, compatible HTTP multipart profile uploads, and opt-in Security SBOM
   delivery. Tests run as non-root with a read-only root filesystem and no external
   network. This establishes local protocol behavior, not DataKit qualification
   or additional Security finding coverage.
5. Review the snapshot and results, then approve the protected environment. It
   promotes the tested image archives without rebuilding and rejects existing tags.
6. On first publication, set the GHCR package visibility to Public. Verify an
   anonymous pull of the manifest and repeat the smoke test against its digest.

The preparation job's build-context artifact is retained for 90 days, including
its SHA-256 checksum, generated dependency lock, original public Beacon packages,
Dockerfile and provenance. Rerunning failed candidate jobs uses that artifact;
rerunning all jobs also reuses an existing unexpired snapshot from the same run.
A new workflow run resolves a new snapshot, so specifying the same product version
alone does not promise identical transitive dependencies. For a later rebuild,
download and verify the retained snapshot instead of resolving again. The final
image also preserves the dependency lock and public Beacon artifacts. PR smoke
versions and installation examples are fixed fixtures, not a moving release selector.
Change the image implementation through PRs when packaging, runtime or validation
needs change.

PRs changing this directory build and test both architectures but never publish.
Publication uses the workflow's `GITHUB_TOKEN` with package write permission;
no PyPI credentials are needed. Interrupted untagged uploads may be retried.
Rollback uses the previous accepted image digest, or the previous accepted public
packages; immutable version tags are never moved.

Local build requires Python 3.13, uv, GitHub CLI, curl, and Docker:

```bash
python3 beacon/docker/python/prepare.py 1.2.4 /tmp/beacon-python-release
source=$(python3 -c 'import json; print(json.load(open("/tmp/beacon-python-release/provenance.json"))["source_commit"])')
docker build -f /tmp/beacon-python-release/Dockerfile \
  --build-arg BEACON_VERSION=1.2.4 --build-arg "BEACON_SOURCE_REVISION=$source" \
  -t beacon-python-candidate /tmp/beacon-python-release
bash beacon/docker/python/verify-image.sh beacon-python-candidate 1.2.4
```

The staging directory must be empty.
