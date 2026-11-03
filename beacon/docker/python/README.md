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
2. Update `requirements.in` and regenerate `requirements.lock` using the public
   index. Commit and review the dependency lock before publication:

   ```bash
   uv --no-config pip compile beacon/docker/python/requirements.in \
     --python-version 3.13 --universal --generate-hashes --no-emit-index-url \
     --index-url https://pypi.org/simple \
     --output-file beacon/docker/python/requirements.lock
   ```

3. Configure the `beacon-release` GitHub environment to require maintainer review
   and permit only `main`. Run **Beacon Python image** on `main` with the matching
   `X.Y.Z` input. Preparation compares both public wheel hashes and bytes with
   the stable GitHub Release attachments and records the exact source commit.
4. Native amd64/arm64 jobs install only hash-locked binary wheels, then verify
   installed Beacon files, version, correlated OTLP HTTP/protobuf client traces,
   disabled optional features, pprof multipart uploads, and opt-in Security SBOM
   delivery. Tests run as non-root with a read-only root filesystem and no external
   network. This establishes local protocol behavior, not DataKit qualification
   or additional Security finding coverage.
5. Approve the protected environment. The workflow promotes the tested compressed
   image archives without rebuilding and rejects an existing version tag.
6. On first publication, set the GHCR package visibility to Public. Verify an
   anonymous pull of the multi-platform manifest and rerun the image smoke test
   against the published digest. Record workflow, digests, and actual scope.

PRs changing this directory build and test both architectures but never publish.
Publication uses the workflow's `GITHUB_TOKEN` with package write permission;
no PyPI credentials are needed. Interrupted untagged uploads may be retried.
Rollback uses the previous accepted image digest, or the previous accepted public
packages; immutable version tags are never moved.

Local build requires Python 3.13, GitHub CLI, and Docker:

```bash
python3 beacon/docker/python/prepare.py 1.2.4 /tmp/beacon-python-release
source=$(python3 -c 'import json; print(json.load(open("/tmp/beacon-python-release/provenance.json"))["source_commit"])')
docker build -f beacon/docker/python/Dockerfile \
  --build-arg BEACON_VERSION=1.2.4 --build-arg "BEACON_SOURCE_REVISION=$source" \
  -t beacon-python-candidate /tmp/beacon-python-release
bash beacon/docker/python/verify-image.sh beacon-python-candidate 1.2.4
```

The staging directory must be empty.
