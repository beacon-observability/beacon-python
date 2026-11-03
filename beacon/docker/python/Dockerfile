FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f AS dependencies
WORKDIR /distribution
COPY requirements.in requirements.lock ./
COPY assets/ ./assets/
# Only hash-locked public wheels are installed. No dependency build scripts run.
RUN python -m venv /opt/beacon-python \
    && /opt/beacon-python/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: \
       --index-url https://pypi.org/simple -r requirements.lock \
    && /opt/beacon-python/bin/pip check \
    && mkdir -p /opt/beacon-python/metadata/release \
    && cp assets/*.whl /opt/beacon-python/metadata/release/ \
    && cp requirements.in requirements.lock /opt/beacon-python/metadata/
COPY provenance.json /opt/beacon-python/metadata/provenance.json
RUN chmod -R a+rX,a-w /opt/beacon-python

FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f
ARG BEACON_VERSION
ARG BEACON_SOURCE_REVISION
LABEL org.opencontainers.image.title="Beacon Python" \
      org.opencontainers.image.source="https://github.com/beacon-observability/beacon-python" \
      org.opencontainers.image.version="${BEACON_VERSION}" \
      org.opencontainers.image.revision="${BEACON_SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Published Beacon Python wheels and locked dependencies on CPython 3.13, Debian glibc"
COPY --from=dependencies /opt/beacon-python /opt/beacon-python
ENV PATH="/opt/beacon-python/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
WORKDIR /tmp
CMD ["python"]
