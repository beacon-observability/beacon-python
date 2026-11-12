# Beacon Python Changelog

## Unreleased

- **Breaking:** profiling exporter selection now accepts `otlp` and `file` only.
  Remove pprof multipart uploads and endpoint-based exporter auto-selection.
  Local file export uses the `OTEL_PROFILING_FILE_PATH` directory and ignores
  OTLP endpoint settings. OTLP retains HTTP/protobuf and gRPC support.

## 1.2.4 (2026-11-02)

- Exclude `no_evidence` Security findings from event export by default. Set
  `BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED=true` to restore their export;
  retain `unknown`, `suspected`, and request-level evidence upgrades.

## 1.2.3 (2026-10-30)

- Converge Python Security telemetry on schema v2 while preserving fingerprint v1.
- Publish only finding and successful SBOM inventory events; simplify finding payloads and local exception matching.

The matching `beacon-otel` and `beacon-profiling` packages were published at version `1.2.3`; see [release notes](releases/1.2.3.md) and [public-artifact verification](validation/1.2.3.md).

## 1.2.2 (2026-10-28)

- Synchronize OpenTelemetry Contrib v0.66b1 with Core v1.45.1 while preserving Beacon Security and Profiling.
- Keep Beacon-owned lint checks independent of upstream formatting changes.
- Install Trio in CI and release validation so the ASGI receive-cancellation regression runs on both supported async backends.

The matching `beacon-otel` and `beacon-profiling` packages were published at version `1.2.2`; see [release notes](releases/1.2.2.md) and [public-artifact acceptance](validation/1.2.2.md).
