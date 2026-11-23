# Security SIEM validation

Validated locally on 2026-11-23 with CPython 3.14.3 and Security contract
`41852e7c0d6fe9c9dca04a6e8ec1ec424630fe34` (schema v2, fingerprint v1).
The runtime implements `beacon-security-siem-v1` as its only export format.
No format-selection setting or legacy v2 Body output is provided; v2 evidence
is preserved inside `message`. The bundled payload and envelope schemas match the pinned shared contract
byte-for-byte; their SHA-256 values are recorded in the migration lock.

## Automated checks

- Initial Security regression suite: 247 passed, including 15 SIEM tests.
- Review follow-up: all 22 SIEM tests passed after requiring process identity,
  including seven negative cases that remove instance_id from shared envelopes.
  Span precedence and missing-span omission remain covered.
- Ruff check/format and `git diff --check` passed for changed Python files.
- Shared SIEM fixtures cover finding occurrences, unchanged/empty inventory and
  multipart inventory identity. The enriched vector deliberately expects empty
  actor/IP and configured Resource tenant: trusted request enrichment is absent.
- Tests cover exact input-string preservation (Unicode, quotes, whitespace),
  final envelope byte limits, explicit overflow rejection, default no-evidence
  filtering, preserved v2 truncation markers, no duplicate inventory dependencies,
  stable part IDs, and real OTel SDK HTTP/protobuf transport to a local receiver.

The test environment uses the release workflow's framework constraints:
Django 5.2, FastAPI 0.141, Starlette 1.6, and Uvicorn 0.52. An initial exploratory
run against newer framework versions failed existing framework contracts;
retesting with the supported release matrix passed.

## Collector acceptance

Used the locally available `otel/opentelemetry-collector-contrib:0.135.0`
image with an isolated OTLP/HTTP receiver and file exporter. Emitted one finding
and one inventory from the actual Beacon Exporter through OTel SDK 1.45.2.
After Collector shutdown flushed its file, decoded its OTLP JSON records and
verified both event classes, the SIEM fields plus top-level instance/trace
correlation, service `siem-span-smoke`,
configured tenant `configured-tenant`, and an embedded schema-v2 message.
The final run used no format-selection environment variable and verified
finding trace and span IDs against the Collector OTLP record and embedded
payload. Both envelope and embedded evidence use `span_id`; neither emits
`server_span_id` or `current_span_id`. The active child span takes precedence
over request-entry context when associating the OTLP LogRecord.
The temporary container was stopped and removed. Local output evidence remains
at `/tmp/beacon-siem-collector-evidence/logs.jsonl` for this session only.

This establishes a local Collector path, not production backend acceptance.
Actor/IP remain empty. Inventory `success` describes local collection only;
finding outcome remains `unknown` and severity `informational`. No stable SIEM
certification or trusted request enrichment is claimed.
