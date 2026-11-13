from __future__ import annotations

from os import environ

from opentelemetry.sdk.environment_variables import OTEL_EXPORTER_OTLP_PROTOCOL
from opentelemetry.sdk.extension.profiling.environment_variables import (
    OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL,
)
from opentelemetry.sdk.extension.profiling.export.grpc import (
    OTLPProfileExporter,
)
from opentelemetry.sdk.extension.profiling.export.http import (
    OTLPHTTPProfileExporter,
)
from opentelemetry.sdk.extension.profiling.export.pprof_http import (
    PPROFHTTPExporter as CompatiblePPROFExporter,
)

__all__ = ("CompatiblePPROFExporter", "create_otlp_profile_exporter")


def create_otlp_profile_exporter():
    protocol = environ.get(
        OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL,
        environ.get(OTEL_EXPORTER_OTLP_PROTOCOL, "grpc"),
    )
    if protocol == "grpc":
        return OTLPProfileExporter()
    if protocol == "http/protobuf":
        return OTLPHTTPProfileExporter()
    raise ValueError(f"Unsupported OTLP profiles protocol: {protocol}")
