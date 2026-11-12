from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from opentelemetry.sdk.extension.profiling.environment_variables import (
    OTEL_PROFILING_FILE_PATH,
)
from opentelemetry.sdk.extension.profiling.export.result import (
    ProfileExportResult,
)


class FileProfileExporter:
    def __init__(self, *, directory: str | None = None) -> None:
        self._directory = Path(
            directory
            or os.environ.get(OTEL_PROFILING_FILE_PATH, "otel-profiles")
        )
        self._directory.mkdir(parents=True, exist_ok=True)

    def export(self, payload: bytes) -> ProfileExportResult:
        filename = (
            self._directory / f"profile-{os.getpid()}-{uuid4().hex}.pprof"
        )
        with filename.open("xb") as handle:
            handle.write(payload)
        return ProfileExportResult.SUCCESS

    def shutdown(self) -> None:
        return None
