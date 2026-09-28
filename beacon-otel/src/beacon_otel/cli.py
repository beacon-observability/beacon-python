"""Beacon Python command-line entry point."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, distribution

from beacon_otel.version import __version__

from opentelemetry.instrumentation.auto_instrumentation import run


def main() -> None:
    """Launch an application with the Beacon distro selected by default."""
    args = sys.argv[1:]
    if args == ["--version"]:
        print(f"Beacon Python {__version__}")
        return
    if not args or args[0] in ("-h", "--help"):
        print("usage: beacon [OTEL options] COMMAND [ARGS ...]")
        print("Run a Python application with Beacon auto-instrumentation.")
        print(
            "Configure telemetry with standard OTEL_* environment variables."
        )
        if not args:
            raise SystemExit(2)
        return

    try:
        distribution("guance-sdk-extension-profiling")
    except PackageNotFoundError:
        pass
    else:
        raise SystemExit(
            "Beacon Python cannot run alongside a conflicting legacy "
            "profiling package. Remove that package from this environment "
            "before launching with beacon."
        )

    os.environ.setdefault("OTEL_PYTHON_DISTRO", "beacon")
    os.environ.setdefault("OTEL_PYTHON_CONFIGURATOR", "beacon")

    run()
