from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import sysconfig
import uuid
from functools import lru_cache
from pathlib import Path

from beacon_otel.version import __version__ as VERSION

RULES = (
    "sql_injection",
    "command_execution",
    "command_injection",
    "ssrf",
    "http_request_input",
    "path_traversal",
)


def text(key: str, default: str = "") -> str:
    return os.environ.get(
        key.upper().replace(".", "_").replace("-", "_"), default
    )


def flag(key: str, default: bool = True) -> bool:
    return text(key, str(default)).lower() == "true"


def limit(key: str, default: int) -> int:
    try:
        return max(1, int(text(key, str(default))))
    except (ValueError, OverflowError):
        return default


def prefixes(key: str) -> tuple[str, ...]:
    return _parse_prefixes(text(key))


@lru_cache(maxsize=8)
def _parse_prefixes(value: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                item.strip().rstrip(".")
                for item in value.split(",")
                if item.strip().rstrip(".")
            }
        )
    )


def prefix_match(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".")


def included(name: str) -> bool:
    root = name.partition(".")[0]
    if root in sys.stdlib_module_names or root in {
        "beacon_security",
        "opentelemetry",
        "wrapt",
    }:
        return False
    return any(
        prefix_match(name, p)
        for p in prefixes("beacon.security.python.include")
    ) and not any(
        prefix_match(name, p)
        for p in prefixes("beacon.security.python.exclude")
    )


def supported_runtime() -> bool:
    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    return (
        platform.python_implementation() == "CPython"
        and (3, 11) <= sys.version_info[:2] < (3, 15)
        and gil
        and not sysconfig.get_config_var("Py_GIL_DISABLED")
    )


def lifecycle_configured() -> bool:
    return flag("beacon.security.enabled", False) and supported_runtime()


def collection_configured() -> bool:
    return lifecycle_configured() and bool(
        prefixes("beacon.security.python.include")
    )


def dependency_supported(distribution: str, versions: str) -> bool:
    from packaging.specifiers import SpecifierSet

    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return False
    if version in SpecifierSet(versions):
        return True
    from .runtime import startup_gap

    startup_gap(f"unsupported_dependency:{distribution}:{version}")
    return False


def runtime_identity() -> dict:
    arch = platform.machine().lower()
    arch = {
        "aarch64": "arm64",
        "amd64": "x64",
        "x86_64": "x64",
        "x86": "ia32",
        "i386": "ia32",
        "i686": "ia32",
    }.get(arch, arch)
    return {
        "language": "python",
        "implementation": platform.python_implementation().lower(),
        "version": platform.python_version(),
        "os": sys.platform,
        "architecture": arch,
        "details": {
            "gil_build": "free-threaded"
            if sysconfig.get_config_var("Py_GIL_DISABLED")
            else "standard"
        },
    }


def digest(value: str | bytes) -> str:
    return hashlib.sha256(
        value.encode("utf-8", "surrogatepass")
        if isinstance(value, str)
        else value
    ).hexdigest()


def identity() -> dict:
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    resource = getattr(getattr(provider, "resource", None), "attributes", {})
    names = (
        "service.name",
        "service.version",
        "service.namespace",
        "service.instance.id",
        "deployment.environment.name",
    )
    service = {
        key: str(resource[key])[:512] for key in names if key in resource
    }
    for entry in text("otel.resource.attributes").split(","):
        key, sep, value = entry.partition("=")
        if sep and key in names and key not in service:
            service[key] = value[:512]
    if text("otel.service.name"):
        service["service.name"] = text("otel.service.name")[:512]
    app = "app-" + digest(
        service.get("service.namespace", "")
        + "|"
        + service.get("service.name", "unknown_service:python")
    )
    return {
        "application_id": app[:1024],
        "instance_id": str(uuid.uuid4()),
        "service": service,
        "code": {
            "repository": text("beacon.security.code.repository")[:1024],
            "commit": text("beacon.security.code.commit")[:1024],
            "build_id": text("beacon.security.code.build-id")[:1024],
            "service_version": service.get("service.version", ""),
        },
        "runtime": runtime_identity(),
        "identity_status": "configured"
        if "service.name" in service
        else "fallback",
    }


def profile(adapters: list[str] | tuple[str, ...] = ()) -> str:
    versions = {}
    for name in (
        "opentelemetry-api",
        "opentelemetry-instrumentation",
        "fastapi",
        "starlette",
        "pydantic",
        "flask",
        "django",
        "uvicorn",
        "gunicorn",
        "sqlalchemy",
        "psycopg",
        "pymysql",
        "requests",
        "httpx",
        "aiohttp",
    ):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
    budgets = {
        key: limit(key, default)
        for key, default in {
            "beacon.security.max.objects": 4096,
            "beacon.security.max.nodes": 8192,
            "beacon.security.max.marks-per-object": 64,
            "beacon.security.max.findings": 32,
            "beacon.security.max.tracked.bytes": 1024 * 1024,
            "beacon.security.max.process.tracked.bytes": 64 * 1024 * 1024,
            "beacon.security.max.active.requests": 256,
            "beacon.security.requests-per-second": 1000,
            "beacon.security.evidence.max.bytes": 65536,
            "beacon.security.runs.max.bytes": 8 * 1024 * 1024,
            "beacon.security.python.max-fields": 256,
            "beacon.security.max.framework.carriers": 256,
        }.items()
    }
    return digest(
        json.dumps(
            {
                "version": VERSION,
                "runtime": runtime_identity(),
                "dependencies": versions,
                "budgets": budgets,
                "adapters": sorted(adapters),
                "include": prefixes("beacon.security.python.include"),
                "exclude": prefixes("beacon.security.python.exclude"),
                "rules": {
                    r: flag(f"beacon.security.rules.{r}.enabled")
                    for r in RULES
                },
            },
            sort_keys=True,
        )
    )


def output_directory(instance_id: str) -> Path:
    return Path(
        text(
            "beacon.security.output",
            f"./beacon-security-output/{instance_id}",
        )
    ).absolute()
