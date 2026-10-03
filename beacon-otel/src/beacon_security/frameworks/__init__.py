"""Fail-open framework lifecycle and HTTP source adapters.

The adapters deliberately create no OpenTelemetry spans.  They only create a
request state, bind an already-current server span when one exists, and hand
framework-returned values to the shared runtime source API.
"""

from __future__ import annotations

import threading

from ..patching import Patches
from ._common import observe_access as _observe_access

_lock = threading.RLock()
_patches: Patches | None = None
_seen: set[tuple[int, str]] = set()
_adapters: tuple[str, ...] = ()


async def _uvicorn_shutdown(wrapped, instance, args, kwargs):
    try:
        return await wrapped(*args, **kwargs)
    finally:
        # Uvicorn re-raises SIGTERM after graceful shutdown, which can bypass
        # atexit. Drain here without changing signal handlers or provider life.
        try:
            from .. import runtime

            await runtime.aflush()
        except Exception:
            pass


def observe_access(container, key, result, location=""):
    """Observe an already-completed subscript and always return ``result``."""

    try:
        return _observe_access(container, key, result, location)
    except BaseException:
        return result


def install() -> list[str]:
    """Install available framework adapters before or after app import."""

    global _patches, _adapters
    with _lock:
        if _patches is not None:
            return list(_adapters)

        patches = Patches()
        seen: set[tuple[int, str]] = set()
        adapters: set[str] = set()
        try:
            from . import _asgi, _django, _flask

            adapters.update(_asgi.install(patches, seen))
            adapters.update(_flask.install(patches, seen))
            adapters.update(_django.install(patches, seen))
            from .. import config, runtime

            try:
                if config.dependency_supported("uvicorn", ">=0.52,<0.53"):
                    from uvicorn import Server

                    if patches.wrap(Server, "shutdown", _uvicorn_shutdown):
                        adapters.add("uvicorn.shutdown")
            except Exception as error:
                runtime.startup_gap(
                    "server_shutdown_hook_failed:" + type(error).__name__
                )
        except Exception:
            # Do not hide adapter programming errors from the caller.  The
            # caller owns startup-gap reporting; restore our partial patches
            # before allowing a retry.
            patches.restore()
            raise
        _patches = patches
        _seen.clear()
        _seen.update(seen)
        _adapters = tuple(sorted(adapters))
        return list(_adapters)


def uninstall() -> None:
    """Restore only patches installed by this package."""

    global _patches, _adapters
    with _lock:
        if _patches is not None:
            _patches.restore()
        _patches = None
        _seen.clear()
        _adapters = ()
