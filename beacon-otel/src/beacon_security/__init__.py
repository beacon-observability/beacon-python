from __future__ import annotations

from opentelemetry.instrumentation.instrumentor import BaseInstrumentor

from .config import VERSION as __version__

__all__ = ("SecurityInstrumentor", "__version__", "bootstrap")


def bootstrap() -> None:
    from . import config

    disabled = {
        value.strip()
        for value in config.text(
            "otel.python.disabled.instrumentations"
        ).split(",")
    }
    if (
        "beacon_security" in disabled
        or "*" in disabled
        or not config.collection_configured()
    ):
        return
    from .loader import install

    install()


class SecurityInstrumentor(BaseInstrumentor):
    _active = False
    _owns_threading = False

    def instrumentation_dependencies(self) -> tuple[str, ...]:
        return ()

    def _instrument(self, **kwargs: object) -> None:
        from . import config, runtime

        if not config.lifecycle_configured():
            return
        self._active = True
        self._owns_threading = False
        try:
            bootstrap()
            adapters = []
            from opentelemetry.instrumentation.threading import (
                ThreadingInstrumentor,
            )

            from . import frameworks, sinks

            for module in (frameworks, sinks):
                try:
                    adapters.extend(module.install())
                except Exception as error:
                    runtime.startup_gap(
                        "adapter_install_failed:"
                        + module.__name__
                        + ":"
                        + type(error).__name__
                    )
            threading = ThreadingInstrumentor()
            if not threading.is_instrumented_by_opentelemetry:
                threading.instrument()
                self._owns_threading = True
            adapters.append("otel.threading")
            runtime.start(adapters)
        except BaseException:
            self._uninstrument()
            raise

    def _uninstrument(self, **kwargs: object) -> None:
        if not self._active:
            return

        from . import frameworks, runtime, sinks
        from .loader import uninstall

        try:
            runtime.stop()
        finally:
            try:
                frameworks.uninstall()
            finally:
                try:
                    sinks.uninstall()
                finally:
                    try:
                        uninstall()
                    finally:
                        owns_threading = self._owns_threading
                        self._active = False
                        self._owns_threading = False
                        if owns_threading:
                            from opentelemetry.instrumentation.threading import (
                                ThreadingInstrumentor,
                            )

                            ThreadingInstrumentor().uninstrument()
