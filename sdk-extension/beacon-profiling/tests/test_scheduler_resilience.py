from __future__ import annotations

from threading import Event

import pytest

from opentelemetry.sdk.extension.profiling.scheduler import ProfileScheduler


@pytest.mark.parametrize("stage", ["capture", "flush"])
def test_scheduler_recovers_after_one_failed_cycle(stage: str, caplog) -> None:
    recovered = Event()
    captures = []
    flushes = []

    def capture() -> None:
        captures.append(1)
        if stage == "capture" and len(captures) == 1:
            raise RuntimeError("capture failed once")

    def flush() -> None:
        flushes.append(1)
        if stage == "flush" and len(flushes) == 1:
            raise PermissionError("export failed once")
        if len(captures) >= 2:
            recovered.set()

    scheduler = ProfileScheduler(capture, flush, 0.005, 0.005)
    scheduler.start()
    try:
        assert recovered.wait(timeout=2)
        assert scheduler._thread.is_alive()
        assert "will continue" in caplog.text
    finally:
        scheduler.stop()
        scheduler.join()
    assert not scheduler._thread.is_alive()


def test_scheduler_does_not_swallow_process_termination() -> None:
    def capture() -> None:
        raise SystemExit()

    scheduler = ProfileScheduler(capture, lambda: None, 1, 1)
    with pytest.raises(SystemExit):
        scheduler._run()
