# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import logging
from threading import Event, Lock, Thread
from time import monotonic
from typing import Callable

_logger = logging.getLogger(__name__)


class ProfileScheduler:
    def __init__(
        self,
        capture: Callable[[], None],
        flush: Callable[[], None],
        sample_interval: float,
        export_interval: float,
    ) -> None:
        self._capture = capture
        self._flush = flush
        self._sample_interval = sample_interval
        self._export_interval = export_interval
        self._thread: Thread | None = None
        self._stop_event = Event()
        self._lock = Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = Thread(
                target=self._run,
                name="OTelProfileScheduler",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def join(self) -> None:
        thread = self._thread
        if thread is not None:
            thread.join()

    def reset_after_fork(self) -> None:
        self._thread = None
        self._stop_event = Event()
        self._lock = Lock()

    def _run(self) -> None:
        next_flush = monotonic() + self._export_interval
        while not self._stop_event.is_set():
            started = monotonic()
            try:
                self._capture()
            except Exception:
                _logger.exception(
                    "Profile capture failed; sampling will continue"
                )
            now = monotonic()
            if now >= next_flush:
                try:
                    self._flush()
                except Exception:
                    _logger.exception(
                        "Profile export failed; sampling will continue"
                    )
                next_flush = monotonic() + self._export_interval
            elapsed = monotonic() - started
            wait_for = max(0.0, self._sample_interval - elapsed)
            self._stop_event.wait(wait_for)
