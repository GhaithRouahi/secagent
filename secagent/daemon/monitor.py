"""Base class shared by all monitors."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from secagent.events import Event

Publish = Callable[[Event], bool]


class Monitor:
    """A monitor owns one or more worker threads that observe the host and publish
    ``Event`` objects. Subclasses implement ``_start`` (spawn workers via ``spawn``)
    and optionally ``_stop`` (release OS resources)."""

    name = "base"

    def __init__(self, publish: Publish) -> None:
        self._publish = publish
        self._stop_evt = threading.Event()
        self._threads: list[threading.Thread] = []
        self.log = logging.getLogger(f"secagent.monitor.{self.name}")
        self.backend: str | None = None
        self.events_emitted = 0
        self.errors = 0
        self.last_error: str | None = None
        self.started_at: float | None = None

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self._stop_evt.clear()
        self._start()
        self.started_at = time.time()
        self.log.info("%s monitor started (backend=%s)", self.name, self.backend)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_evt.set()
        try:
            self._stop()
        finally:
            for t in self._threads:
                t.join(timeout)
            self._threads.clear()

    def _start(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _stop(self) -> None:
        pass

    @property
    def stopping(self) -> bool:
        return self._stop_evt.is_set()

    def sleep(self, seconds: float) -> bool:
        """Interruptible sleep; returns True if the monitor is stopping."""
        return self._stop_evt.wait(seconds)

    def spawn(self, target: Callable[[], None], name: str) -> threading.Thread:
        def runner() -> None:
            try:
                target()
            except Exception as e:  # keep the daemon alive, surface the failure in status
                self.record_error(f"{name} crashed: {e}")
                self.log.exception("%s worker %s crashed", self.name, name)

        t = threading.Thread(target=runner, name=f"{self.name}-{name}", daemon=True)
        t.start()
        self._threads.append(t)
        return t

    # ------------------------------------------------------------- helpers
    def emit(self, event_type: str, data: dict[str, Any], timestamp: float | None = None) -> None:
        ev = Event(type=event_type, source=self.name, data=data)
        if timestamp is not None:
            ev.timestamp = timestamp
        self.events_emitted += 1
        self._publish(ev)

    def record_error(self, msg: str) -> None:
        self.errors += 1
        self.last_error = msg

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "backend": self.backend,
            "running": self.running,
            "events": self.events_emitted,
            "errors": self.errors,
            "last_error": self.last_error,
            "started_at": self.started_at,
        }
