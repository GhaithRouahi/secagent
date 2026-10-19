"""Central event pipeline: monitors -> EventBus -> AlertPipeline (policy -> responder -> storage).

Monitors run in their own threads and call ``EventBus.publish``. A single dispatcher
thread drains the queue and hands each event to subscribers, so the policy engine and
its stateful threshold windows are only ever touched from one thread.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import TYPE_CHECKING, Callable

from secagent.events import Alert, Event

if TYPE_CHECKING:
    from secagent.daemon.policy_engine import PolicyEngine
    from secagent.daemon.responder import Responder
    from secagent.daemon.storage import Storage

log = logging.getLogger(__name__)

Subscriber = Callable[[Event], None]
_STOP = object()


class EventBus:
    """Thread-safe, bounded pub/sub queue. Publishing never blocks a monitor: if the
    queue is full the event is dropped and counted, which surfaces in ``status``."""

    def __init__(self, maxsize: int = 50_000) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._subscribers: list[tuple[Subscriber, frozenset[str] | None]] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.published = 0
        self.dropped = 0
        self.processed = 0
        self.errors = 0

    def subscribe(self, fn: Subscriber, event_types: list[str] | None = None) -> None:
        with self._lock:
            self._subscribers.append((fn, frozenset(event_types) if event_types else None))

    def publish(self, event: Event) -> bool:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            return False
        self.published += 1
        return True

    def dispatch(self, event: Event) -> None:
        """Deliver one event to every interested subscriber (synchronously)."""
        with self._lock:
            subs = list(self._subscribers)
        for fn, types in subs:
            if types is not None and event.type not in types:
                continue
            try:
                fn(event)
            except Exception:  # a broken subscriber must not kill the pipeline
                self.errors += 1
                log.exception("subscriber %r failed on event %s", fn, event.type)
        self.processed += 1

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="event-bus", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                self.dispatch(item)
            finally:
                self._queue.task_done()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Block until every queued event has been dispatched (used by tests/shutdown)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.01)
        return False

    def stop(self, timeout: float = 5.0) -> None:
        if self._thread and self._thread.is_alive():
            self._queue.put(_STOP)
            self._thread.join(timeout)
        self._thread = None

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()


class AlertPipeline:
    """The bus subscriber that turns events into alerts.

    event -> (optional) store raw event -> policy engine -> responder -> store alert
          -> notify alert listeners (CLI ``tail``, dashboard)
    """

    def __init__(
        self,
        engine: "PolicyEngine",
        storage: "Storage",
        responder: "Responder | None" = None,
        record_events: bool = True,
    ) -> None:
        self.engine = engine
        self.storage = storage
        self.responder = responder
        self.record_events = record_events
        self._listeners: list[Callable[[str, dict], None]] = []
        self._lock = threading.Lock()
        self.alerts_raised = 0

    def add_listener(self, fn: Callable[[str, dict], None]) -> None:
        """``fn(kind, payload)`` is called for every event (kind="event") and alert
        (kind="alert"). Listeners must be fast and non-blocking."""
        with self._lock:
            self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[str, dict], None]) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    def _notify(self, kind: str, payload: dict) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(kind, payload)
            except Exception:
                log.exception("listener failed")

    def __call__(self, event: Event) -> list[Alert]:
        if self.record_events:
            self.storage.insert_event(event)
        self._notify("event", event.to_dict())
        alerts = self.engine.evaluate(event)
        for alert in alerts:
            if self.responder is not None:
                self.responder.handle(alert)
            self.storage.insert_alert(alert)
            self.alerts_raised += 1
            log.warning("ALERT [%s] %s: %s", alert.severity.upper(), alert.rule_id, alert.message)
            self._notify("alert", alert.to_dict())
        return alerts
