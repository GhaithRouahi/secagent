"""Sensor self-test.

bpftrace reports "attached" before its kprobes are actually live, so an eBPF monitor
isn't trustworthy until it has *observed* something. Each eBPF monitor therefore
triggers a synthetic, uniquely-marked event (an exec, a loopback connect) and waits for
it to come back through its own probe. This both closes the startup race and proves the
sensor works end-to-end on this kernel - the result is reported in ``status``.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Callable


class Canary:
    def __init__(self) -> None:
        self.token = f"secagent-canary-{uuid.uuid4().hex[:12]}"
        self._seen = threading.Event()
        self.result: str = "pending"

    def seen(self) -> None:
        self._seen.set()

    @property
    def is_seen(self) -> bool:
        return self._seen.is_set()

    def run(self, trigger: Callable[[], None], alive: Callable[[], bool],
            timeout: float = 15.0, interval: float = 0.1) -> bool:
        """Fire ``trigger`` repeatedly until the canary is observed."""
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            if not alive():
                self.result = "failed: probe process exited"
                return False
            try:
                trigger()
            except OSError:
                pass
            if self._seen.wait(interval):
                self.result = f"ok ({(time.monotonic() - t0) * 1000:.0f} ms)"
                return True
        self.result = f"failed: canary not observed within {timeout:.0f}s"
        return False
