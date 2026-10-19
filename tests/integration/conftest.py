"""Harness for integration tests: a real EventBus + PolicyEngine (default policy) +
SQLite store, with one or more real monitors attached. Tests trigger real behaviour on
the host and assert that the expected alert lands in SQLite within a timeout."""

import os
import tempfile
from pathlib import Path

import pytest

from secagent.daemon.event_bus import AlertPipeline, EventBus
from secagent.daemon.policy_engine import Policy, PolicyEngine
from secagent.daemon.storage import Storage
from secagent.policy import DEFAULT_POLICY_PATH
from tests.conftest import requires_linux, wait_for

pytestmark = requires_linux


class Harness:
    def __init__(self, tmp_path: Path, policy: Policy | None = None, responder=None):
        self.storage = Storage(tmp_path / "it.db")
        self.engine = PolicyEngine(policy or Policy.from_file(DEFAULT_POLICY_PATH))
        self.pipeline = AlertPipeline(self.engine, self.storage, responder=responder,
                                      record_events=True)
        self.bus = EventBus()
        self.bus.subscribe(self.pipeline)
        self.monitors = []

    def start(self, *monitors):
        self.bus.start()
        for m in monitors:
            m.start()
            self.monitors.append(m)
        return self

    def stop(self):
        for m in self.monitors:
            m.stop()
        self.bus.wait_idle(5)
        self.bus.stop()
        self.storage.close()

    def alerts(self, rule_id=None):
        return self.storage.query_alerts(rule_id=rule_id, limit=1000)

    def wait_alert(self, rule_id, predicate=lambda data: True, timeout=10.0):
        """Wait for an alert of ``rule_id`` whose event data satisfies ``predicate``."""
        def find():
            for a in self.storage.query_alerts(rule_id=rule_id, limit=1000):
                if predicate(a["event"]["data"]):
                    return a
            return None
        return wait_for(find, timeout=timeout, interval=0.1)


@pytest.fixture
def harness(tmp_path):
    h = Harness(tmp_path)
    yield h
    h.stop()


@pytest.fixture
def scratch_dir():
    """A world-traversable directory under /tmp (pytest's tmp_path is 0700 and lives
    under /tmp/pytest-of-<user>, which unprivileged test helpers can't enter)."""
    d = tempfile.mkdtemp(prefix="secagent-it-", dir="/tmp")
    os.chmod(d, 0o755)
    yield Path(d)
    import shutil
    shutil.rmtree(d, ignore_errors=True)
