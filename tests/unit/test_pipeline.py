"""Event bus, alert pipeline and SQLite storage."""

import threading
import time

from secagent.daemon.event_bus import AlertPipeline, EventBus
from secagent.daemon.policy_engine import Policy, PolicyEngine
from secagent.daemon.storage import Storage
from secagent.events import Alert, Event

from tests.conftest import wait_for

POLICY = """
rules:
  - id: webshell
    match: {event_type: process_exec, parent_name: nginx, child_name: [sh, bash]}
    severity: high
    message: "{parent_name} -> {child_name}"
  - id: tmp-exec
    match: {event_type: process_exec, exe: {startswith: /tmp/}}
    severity: medium
"""


def test_bus_delivers_to_filtered_subscribers():
    bus = EventBus()
    got_all, got_net = [], []
    bus.subscribe(got_all.append)
    bus.subscribe(got_net.append, event_types=["net_connect"])
    bus.start()
    try:
        bus.publish(Event("process_exec", "t", {}))
        bus.publish(Event("net_connect", "t", {}))
        assert bus.wait_idle()
    finally:
        bus.stop()
    assert [e.type for e in got_all] == ["process_exec", "net_connect"]
    assert [e.type for e in got_net] == ["net_connect"]
    assert bus.processed == 2


def test_bus_survives_failing_subscriber():
    bus = EventBus()
    ok = []

    def boom(_):
        raise RuntimeError("bad subscriber")

    bus.subscribe(boom)
    bus.subscribe(ok.append)
    bus.start()
    try:
        bus.publish(Event("x", "t", {}))
        bus.publish(Event("y", "t", {}))
        assert bus.wait_idle()
    finally:
        bus.stop()
    assert len(ok) == 2
    assert bus.errors == 2


def test_bus_drops_instead_of_blocking_when_full():
    bus = EventBus(maxsize=3)  # dispatcher not started: queue fills up
    results = [bus.publish(Event("x", "t", {})) for _ in range(5)]
    assert results == [True, True, True, False, False]
    assert bus.dropped == 2


def test_bus_concurrent_publishers():
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    bus.start()

    def worker(n):
        for i in range(200):
            bus.publish(Event("x", f"w{n}", {"i": i}))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert bus.wait_idle()
    bus.stop()
    assert len(seen) == 1000


def test_pipeline_end_to_end_into_sqlite(storage):
    engine = PolicyEngine(Policy.from_yaml(POLICY))
    pipeline = AlertPipeline(engine, storage)
    notified = []
    pipeline.add_listener(lambda kind, payload: notified.append(kind))
    bus = EventBus()
    bus.subscribe(pipeline)
    bus.start()
    try:
        bus.publish(Event("process_exec", "test",
                          {"parent_name": "nginx", "child_name": "bash", "exe": "/tmp/bash"}))
        bus.publish(Event("process_exec", "test",
                          {"parent_name": "sshd", "child_name": "bash", "exe": "/usr/bin/bash"}))
        assert bus.wait_idle()
    finally:
        bus.stop()

    alerts = storage.query_alerts()
    assert sorted(a["rule_id"] for a in alerts) == ["tmp-exec", "webshell"]
    web = next(a for a in alerts if a["rule_id"] == "webshell")
    assert web["severity"] == "high"
    assert web["message"] == "nginx -> bash"
    assert web["event"]["data"]["child_name"] == "bash"   # raw event preserved
    assert web["timestamp"] > 0
    assert len(storage.query_events()) == 2
    assert notified.count("event") == 2 and notified.count("alert") == 2


def _alert(rule="r", sev="low", ts=None):
    return Alert(rule_id=rule, severity=sev, message="m",
                 event=Event("x", "t", {"k": 1}), timestamp=ts or time.time())


def test_storage_filters(storage):
    now = time.time()
    storage.insert_alert(_alert("old", "critical", now - 7200))
    storage.insert_alert(_alert("low1", "low", now))
    storage.insert_alert(_alert("high1", "high", now))
    storage.insert_alert(_alert("crit1", "critical", now))

    assert [a["rule_id"] for a in storage.query_alerts()] == ["crit1", "high1", "low1", "old"]
    assert {a["rule_id"] for a in storage.query_alerts(min_severity="high")} == {"old", "high1", "crit1"}
    assert {a["rule_id"] for a in storage.query_alerts(since=now - 60)} == {"low1", "high1", "crit1"}
    assert [a["rule_id"] for a in storage.query_alerts(rule_id="high1")] == ["high1"]
    first_id = storage.query_alerts(ascending=True, limit=1)[0]["id"]
    assert len(storage.query_alerts(after_id=first_id)) == 3


def test_storage_stats(storage):
    for sev in ["low", "high", "high", "critical"]:
        storage.insert_alert(_alert(sev=sev))
    st = storage.stats()
    assert st["alerts_by_severity"] == {"low": 1, "medium": 0, "high": 2, "critical": 1}
    assert st["alerts_total"] == 4
    assert sum(b["high"] for b in st["timeline"]) == 2


def test_storage_prune_events(storage):
    for i in range(50):
        storage.insert_event(Event("x", "t", {"i": i}))
    storage.prune_events(10)
    remaining = storage.query_events(limit=100)
    assert len(remaining) == 10
    assert remaining[0]["data"]["i"] == 49


def test_storage_readonly_reader_sees_writes(tmp_path):
    db = tmp_path / "a.db"
    w = Storage(db)
    w.insert_alert(_alert("x"))
    r = Storage(db, readonly=True)
    assert r.query_alerts()[0]["rule_id"] == "x"
    w.close()
    r.close()


def test_storage_baseline_roundtrip(storage):
    storage.set_baseline("/etc/passwd", {"sha256": "ab", "size": 1, "mode": 0o644, "uid": 0})
    assert storage.get_baseline("/etc/passwd")["sha256"] == "ab"
    storage.set_baseline("/etc/passwd", None)
    assert storage.get_baseline("/etc/passwd") is None


def test_wait_for_helper():
    t0 = time.monotonic()
    assert wait_for(lambda: time.monotonic() - t0 > 0.2, timeout=2)
