"""secagentctl commands (against a temp DB / policy) and the dashboard JSON API."""

import json
import time

import pytest

from secagent.cli import secagentctl as ctl
from secagent.daemon.storage import Storage
from secagent.events import Alert, Event
from secagent.policy import DEFAULT_POLICY_PATH


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "a.db"
    s = Storage(path)
    now = time.time()
    s.insert_alert(Alert("exec-from-temp-dir", "high", "Executed from temp dir: /tmp/x",
                         Event("process_exec", "process", {"pid": 7, "exe": "/tmp/x"}), timestamp=now - 7200))
    s.insert_alert(Alert("ssh-brute-force", "high", "5 failed SSH logins from 203.0.113.9",
                         Event("auth_failure", "auth", {"src_ip": "203.0.113.9"}), action="block_ip",
                         action_result="not executed: response disabled", timestamp=now - 30))
    s.insert_alert(Alert("account-created", "low", "New account 'bob'",
                         Event("account_created", "auth", {"user": "bob"}), timestamp=now - 10))
    s.close()
    return str(path)


def run(capsys, *argv):
    code = ctl.main(list(argv))
    return code, capsys.readouterr().out


def test_parse_since():
    now = time.time()
    assert abs(ctl.parse_since("30m") - (now - 1800)) < 2
    assert abs(ctl.parse_since("2h") - (now - 7200)) < 2
    assert ctl.parse_since("2026-10-19T10:00") > 0
    with pytest.raises(Exception):
        ctl.parse_since("yesterday-ish")


def test_alerts_table_and_filters(capsys, db, monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")  # the table truncates to terminal width
    code, out = run(capsys, "--db", db, "alerts")
    assert code == 0
    assert "ssh-brute-force" in out and "exec-from-temp-dir" in out and "account-created" in out
    assert "RESPONSE" in out and "not executed (disabled)" in out
    _, out = run(capsys, "--db", db, "alerts", "--severity", "high", "--since", "1h")
    assert "ssh-brute-force" in out and "exec-from-temp-dir" not in out and "account-created" not in out
    _, out = run(capsys, "--db", db, "alerts", "--json", "--rule", "account-created")
    assert [a["rule_id"] for a in json.loads(out)] == ["account-created"]


def test_short_result():
    assert ctl.short_result(None) == "-"
    assert ctl.short_result("not executed: response disabled (set ...)") == "not executed (disabled)"
    assert ctl.short_result("blocked 203.0.113.9 for 600s (nftables inet secagent)") == "blocked 203.0.113.9 for 600s"
    assert ctl.short_result("killed pid 941 (bash)") == "killed pid 941 (bash)"


def test_show_alert(capsys, db):
    code, out = run(capsys, "--db", db, "show", "2")
    assert code == 0 and "Alert #2" in out and "203.0.113.9" in out
    with pytest.raises(SystemExit):
        ctl.main(["--db", db, "show", "999"])


def test_alerts_without_database_fails_cleanly(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        ctl.main(["--db", str(tmp_path / "missing.db"), "alerts"])
    assert e.value.code == 1


def test_policy_list_from_file(capsys, tmp_path):
    code, out = run(capsys, "--socket", str(tmp_path / "none.sock"), "--policy", str(DEFAULT_POLICY_PATH),
                    "policy", "list")
    assert code == 0 and "suspicious-shell-from-webserver" in out and "T1505.003" in out


def test_policy_test_match_and_no_match(capsys):
    code, out = run(capsys, "--policy", str(DEFAULT_POLICY_PATH), "policy", "test",
                    "suspicious-shell-from-webserver", "event_type=process_exec",
                    "parent_name=nginx", "child_name=bash", "pid=4242", "ppid=100", "cmdline=bash -i")
    assert code == 0 and "MATCH" in out and "nginx (pid 100) spawned bash (pid 4242)" in out
    code, out = run(capsys, "--policy", str(DEFAULT_POLICY_PATH), "policy", "test",
                    "suspicious-shell-from-webserver", "event_type=process_exec",
                    "parent_name=sshd", "child_name=bash")
    assert code == 1 and "NO MATCH" in out


def test_policy_test_json_event(capsys):
    ev = json.dumps({"type": "auth_failure", "data": {"src_ip": "1.2.3.4", "service": "sshd"}})
    code, out = run(capsys, "--policy", str(DEFAULT_POLICY_PATH), "policy", "test", "ssh-brute-force",
                    "--event", ev, "--json")
    res = json.loads(out)
    assert code == 0 and res["matched"] and res["threshold"]["count"] == 5


def test_policy_validate(capsys, tmp_path):
    code, out = run(capsys, "--policy", str(DEFAULT_POLICY_PATH), "policy", "validate")
    assert code == 0 and "rules" in out
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: x\n    match: {a: {nope: 1}}\n")
    with pytest.raises(SystemExit) as e:
        ctl.main(["--policy", str(bad), "policy", "validate"])
    assert e.value.code == 2


def test_status_without_daemon(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        ctl.main(["--socket", str(tmp_path / "nope.sock"), "status"])
    assert e.value.code == 3
    assert "not running" in capsys.readouterr().err


@pytest.mark.parametrize("etype,data,needle", [
    ("process_exec", {"parent_name": "nginx", "ppid": 1, "child_name": "bash", "pid": 2, "uid": 33, "cmdline": "bash -i"}, "nginx(1) → bash(2)"),
    ("net_connect", {"process_name": "curl", "pid": 5, "dst": "1.2.3.4:443"}, "curl(5) → 1.2.3.4:443"),
    ("file_change", {"change": "modified", "path": "/etc/passwd", "group": "identity", "old_hash": "a", "new_hash": "b"}, "modified /etc/passwd"),
])
def test_summarize_event(etype, data, needle):
    assert needle in ctl.summarize_event(etype, data)


# ------------------------------------------------------------------ dashboard API

def test_dashboard_api(db):
    from fastapi.testclient import TestClient

    from secagent.dashboard.api import create_app
    client = TestClient(create_app(Storage(db, readonly=True), status_provider=lambda: {"pid": 1}))
    assert "SecAgent" in client.get("/").text
    st = client.get("/api/status").json()
    assert st["daemon"] is True and st["pid"] == 1
    alerts = client.get("/api/alerts").json()
    assert [a["id"] for a in alerts] == [3, 2, 1]
    assert [a["id"] for a in client.get("/api/alerts?after_id=1").json()] == [3, 2]
    assert [a["id"] for a in client.get("/api/alerts?severity=high").json()] == [2, 1]
    assert client.get("/api/alerts?severity=bogus").status_code == 400
    stats = client.get("/api/stats?hours=1&bucket=60").json()
    assert stats["alerts_by_severity"]["high"] == 2 and stats["bucket_seconds"] == 60
    assert sum(b["high"] + b["low"] for b in stats["timeline"]) == 2  # the 2h-old one is outside
