"""Auth monitor: log parsing (sshd / sudo / su / useradd), timestamps, default rules."""

import json
from datetime import datetime

import pytest

from secagent.daemon.auth_monitor import AuthMonitor, parse_auth_line, parse_timestamp
from secagent.daemon.policy_engine import Policy, PolicyEngine
from secagent.events import Event
from secagent.policy import DEFAULT_POLICY_PATH

H = "2026-10-19T16:03:58.280980+01:00 web01"
B = "Oct 19 16:03:58 web01"


@pytest.mark.parametrize("line,etype,expect", [
    (f"{H} sshd[812]: Failed password for root from 203.0.113.9 port 51234 ssh2",
     "auth_failure", {"user": "root", "src_ip": "203.0.113.9", "src_port": 51234,
                      "method": "password", "invalid_user": False}),
    (f"{B} sshd[812]: Failed password for invalid user admin from 198.51.100.4 port 2222 ssh2",
     "auth_failure", {"user": "admin", "invalid_user": True, "src_ip": "198.51.100.4"}),
    (f"{H} sshd[9]: Failed publickey for git from 2001:db8::7 port 40000 ssh2: ED25519 SHA256:abc",
     "auth_failure", {"user": "git", "method": "publickey", "src_ip": "2001:db8::7"}),
    (f"{H} sshd[9]: Accepted publickey for deploy from 10.0.0.8 port 50022 ssh2: RSA SHA256:x",
     "auth_success", {"user": "deploy", "method": "publickey", "src_ip": "10.0.0.8"}),
    (f"{H} sshd-session[9]: Accepted password for root from 10.0.0.8 port 50022 ssh2",
     "auth_success", {"user": "root", "method": "password"}),
    (f"{H} sshd[9]: Invalid user oracle from 203.0.113.50 port 33333",
     "auth_invalid_user", {"user": "oracle", "src_ip": "203.0.113.50", "src_port": 33333}),
    (f"{H} sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
     "auth_sudo", {"user": "alice", "target_user": "root", "command": "/usr/bin/id",
                   "success": True, "reason": None}),
    (f"{H} sudo:   mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
     "auth_sudo", {"user": "mallory", "success": False, "reason": "not_in_sudoers", "command": "/bin/bash"}),
    (f"{H} sudo:   bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/su",
     "auth_sudo", {"user": "bob", "reason": "incorrect_password", "attempts": 3}),
    (f"{H} sudo:   carol : TTY=pts/0 ; PWD=/ ; USER=root ; ENV=A=1 ; COMMAND=/usr/bin/env",
     "auth_sudo", {"user": "carol", "command": "/usr/bin/env"}),
    (f"{B} su[77]: FAILED SU (to root) eve on pts/3", "auth_su",
     {"user": "eve", "target_user": "root", "success": False}),
    (f"{H} useradd[5]: new user: name=sysbackup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0",
     "account_created", {"user": "sysbackup", "uid": 0, "shell": "/bin/bash"}),
])
def test_parse_lines(line, etype, expect):
    got = parse_auth_line(line)
    assert got is not None, line
    t, data, ts = got
    assert t == etype
    for k, v in expect.items():
        assert data[k] == v, (k, data)
    assert data["host"] == "web01" and data["line"] == line
    assert ts is not None


@pytest.mark.parametrize("line", [
    f"{H} sshd[812]: Connection closed by authenticating user root 203.0.113.9 port 51234 [preauth]",
    f"{H} sshd[812]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=1.2.3.4 user=root",
    f"{H} CRON[1]: pam_unix(cron:session): session opened for user root(uid=0)",
    f"{H} systemd-logind[1]: New session 4 of user root.",
    "complete garbage",
    "",
])
def test_irrelevant_lines_ignored(line):
    assert parse_auth_line(line) is None


def test_rfc3339_timestamp():
    assert parse_timestamp("2026-10-19T15:03:58+00:00") == datetime.fromisoformat("2026-10-19T15:03:58+00:00").timestamp()
    assert parse_timestamp("2026-10-19T15:03:58Z") is not None


def test_bsd_timestamp_year_rollover():
    now = datetime(2027, 1, 1, 0, 0, 5)
    ts = parse_timestamp("Dec 31 23:59:59", now)
    assert datetime.fromtimestamp(ts).year == 2026
    assert datetime.fromtimestamp(parse_timestamp("Jan  1 00:00:01", now)).year == 2027
    assert parse_timestamp("Foo 99 99:99:99", now) is None


def test_journal_entry():
    events = []
    mon = AuthMonitor(events.append, backend="journald")
    entry = {"MESSAGE": "Failed password for root from 203.0.113.9 port 4242 ssh2",
             "SYSLOG_IDENTIFIER": "sshd", "SYSLOG_PID": "99", "_HOSTNAME": "h",
             "__REALTIME_TIMESTAMP": "1792422381189010"}
    assert mon.handle_journal_entry(json.dumps(entry))
    assert events[0].type == "auth_failure" and events[0].timestamp == pytest.approx(1792422381.189010)
    # journald encodes non-UTF-8 messages as byte arrays
    entry["MESSAGE"] = list("Accepted password for root from 1.2.3.4 port 1 ssh2".encode())
    assert mon.handle_journal_entry(json.dumps(entry))
    assert events[1].type == "auth_success"
    assert not mon.handle_journal_entry("not json")


# ------------------------------------------------------------------ default rules

@pytest.fixture
def engine():
    return PolicyEngine(Policy.from_file(DEFAULT_POLICY_PATH))


def failure(ip, user, ts):
    return Event("auth_failure", "t", {"user": user, "src_ip": ip, "service": "sshd"}, timestamp=ts)


def test_brute_force_fires_on_fifth_failure_not_before(engine):
    for i in range(4):
        assert [a for a in engine.evaluate(failure("203.0.113.9", "root", 1000 + i))
                if a.rule_id == "ssh-brute-force"] == []
    alerts = [a for a in engine.evaluate(failure("203.0.113.9", "root", 1004)) if a.rule_id == "ssh-brute-force"]
    assert len(alerts) == 1
    assert alerts[0].message == "5 failed SSH logins from 203.0.113.9 within 60.0s (last tried user 'root')"
    assert alerts[0].action == "block_ip"


def test_brute_force_slow_attempts_outside_window_do_not_fire(engine):
    for i in range(10):  # one attempt every 20 s -> never 5 within 60 s
        assert [a for a in engine.evaluate(failure("203.0.113.9", "root", 1000 + i * 20))
                if a.rule_id == "ssh-brute-force"] == []


def test_password_spray_counts_distinct_users(engine):
    ids = []
    for i, user in enumerate(["root", "admin", "oracle", "postgres", "ubuntu"]):
        ids += [a.rule_id for a in engine.evaluate(failure("198.51.100.4", user, 1000 + i * 30))]
    assert "ssh-password-spray" in ids


def test_other_auth_rules(engine):
    def rules(etype, **data):
        return {a.rule_id for a in engine.evaluate(Event(etype, "t", data))}
    assert rules("auth_success", user="root", src_ip="1.2.3.4", method="password") == {"ssh-root-login"}
    assert rules("auth_success", user="deploy", src_ip="1.2.3.4") == set()
    assert rules("auth_sudo", user="m", reason="not_in_sudoers", command="x", target_user="root") == {"sudo-not-in-sudoers"}
    assert rules("auth_sudo", user="m", reason=None, success=True) == set()
    assert rules("account_created", user="x", uid=0, home="/", shell="/bin/sh") == {"uid0-account-created"}
    assert rules("account_created", user="x", uid=1001) == {"account-created"}
    assert rules("auth_su", user="e", target_user="root", success=False, tty="pts/1") == {"su-to-root-failed"}
