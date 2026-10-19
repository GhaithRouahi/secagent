"""Brute-force detection end-to-end: injected log lines -> AuthMonitor -> alert in SQLite."""

import os
import random
import shutil
import subprocess
import time
from datetime import datetime, timezone

import pytest

from secagent.daemon.auth_monitor import AuthMonitor
from tests.conftest import IS_ROOT, wait_for


def line(msg, ident="sshd", pid=4242):
    ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="microseconds")
    return f"{ts} testhost {ident}[{pid}]: {msg}\n"


def fail_line(ip, user="root", port=50000):
    return line(f"Failed password for {user} from {ip} port {port} ssh2")


def append(path, text):
    with open(path, "a") as f:
        f.write(text)
        f.flush()


def brute_alerts(harness, ip):
    return [a for a in harness.alerts("ssh-brute-force") if a["event"]["data"]["src_ip"] == ip]


def start_auth(harness, **kw):
    mon = AuthMonitor(harness.bus.publish, poll_interval=0.1, **kw)
    harness.start(mon)
    return mon


def test_brute_force_threshold_exact(harness, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    mon = start_auth(harness, backend="file", log_path=str(log))
    ip = "203.0.113.77"
    for i in range(4):
        append(log, fail_line(ip, port=50000 + i))
    # give the tail loop ample time to consume the 4 lines, then verify silence
    assert wait_for(lambda: mon.lines_parsed >= 4, timeout=5)
    harness.bus.wait_idle(3)
    assert brute_alerts(harness, ip) == [], "fired before the 5th failure"

    append(log, fail_line(ip, port=50004))
    alert = harness.wait_alert("ssh-brute-force", lambda d: d["src_ip"] == ip, timeout=5)
    assert alert and alert["severity"] == "high"
    assert alert["event"]["data"]["_threshold"]["count"] == 5
    assert "5 failed SSH logins from 203.0.113.77" in alert["message"]

    # a 6th..10th failure inside the cooldown does not re-alert
    for i in range(5):
        append(log, fail_line(ip, port=51000 + i))
    assert wait_for(lambda: mon.lines_parsed >= 10, timeout=5)
    harness.bus.wait_idle(3)
    assert len(brute_alerts(harness, ip)) == 1


def test_interleaved_sources_counted_separately(harness, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    mon = start_auth(harness, backend="file", log_path=str(log))
    for i in range(4):
        append(log, fail_line("198.51.100.1") + fail_line("198.51.100.2"))
    assert wait_for(lambda: mon.lines_parsed >= 8, timeout=5)
    harness.bus.wait_idle(3)
    assert harness.alerts("ssh-brute-force") == []
    append(log, fail_line("198.51.100.2"))
    assert harness.wait_alert("ssh-brute-force", lambda d: d["src_ip"] == "198.51.100.2", timeout=5)
    assert brute_alerts(harness, "198.51.100.1") == []


def test_existing_history_not_replayed(harness, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(fail_line("192.0.2.1") for _ in range(10)))
    mon = start_auth(harness, backend="file", log_path=str(log))
    append(log, line("Accepted password for root from 192.0.2.5 port 1 ssh2"))
    assert harness.wait_alert("ssh-root-login", timeout=5)
    assert harness.alerts("ssh-brute-force") == []
    assert mon.lines_read == 1


def test_log_rotation_is_followed(harness, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    mon = start_auth(harness, backend="file", log_path=str(log))
    append(log, fail_line("203.0.113.5") * 2)
    assert wait_for(lambda: mon.lines_parsed >= 2, timeout=5)
    os.rename(log, tmp_path / "auth.log.1")          # logrotate
    log.write_text("")
    append(log, fail_line("203.0.113.5") * 3)
    assert harness.wait_alert("ssh-brute-force", lambda d: d["src_ip"] == "203.0.113.5", timeout=5)


def test_uid0_backdoor_account(harness, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    start_auth(harness, backend="file", log_path=str(log))
    append(log, line("new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0",
                     ident="useradd"))
    alert = harness.wait_alert("uid0-account-created", timeout=5)
    assert alert and alert["severity"] == "critical"


# ------------------------------------------------------------------ real syslog pipeline

def _logger_ok():
    return IS_ROOT and shutil.which("logger") is not None


@pytest.mark.skipif(not (_logger_ok() and os.path.exists("/var/log/auth.log")),
                    reason="needs root, logger and rsyslog writing /var/log/auth.log")
def test_real_rsyslog_pipeline(harness):
    """logger -> rsyslog -> /var/log/auth.log -> AuthMonitor -> alert."""
    start_auth(harness, backend="file", log_path="/var/log/auth.log")
    ip = f"203.0.113.{random.randint(100, 250)}"
    for i in range(5):
        subprocess.run(["logger", "-p", "auth.info", "-t", "sshd", f"--id={os.getpid()}",
                        f"Failed password for invalid user test{i} from {ip} port {40000 + i} ssh2"],
                       check=True)
    alert = harness.wait_alert("ssh-brute-force", lambda d: d["src_ip"] == ip, timeout=10)
    assert alert, "rsyslog-delivered lines did not trigger brute-force detection"
    # 5 distinct usernames from one IP is also a password spray
    assert harness.wait_alert("ssh-password-spray", lambda d: d["src_ip"] == ip, timeout=5)


@pytest.mark.skipif(not (_logger_ok() and shutil.which("journalctl")), reason="needs root, logger, journald")
def test_real_journald_pipeline(harness):
    mon = start_auth(harness, backend="journald")
    time.sleep(1.0)  # let journalctl -f reach the tail of the journal
    ip = f"198.51.100.{random.randint(100, 250)}"
    for i in range(5):
        subprocess.run(["logger", "-p", "auth.info", "-t", "sshd", f"--id={os.getpid()}",
                        f"Failed password for root from {ip} port {40000 + i} ssh2"], check=True)
    alert = harness.wait_alert("ssh-brute-force", lambda d: d["src_ip"] == ip, timeout=10)
    assert alert, f"journald backend status: {mon.status()}"
