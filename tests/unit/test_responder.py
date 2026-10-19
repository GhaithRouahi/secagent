"""Responder safety gating, with fake /proc, fake kill() and a recording firewall runner."""

import os
import signal
import subprocess

import pytest

from secagent.daemon.responder import Firewall, Responder
from secagent.events import Alert, Event
from tests.conftest import requires_linux
from tests.unit.test_process_monitor import FakeProc


class FakeRunner:
    def __init__(self, table_exists=False, fail=False):
        self.calls = []
        self.table_exists = table_exists
        self.fail = fail

    def __call__(self, cmd, stdin=None):
        self.calls.append((cmd, stdin))
        if cmd[:3] == ["nft", "list", "table"]:
            return subprocess.CompletedProcess(cmd, 0 if self.table_exists else 1, "", "")
        if self.fail:
            return subprocess.CompletedProcess(cmd, 1, "", "permission denied")
        return subprocess.CompletedProcess(cmd, 0, "", "")


def alert(action, etype="process_exec", **data):
    return Alert(rule_id="r", severity="high", message="m", action=action,
                 event=Event(etype, "t", data))


@pytest.fixture
def proc(tmp_path):
    fp = FakeProc(tmp_path)
    fp.add(1, 0, "systemd", "/usr/lib/systemd/systemd", ["/sbin/init"], uid=0)
    fp.add(4000, 1, "implant", "/tmp/implant", ["/tmp/implant"], uid=0, start=777)
    fp.add(4001, 1, "sshd", "/usr/sbin/sshd", ["sshd"], uid=0, start=10)
    fp.add(4002, 2, "kworker/1:0", None, [], uid=0)
    return fp


def responder(proc=None, **cfg):
    kills = []
    cfg.setdefault("enabled", True)
    r = Responder(cfg, firewall=Firewall("nftables", runner=FakeRunner()),
                  kill=lambda pid, sig: kills.append((pid, sig)),
                  proc_root=str(proc.root) if proc else "/proc")
    r._own_lineage = {os.getpid()}
    return r, kills


def test_alert_only_rules_do_nothing():
    r, kills = responder()
    a = alert("alert", pid=4000)
    assert r.handle(a) is None and a.action_result is None and kills == []


def test_disabled_by_default_records_but_never_executes(proc):
    kills = []
    r = Responder({}, kill=lambda p, s: kills.append(p), proc_root=str(proc.root))
    a = alert("kill_process", pid=4000, start_time=777)
    assert r.handle(a).startswith("not executed: response disabled")
    assert kills == [] and a.action_result.startswith("not executed")


@requires_linux
def test_kill_success(proc):
    r, kills = responder(proc)
    assert r.handle(alert("kill_process", pid=4000, start_time=777)) == "killed pid 4000 (implant)"
    assert kills == [(4000, signal.SIGKILL)]


@requires_linux
@pytest.mark.parametrize("data,expect", [
    ({"pid": 1}, "refused: pid 1 is protected"),
    ({"pid": 0}, "refused: pid 0 is protected"),
    ({}, "skipped: event has no pid"),
    ({"pid": 9999}, "skipped: pid 9999 already exited"),
    ({"pid": 4001, "start_time": 10}, "refused: sshd (pid 4001) is in protected_processes"),
    ({"pid": 4002}, "refused: pid 4002 is a kernel thread"),
    ({"pid": 4000, "start_time": 123}, "refused: pid 4000 was reused by another process (start time mismatch)"),
])
def test_kill_guards(proc, data, expect):
    r, kills = responder(proc)
    assert r.handle(alert("kill_process", **data)) == expect
    assert kills == []


@requires_linux
def test_kill_refuses_own_lineage(proc):
    r, kills = responder(proc)
    r._own_lineage = {4000}
    assert r.handle(alert("kill_process", pid=4000, start_time=777)).startswith("refused: pid 4000 is the agent")
    assert kills == []


@requires_linux
def test_kill_dry_run(proc):
    r, kills = responder(proc, dry_run=True)
    assert r.handle(alert("kill_process", pid=4000, start_time=777)) == "dry-run: would SIGKILL pid 4000 (implant)"
    assert kills == []


@requires_linux
def test_rate_limit_circuit_breaker(proc):
    r, kills = responder(proc, max_actions_per_minute=2)
    results = [r.handle(alert("kill_process", pid=4000, start_time=777)) for _ in range(4)]
    assert results[:2] == ["killed pid 4000 (implant)"] * 2
    assert results[2:] == ["skipped: response rate limit reached"] * 2
    assert len(kills) == 2


def test_block_ip_nftables_commands():
    runner = FakeRunner()
    r = Responder({"enabled": True, "block_duration": 600},
                  firewall=Firewall("nftables", runner=runner))
    res = r.handle(alert("block_ip", "auth_failure", src_ip="203.0.113.9"))
    assert res == "blocked 203.0.113.9 for 600s (nftables inet secagent)"
    setup = runner.calls[1]
    assert setup[0] == ["nft", "-f", "-"] and "table inet secagent" in setup[1]
    assert "ip saddr @blocklist4 drop" in setup[1]
    assert runner.calls[2][0] == ["nft", "add", "element", "inet", "secagent", "blocklist4",
                                  "{ 203.0.113.9 timeout 600s }"]
    r.handle(alert("block_ip", "auth_failure", src_ip="2001:db8::66"))
    assert runner.calls[-1][0][5] == "blocklist6"
    assert len(runner.calls) == 4  # table set up only once


def test_block_ip_target_direction():
    r, _ = responder()
    assert r.target_ip(alert("block_ip", "net_connect", src_ip="10.0.0.5", dst_ip="198.51.100.1")) == "198.51.100.1"
    assert r.target_ip(alert("block_ip", "auth_failure", src_ip="203.0.113.9")) == "203.0.113.9"


@pytest.mark.parametrize("ip,cfg,expect", [
    ("127.0.0.1", {}, "refused: 127.0.0.1 is allowlisted"),
    ("::1", {}, "refused: ::1 is allowlisted"),
    ("10.1.2.3", {"allowlist": ["10.0.0.0/8"]}, "refused: 10.1.2.3 is allowlisted"),
    ("not-an-ip", {}, "refused: 'not-an-ip' is not a valid IP address"),
    ("203.0.113.9", {"dry_run": True}, "dry-run: would block 203.0.113.9 for 3600s"),
])
def test_block_ip_guards(ip, cfg, expect):
    r, _ = responder(**cfg)
    assert r.handle(alert("block_ip", "auth_failure", src_ip=ip)) == expect


def test_block_ip_failure_is_reported_not_raised():
    r = Responder({"enabled": True}, firewall=Firewall("nftables", runner=FakeRunner(fail=True)))
    assert r.handle(alert("block_ip", "auth_failure", src_ip="203.0.113.9")).startswith("failed: nft setup failed")


def test_iptables_backend():
    runner = FakeRunner()
    r = Responder({"enabled": True}, firewall=Firewall("iptables", runner=runner))
    assert r.handle(alert("block_ip", "auth_failure", src_ip="203.0.113.9")).startswith("blocked 203.0.113.9")
    assert runner.calls[0][0][:5] == ["iptables", "-I", "INPUT", "-s", "203.0.113.9"]
