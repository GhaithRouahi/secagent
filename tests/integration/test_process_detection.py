"""Simulated attacks against the real process monitor (both backends)."""

import os
import shutil
import subprocess

import pytest

from secagent.daemon.process_monitor import ProcessMonitor
from tests.conftest import requires_ebpf, requires_root, wait_for

BACKENDS = ["proc", pytest.param("ebpf", marks=requires_ebpf)]


def start_monitor(harness, backend):
    mon = ProcessMonitor(harness.bus.publish, backend=backend, poll_interval=0.1)
    harness.start(mon)
    assert mon.backend == backend
    if backend == "ebpf":
        assert mon.status()["self_test"].startswith("ok"), mon.status()
    return mon


@pytest.mark.parametrize("backend", BACKENDS)
def test_webserver_spawns_shell(harness, scratch_dir, backend):
    """Simulated web-shell: a process named 'nginx' spawns bash."""
    start_monitor(harness, backend)
    fake_nginx = scratch_dir / "nginx"
    # comm of a shebang script is the script's basename -> the kernel calls it "nginx"
    fake_nginx.write_text("#!/bin/sh\nbash -c 'sleep 1.5; true'\n")
    fake_nginx.chmod(0o755)
    proc = subprocess.Popen([str(fake_nginx)])
    try:
        alert = harness.wait_alert(
            "suspicious-shell-from-webserver",
            lambda d: d["ppid"] == proc.pid and d["child_name"] == "bash")
    finally:
        proc.wait(10)
    assert alert, f"no webshell alert; alerts seen: {[a['rule_id'] for a in harness.alerts()]}"
    assert alert["severity"] == "high"
    assert alert["event"]["data"]["parent_name"] == "nginx"
    assert alert["event"]["data"]["backend"] == backend
    assert "nginx" in alert["message"] and "bash" in alert["message"]


@pytest.mark.parametrize("backend", BACKENDS)
def test_exec_from_tmp(harness, scratch_dir, backend):
    start_monitor(harness, backend)
    payload = scratch_dir / "payload"
    shutil.copy("/bin/sleep", payload)
    proc = subprocess.Popen([str(payload), "1.5"])
    try:
        alert = harness.wait_alert("exec-from-temp-dir", lambda d: d["pid"] == proc.pid)
    finally:
        proc.wait(10)
    assert alert
    assert alert["event"]["data"]["exe"] == str(payload)


@pytest.mark.parametrize("backend", BACKENDS)
def test_reverse_shell_cmdline(harness, backend):
    start_monitor(harness, backend)
    # harmless: the /dev/tcp string is only echoed, nothing connects. The trailing
    # "; true" keeps bash resident (real reverse shells are long-lived); without it bash
    # exec()s the final sleep in place and the /proc poller would never see the bash
    # cmdline - exactly the short-lived-process gap the eBPF backend closes.
    proc = subprocess.Popen(["bash", "-c", "echo /dev/tcp/10.9.9.9/4444 >/dev/null; sleep 1.5; true"])
    try:
        alert = harness.wait_alert("reverse-shell-cmdline", lambda d: d["pid"] == proc.pid)
    finally:
        proc.wait(10)
    assert alert and alert["severity"] == "critical"


@requires_root
@pytest.mark.parametrize("backend", BACKENDS)
def test_setuid_privilege_escalation(harness, scratch_dir, backend):
    """An unprivileged shell (uid 65534) runs a setuid-root binary -> euid 0."""
    if not shutil.which("setpriv"):
        pytest.skip("setpriv not available")
    start_monitor(harness, backend)
    suid = scratch_dir / "rootsleep"
    shutil.copy("/bin/sleep", suid)
    os.chown(suid, 0, 0)
    os.chmod(suid, 0o4755)
    proc = subprocess.Popen(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--",
                             "/bin/sh", "-c", f"{suid} 1.5; true"])
    try:
        alert = harness.wait_alert("privilege-escalation-to-root",
                                   lambda d: d["child_name"] == "rootsleep")
    finally:
        proc.wait(10)
    assert alert, f"alerts seen: {[a['rule_id'] for a in harness.alerts()]}"
    d = alert["event"]["data"]
    assert (d["uid"], d["euid"], d["parent_euid"]) == (65534, 0, 65534)


@requires_ebpf
def test_ebpf_catches_short_lived_process(harness, scratch_dir):
    """A process that exits in ~1 ms: invisible to polling, caught by the exec tracepoint."""
    start_monitor(harness, "ebpf")
    payload = scratch_dir / "blink"
    shutil.copy("/bin/true", payload)
    pids = []
    for _ in range(5):
        p = subprocess.Popen([str(payload)])
        p.wait()
        pids.append(p.pid)
    for pid in pids:
        assert harness.wait_alert("exec-from-temp-dir", lambda d, pid=pid: d["pid"] == pid), pid


@pytest.mark.parametrize("backend", BACKENDS)
def test_benign_process_does_not_alert(harness, backend):
    start_monitor(harness, backend)
    proc = subprocess.Popen(["/bin/sh", "-c", "sleep 1; true"])
    try:
        # the process must be *observed* (proves the monitor works) ...
        assert wait_for(lambda: any(
            e["data"]["pid"] == proc.pid
            for e in harness.storage.query_events(event_type="process_exec", limit=5000)))
    finally:
        proc.wait(10)
    harness.bus.wait_idle(3)
    # ... but must not raise any alert
    hits = [a for a in harness.alerts() if a["event"]["data"].get("pid") == proc.pid
            or a["event"]["data"].get("ppid") == proc.pid]
    assert hits == []
