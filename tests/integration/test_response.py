"""Active response end-to-end: real detection -> real SIGKILL / real nftables block."""

import shutil
import subprocess

import pytest

from secagent.daemon.policy_engine import Policy
from secagent.daemon.process_monitor import ProcessMonitor
from secagent.daemon.responder import Firewall, Responder
from secagent.events import Alert, Event
from tests.conftest import requires_root
from tests.integration.conftest import Harness

KILL_POLICY = """
rules:
  - id: kill-tmp-implant
    match: {event_type: process_exec, exe: {startswith: /tmp/}, child_name: implant}
    severity: critical
    action: kill_process
response:
  enabled: {enabled}
"""


def make_harness(tmp_path, enabled):
    policy = Policy.from_yaml(KILL_POLICY.replace("{enabled}", "true" if enabled else "false"))
    h = Harness(tmp_path, policy=policy, responder=Responder(policy.response))
    mon = ProcessMonitor(h.bus.publish, backend="auto", poll_interval=0.1)
    h.start(mon)
    return h


@requires_root
def test_kill_process_when_enabled(tmp_path, scratch_dir):
    h = make_harness(tmp_path, enabled=True)
    try:
        implant = scratch_dir / "implant"
        shutil.copy("/bin/sleep", implant)
        proc = subprocess.Popen([str(implant), "30"])
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.fail("implant was not killed by the responder")
        assert rc == -9, f"expected SIGKILL, got {rc}"
        alert = h.wait_alert("kill-tmp-implant", lambda d: d["pid"] == proc.pid)
        assert alert["action_result"] == f"killed pid {proc.pid} (implant)"
    finally:
        h.stop()


@requires_root
def test_kill_not_executed_when_disabled(tmp_path, scratch_dir):
    h = make_harness(tmp_path, enabled=False)
    try:
        implant = scratch_dir / "implant"
        shutil.copy("/bin/sleep", implant)
        proc = subprocess.Popen([str(implant), "30"])
        try:
            alert = h.wait_alert("kill-tmp-implant", lambda d: d["pid"] == proc.pid)
            assert alert, "detection must still happen with response disabled"
            assert alert["action_result"].startswith("not executed: response disabled")
            assert proc.poll() is None, "process must survive when response is disabled"
        finally:
            proc.kill()
            proc.wait()
    finally:
        h.stop()


@requires_root
@pytest.mark.skipif(not shutil.which("nft"), reason="nftables not installed")
def test_real_nftables_block_and_cleanup():
    if subprocess.run(["nft", "list", "table", "inet", "secagent"], capture_output=True).returncode == 0:
        pytest.skip("an inet secagent table already exists on this host; not touching it")
    r = Responder({"enabled": True, "block_duration": 120}, firewall=Firewall("nftables"))
    a = Alert(rule_id="ssh-brute-force", severity="high", message="m", action="block_ip",
              event=Event("auth_failure", "t", {"src_ip": "198.51.100.199"}))
    try:
        assert r.handle(a) == "blocked 198.51.100.199 for 120s (nftables inet secagent)"
        out = subprocess.run(["nft", "list", "set", "inet", "secagent", "blocklist4"],
                             capture_output=True, text=True, check=True).stdout
        assert "198.51.100.199" in out and "expires" in out
        # loopback stays reachable no matter what
        lo = Alert(rule_id="x", severity="high", message="m", action="block_ip",
                   event=Event("auth_failure", "t", {"src_ip": "127.0.0.1"}))
        assert r.handle(lo) == "refused: 127.0.0.1 is allowlisted"
    finally:
        subprocess.run(["nft", "delete", "table", "inet", "secagent"], capture_output=True)
