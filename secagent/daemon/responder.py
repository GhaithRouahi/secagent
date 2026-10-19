"""Active response: kill a process or block an IP for alerts whose rule asks for it.

SAFETY MODEL - destructive actions need *both* keys:
  1. the rule declares ``action: kill_process`` or ``action: block_ip``, and
  2. the policy sets ``response.enabled: true`` (default: false).
With the master switch off, alerts still record what *would* have happened
("not executed: response disabled"). ``response.dry_run: true`` performs every safety
check and logs the exact action without executing it.

kill_process guards
  * PID-reuse protection: the target's kernel start time must equal the one recorded
    in the event, so a recycled PID is never killed.
  * never: pid <= 1, kernel threads, the agent itself or any of its ancestors, or a
    process whose name is in ``protected_processes``.
block_ip guards
  * never: an address in ``allowlist`` (loopback is always included) or an unparseable one.
  * rules live in a dedicated nftables table (``inet secagent``), never mixed with the
    host's own ruleset; entries expire automatically (``block_duration``), and
    ``nft delete table inet secagent`` removes everything. iptables is a fallback.
Circuit breaker: at most ``max_actions_per_minute`` executed actions.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from collections import deque
from typing import Any, Callable

from secagent.daemon import procfs
from secagent.events import Alert

log = logging.getLogger(__name__)

DEFAULT_PROTECTED = ["systemd", "init", "sshd", "sshd-session", "secagentd", "containerd",
                     "dockerd", "kubelet", "journald", "systemd-journal", "dbus-daemon",
                     "rsyslogd", "polkitd", "agetty", "login"]
ALWAYS_ALLOW = ["127.0.0.0/8", "::1/128"]

Runner = Callable[[list[str], str | None], subprocess.CompletedProcess]


def _run(cmd: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=10)


class Firewall:
    """IP blocking via a dedicated nftables table (preferred) or an iptables chain."""

    TABLE = "secagent"

    def __init__(self, backend: str = "auto", runner: Runner = _run) -> None:
        self.run = runner
        if backend == "auto":
            backend = "nftables" if shutil.which("nft") else "iptables" if shutil.which("iptables") else "none"
        self.backend = backend
        self._ready = False
        self._lock = threading.Lock()

    def _nft_setup(self) -> None:
        if self.run(["nft", "list", "table", "inet", self.TABLE], None).returncode == 0:
            return
        script = f"""
table inet {self.TABLE} {{
  set blocklist4 {{ type ipv4_addr; flags timeout; }}
  set blocklist6 {{ type ipv6_addr; flags timeout; }}
  chain input {{
    type filter hook input priority -10; policy accept;
    ip saddr @blocklist4 drop
    ip6 saddr @blocklist6 drop
  }}
  chain output {{
    type filter hook output priority -10; policy accept;
    ip daddr @blocklist4 drop
    ip6 daddr @blocklist6 drop
  }}
}}
"""
        r = self.run(["nft", "-f", "-"], script)
        if r.returncode != 0:
            raise RuntimeError(f"nft setup failed: {r.stderr.strip()}")

    def block(self, ip: str, duration: int) -> str:
        addr = ipaddress.ip_address(ip)
        with self._lock:
            if self.backend == "nftables":
                if not self._ready:
                    self._nft_setup()
                    self._ready = True
                setname = "blocklist4" if addr.version == 4 else "blocklist6"
                r = self.run(["nft", "add", "element", "inet", self.TABLE, setname,
                              f"{{ {addr} timeout {int(duration)}s }}"], None)
                if r.returncode != 0:
                    raise RuntimeError(r.stderr.strip())
                return f"blocked {addr} for {int(duration)}s (nftables inet {self.TABLE})"
            if self.backend == "iptables":
                tool = "iptables" if addr.version == 4 else "ip6tables"
                r = self.run([tool, "-I", "INPUT", "-s", str(addr), "-j", "DROP",
                              "-m", "comment", "--comment", "secagent"], None)
                if r.returncode != 0:
                    raise RuntimeError(r.stderr.strip())
                return f"blocked {addr} (iptables INPUT; no auto-expiry)"
        raise RuntimeError("no firewall backend (install nftables or iptables)")


class Responder:
    def __init__(self, config: dict[str, Any] | None = None, firewall: Firewall | None = None,
                 kill: Callable[[int, int], None] = os.kill, proc_root: str = procfs.PROC) -> None:
        self._kill = kill
        self.proc_root = proc_root
        self._recent: deque[float] = deque()
        self.executed = 0
        self.skipped = 0
        self._own_lineage = self._lineage(os.getpid())
        self.firewall = firewall
        self.configure(config or {})

    def configure(self, cfg: dict[str, Any]) -> None:
        """Apply the policy's ``response`` section (called again on policy reload)."""
        self.enabled = bool(cfg.get("enabled", False))
        self.dry_run = bool(cfg.get("dry_run", False))
        self.protected = set(cfg.get("protected_processes", DEFAULT_PROTECTED))
        self.allowlist = [ipaddress.ip_network(n, strict=False)
                          for n in ALWAYS_ALLOW + list(cfg.get("allowlist", []))]
        self.block_duration = int(cfg.get("block_duration", 3600))
        self.max_per_minute = int(cfg.get("max_actions_per_minute", 10))
        backend = cfg.get("firewall", "auto")
        if self.firewall is None or (backend != "auto" and backend != self.firewall.backend):
            self.firewall = Firewall(backend)

    def _lineage(self, pid: int) -> set[int]:
        out, cur = set(), pid
        while cur and cur not in out:
            out.add(cur)
            cur = procfs.read_ppid(cur, self.proc_root) or 0
        return out

    def handle(self, alert: Alert) -> str | None:
        """Decide on and (maybe) execute the rule's action. The outcome string is stored
        on the alert (``action_result``) so every decision is auditable."""
        if alert.action == "alert":
            return None
        if not self.enabled:
            result = "not executed: response disabled (set response.enabled: true)"
        else:
            try:
                if alert.action == "kill_process":
                    result = self._kill_process(alert)
                elif alert.action == "block_ip":
                    result = self._block_ip(alert)
                else:
                    result = f"skipped: unknown action {alert.action}"
            except Exception as e:  # never let a response failure break detection
                result = f"failed: {e}"
        if result.startswith(("killed", "blocked")):
            self.executed += 1
        else:
            self.skipped += 1
        alert.action_result = result
        log.warning("RESPONSE %s for %s: %s", alert.action, alert.rule_id, result)
        return result

    def _rate_ok(self) -> bool:
        now = time.monotonic()
        while self._recent and now - self._recent[0] > 60:
            self._recent.popleft()
        if len(self._recent) >= self.max_per_minute:
            return False
        self._recent.append(now)
        return True

    # ------------------------------------------------------------ kill_process
    def _kill_process(self, alert: Alert) -> str:
        data = alert.event.data
        try:
            pid = int(data.get("pid"))
        except (TypeError, ValueError):
            return "skipped: event has no pid"
        if pid <= 1:
            return f"refused: pid {pid} is protected"
        if pid in self._own_lineage:
            return f"refused: pid {pid} is the agent or one of its ancestors"
        info = procfs.read_proc(pid, self.proc_root)
        if info is None:
            return f"skipped: pid {pid} already exited"
        if info.ppid == 2 or (info.exe is None and not info.argv):
            return f"refused: pid {pid} is a kernel thread"
        if info.comm in self.protected:
            return f"refused: {info.comm} (pid {pid}) is in protected_processes"
        expected = data.get("start_time")
        if expected is not None and info.start_time != expected:
            return f"refused: pid {pid} was reused by another process (start time mismatch)"
        if self.dry_run:
            return f"dry-run: would SIGKILL pid {pid} ({info.comm})"
        if not self._rate_ok():
            return "skipped: response rate limit reached"
        self._kill(pid, signal.SIGKILL)
        return f"killed pid {pid} ({info.comm})"

    # ------------------------------------------------------------ block_ip
    def target_ip(self, alert: Alert) -> str | None:
        data = alert.event.data
        if alert.event.type == "net_connect":
            return data.get("dst_ip")  # outbound: block the C2 / scan target
        return data.get("src_ip")     # inbound / auth: block the attacker

    def _block_ip(self, alert: Alert) -> str:
        ip = self.target_ip(alert)
        if not ip:
            return "skipped: event has no IP address"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return f"refused: {ip!r} is not a valid IP address"
        if any(addr in net for net in self.allowlist):
            return f"refused: {addr} is allowlisted"
        if self.dry_run:
            return f"dry-run: would block {addr} for {self.block_duration}s"
        if not self._rate_ok():
            return "skipped: response rate limit reached"
        return self.firewall.block(str(addr), self.block_duration)
