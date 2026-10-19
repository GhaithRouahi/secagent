"""Network monitor: /proc/net parsing, inode->pid attribution, eBPF records, default rules."""

import os

import pytest

from secagent.daemon.network_monitor import (NetworkMonitor, decode_addr, normalize_ip,
                                             parse_proc_net_tcp)
from secagent.daemon.policy_engine import Policy, PolicyEngine
from secagent.events import Event
from secagent.policy import DEFAULT_POLICY_PATH
from tests.conftest import requires_linux

HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
# 127.0.0.1:8080 LISTEN, 10.0.0.5:43210 -> 93.184.216.34:443 ESTABLISHED, a TIME_WAIT (inode 0)
TCP4 = HDR + (
    "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0 100 0 0 10 0\n"
    "   1: 0500000A:A8CA 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0 20 4 30 10 -1\n"
    "   2: 0500000A:A8CB 22D8B85D:01BB 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0\n"
)
# [::1]:5432 LISTEN and an IPv4-mapped peer
TCP6 = HDR + (
    "   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 3333 1 0 100 0 0 10 0\n"
    "   1: 0000000000000000FFFF00000500000A:1538 0000000000000000FFFF00000600000A:D431 01 00000000:00000000 00:00000000 00000000   113        0 4444 1 0 20 4 30 10 -1\n"
)


def test_decode_addr():
    assert decode_addr("0100007F") == "127.0.0.1"
    assert decode_addr("22D8B85D") == "93.184.216.34"
    assert decode_addr("00000000000000000000000001000000") == "::1"
    assert decode_addr("0000000000000000FFFF00000500000A") == "10.0.0.5"  # v4-mapped -> v4


def test_normalize_ip():
    assert normalize_ip("::ffff:192.168.1.1") == "192.168.1.1"
    assert normalize_ip("2001:0db8:0000::1") == "2001:db8::1"
    assert normalize_ip("not-an-ip") == "not-an-ip"


def test_parse_proc_net_tcp():
    socks = parse_proc_net_tcp(TCP4, 4)
    assert [(s.local_ip, s.local_port, s.state, s.inode) for s in socks] == [
        ("127.0.0.1", 8080, 10, 1111), ("10.0.0.5", 43210, 1, 2222), ("10.0.0.5", 43211, 6, 0)]
    assert (socks[1].remote_ip, socks[1].remote_port, socks[1].uid) == ("93.184.216.34", 443, 1000)
    s6 = parse_proc_net_tcp(TCP6, 6)
    assert (s6[0].local_ip, s6[0].local_port) == ("::1", 5432)
    assert (s6[1].remote_ip, s6[1].remote_port) == ("10.0.0.6", 54321)
    assert parse_proc_net_tcp(HDR + "garbage line\n", 4) == []


@pytest.fixture
def fake_net(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "tcp").write_text(HDR)
    (tmp_path / "net" / "tcp6").write_text(HDR)
    return tmp_path


def add_proc(root, pid, comm, inodes):
    d = root / str(pid)
    (d / "fd").mkdir(parents=True)
    (d / "comm").write_text(comm + "\n")
    for i, inode in enumerate(inodes):
        os.symlink(f"socket:[{inode}]", d / "fd" / str(i + 3))


@requires_linux
def test_poll_classifies_listen_inbound_outbound(fake_net):
    events = []
    mon = NetworkMonitor(events.append, backend="proc", proc_root=str(fake_net))
    mon.ignore_pids = set()
    mon.snapshot()
    add_proc(fake_net, 100, "nginx", [1111, 5555])
    add_proc(fake_net, 200, "curl", [2222])
    (fake_net / "net" / "tcp").write_text(TCP4 + (
        # inbound: local port 8080 is listening
        "   3: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 5555 1 0 20 4 30 10 -1\n"))
    assert mon.poll_once() == 3
    by_type = {e.type: e.data for e in events}
    assert by_type["net_listen"]["process_name"] == "nginx" and by_type["net_listen"]["local_port"] == 8080
    assert by_type["net_connect"]["process_name"] == "curl"
    assert by_type["net_connect"]["dst"] == "93.184.216.34:443"
    assert by_type["net_accept"]["src_port"] == 50000 and by_type["net_accept"]["pid"] == 100
    assert mon.poll_once() == 0  # already seen


@requires_linux
def test_poll_snapshot_suppresses_preexisting(fake_net):
    (fake_net / "net" / "tcp").write_text(TCP4)
    events = []
    mon = NetworkMonitor(events.append, backend="proc", proc_root=str(fake_net))
    mon.snapshot()
    assert mon.poll_once() == 0 and events == []


def test_bpf_records():
    events = []
    mon = NetworkMonitor(events.append, backend="ebpf")
    mon.ignore_pids = {1}
    mon.handle_bpf_record(["connect", 9000, 900, "bash", 4, "10.0.0.5", 40000, "1.2.3.4", 4444])
    mon.handle_bpf_record(["accept", 9001, 901, "sshd", 6, "::ffff:10.0.0.5", 22, "::ffff:5.6.7.8", 50000])
    mon.handle_bpf_record(["listen", 9002, 902, "nc", 4, "0.0.0.0", 31337, "", 0])
    mon.handle_bpf_record(["connect", 9003, 1, "self", 4, "1.1.1.1", 1, "2.2.2.2", 2])  # ignored
    mon.handle_bpf_record(["bogus"])
    assert [e.type for e in events] == ["net_connect", "net_accept", "net_listen"]
    assert events[0].data["dst"] == "1.2.3.4:4444"
    assert events[1].data["src_ip"] == "5.6.7.8" and events[1].data["family"] == "ipv6"


# ------------------------------------------------------------------ default rules

@pytest.fixture
def engine():
    return PolicyEngine(Policy.from_file(DEFAULT_POLICY_PATH))


def conn(pid, name, ip, port, ts=1000.0):
    from secagent.daemon.network_monitor import connect_event
    return Event("net_connect", "t", connect_event(pid, name, 4, "10.0.0.5", 40000, ip, port, "proc"),
                 timestamp=ts)


def test_port_scan_threshold(engine):
    fired = []
    for i, port in enumerate(range(1, 15)):
        fired += [a.rule_id for a in engine.evaluate(conn(42, "nmap", "10.0.0.9", port, 1000 + i * 0.1))]
    assert "outbound-port-scan" not in fired  # 14 distinct ports: below threshold
    alerts = engine.evaluate(conn(42, "nmap", "10.0.0.9", 15, 1002))
    scan = [a for a in alerts if a.rule_id == "outbound-port-scan"]
    assert len(scan) == 1 and "15 distinct ports on 10.0.0.9" in scan[0].message


def test_port_scan_not_triggered_by_repeat_connections(engine):
    for i in range(100):  # chatty client hitting the same service
        alerts = engine.evaluate(conn(42, "curl", "10.0.0.9", 443, 1000 + i * 0.05))
        assert not [a for a in alerts if a.rule_id.startswith("outbound-")]


def test_connection_burst(engine):
    rule_ids = []
    for i in range(50):
        rule_ids += [a.rule_id for a in engine.evaluate(conn(7, "beacon", f"198.51.100.{i}", 443, 1000 + i * 0.1))]
    assert rule_ids.count("outbound-connection-burst") == 1


def test_suspicious_port_and_shell_connection(engine):
    ids = {a.rule_id for a in engine.evaluate(conn(5, "bash", "203.0.113.7", 4444))}
    assert {"outbound-suspicious-port", "shell-network-connection"} <= ids
    assert engine.evaluate(conn(6, "curl", "203.0.113.7", 443)) == []


def test_bind_shell(engine):
    from secagent.daemon.network_monitor import listen_event
    ev = Event("net_listen", "t", listen_event(9, "nc", 4, "0.0.0.0", 31337, "ebpf"))
    assert [a.rule_id for a in engine.evaluate(ev)] == ["bind-shell-listener"]
    ok = Event("net_listen", "t", listen_event(9, "nginx", 4, "0.0.0.0", 80, "ebpf"))
    assert engine.evaluate(ok) == []
