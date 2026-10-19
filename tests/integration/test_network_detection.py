"""Simulated network attacks against the real network monitor."""

import shutil
import socket
import subprocess
import sys
import textwrap

import pytest

from secagent.daemon.network_monitor import NetworkMonitor
from tests.conftest import requires_ebpf, wait_for

BACKENDS = ["proc", pytest.param("ebpf", marks=requires_ebpf)]


def start_net(harness, backend):
    mon = NetworkMonitor(harness.bus.publish, backend=backend, poll_interval=0.2)
    harness.start(mon)
    assert mon.backend == backend
    if backend == "ebpf":
        assert mon.status()["self_test"].startswith("ok"), mon.status()
    return mon


class Listeners:
    """N throwaway TCP listeners on 127.0.0.1 (random free ports)."""

    def __init__(self, n):
        self.socks = []
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            s.listen(64)
            self.socks.append(s)
        self.ports = [s.getsockname()[1] for s in self.socks]

    def close(self):
        for s in self.socks:
            s.close()


def run_client(code: str) -> subprocess.Popen:
    """Run attacker-side code in a *separate process* so it has its own pid."""
    return subprocess.Popen([sys.executable, "-c", textwrap.dedent(code)])


@pytest.mark.parametrize("backend", BACKENDS)
def test_rapid_connections_to_many_ports_trigger_scan_heuristic(harness, backend):
    start_net(harness, backend)
    lst = Listeners(20)
    try:
        client = run_client(f"""
            import socket, time
            conns = [socket.create_connection(("127.0.0.1", p)) for p in {lst.ports}]
            time.sleep(2)   # hold them open long enough for the /proc poller to see
        """)
        alert = harness.wait_alert("outbound-port-scan", lambda d: d["pid"] == client.pid)
        client.wait(10)
    finally:
        lst.close()
    assert alert, f"alerts seen: {[a['rule_id'] for a in harness.alerts()]}"
    ctx = alert["event"]["data"]["_threshold"]
    assert ctx["count"] >= 15
    assert set(map(int, ctx["distinct_values"])) <= set(lst.ports)
    assert alert["severity"] == "high"


@requires_ebpf
def test_ebpf_sees_scan_of_closed_ports(harness):
    """A real port scan: most ports are closed, connections are refused instantly.
    /proc polling can't see these at all; the tcp_connect kprobe sees every SYN."""
    start_net(harness, "ebpf")
    client = run_client("""
        import socket
        for port in range(20000, 20040):
            s = socket.socket(); s.settimeout(0.2)
            try: s.connect(("127.0.0.1", port))
            except OSError: pass
            s.close()
    """)
    client.wait(30)
    alert = harness.wait_alert("outbound-port-scan", lambda d: d["pid"] == client.pid)
    assert alert and alert["event"]["data"]["dst_ip"] == "127.0.0.1"


@pytest.mark.parametrize("backend", BACKENDS)
def test_bash_dev_tcp_reverse_shell_connection(harness, backend):
    start_net(harness, backend)
    lst = Listeners(1)
    port = lst.ports[0]
    try:
        # bash opens the socket itself (fd 3); `3>&-` keeps the child sleep from
        # inheriting it so /proc attribution is unambiguous
        sh = subprocess.Popen(["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{port}; sleep 1.5 3>&-; true"])
        alert = harness.wait_alert("shell-network-connection", lambda d: d["pid"] == sh.pid)
        sh.wait(10)
    finally:
        lst.close()
    assert alert and alert["severity"] == "critical"
    assert alert["event"]["data"]["dst"] == f"127.0.0.1:{port}"


@pytest.mark.parametrize("backend", BACKENDS)
def test_connection_to_c2_port(harness, backend):
    start_net(harness, backend)
    try:
        lst_sock = socket.socket()
        lst_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lst_sock.bind(("127.0.0.1", 4444))
        lst_sock.listen()
    except OSError:
        pytest.skip("port 4444 busy")
    try:
        client = run_client("""
            import socket, time
            c = socket.create_connection(("127.0.0.1", 4444)); time.sleep(1.5)
        """)
        alert = harness.wait_alert("outbound-suspicious-port", lambda d: d["pid"] == client.pid)
        client.wait(10)
    finally:
        lst_sock.close()
    assert alert and alert["event"]["data"]["dst_port"] == 4444


@pytest.mark.parametrize("backend", BACKENDS)
def test_netcat_bind_shell_listener(harness, backend):
    nc = shutil.which("nc")
    if not nc:
        pytest.skip("nc not installed")
    start_net(harness, backend)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    proc = subprocess.Popen([nc, "-l", "127.0.0.1", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        alert = harness.wait_alert("bind-shell-listener", lambda d: d["local_port"] == port)
    finally:
        proc.kill()
        proc.wait(5)
    assert alert, f"alerts seen: {[a['rule_id'] for a in harness.alerts()]}"


@pytest.mark.parametrize("backend", BACKENDS)
def test_single_normal_connection_is_observed_but_not_alerted(harness, backend):
    start_net(harness, backend)
    lst = Listeners(1)
    try:
        client = run_client(f"""
            import socket, time
            c = socket.create_connection(("127.0.0.1", {lst.ports[0]})); time.sleep(1.5)
        """)
        assert wait_for(lambda: any(
            e["data"]["pid"] == client.pid
            for e in harness.storage.query_events(event_type="net_connect", limit=5000)))
        client.wait(10)
    finally:
        lst.close()
    harness.bus.wait_idle(3)
    assert [a for a in harness.alerts() if a["event"]["data"].get("pid") == client.pid] == []
