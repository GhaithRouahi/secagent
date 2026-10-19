"""Network connection monitoring (TCP, IPv4 + IPv6).

Backends
--------
``ebpf``  bpftrace kprobes on tcp_connect / inet_csk_accept / inet_listen (bpf/net.bt).
          Sees every connection *attempt*, including SYNs to closed ports.
``proc``  Polls /proc/net/tcp{,6} and maps socket inodes to processes through
          /proc/<pid>/fd. Only sees sockets that exist at poll time, so refused or
          very short connections can be missed. Needs root to attribute other users'
          sockets to a process.

Emitted events
  net_connect  outbound:  pid, process_name, src_ip, src_port, dst_ip, dst_port, dst, family
  net_accept   inbound:   pid, process_name, local_ip, local_port, src_ip, src_port, family
  net_listen   listening: pid, process_name, local_ip, local_port, family
(all events also carry ``direction`` and ``backend``)
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass
from typing import Any

from secagent.daemon import procfs
from secagent.daemon.bpftrace import BPF_DIR, BpftraceProcess, ebpf_supported
from secagent.daemon.monitor import Monitor, Publish
from secagent.events import NET_ACCEPT, NET_CONNECT, NET_LISTEN

TCP_STATES = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 10: "LISTEN"}


@dataclass(frozen=True)
class SockEntry:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: int
    uid: int
    inode: int
    family: int  # 4 or 6


def normalize_ip(ip: str) -> str:
    """Canonical text form; IPv4-mapped IPv6 (::ffff:1.2.3.4) becomes plain IPv4 so a
    single rule matches both stacks."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def decode_addr(hexaddr: str) -> str:
    """Decode the address column of /proc/net/tcp{,6}. The kernel prints the raw
    in-memory bytes as native-endian 32-bit words."""
    raw = bytes.fromhex(hexaddr)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", struct.unpack(">I", raw)[0]))
    words = struct.unpack(">4I", raw)
    return normalize_ip(socket.inet_ntop(socket.AF_INET6, struct.pack("<4I", *words)))


def parse_proc_net_tcp(text: str, family: int) -> list[SockEntry]:
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            lip, lport = parts[1].split(":")
            rip, rport = parts[2].split(":")
            out.append(SockEntry(local_ip=decode_addr(lip), local_port=int(lport, 16),
                                 remote_ip=decode_addr(rip), remote_port=int(rport, 16),
                                 state=int(parts[3], 16), uid=int(parts[7]),
                                 inode=int(parts[9]), family=family))
        except (ValueError, OSError):
            continue
    return out


def connect_event(pid, name, family, src_ip, src_port, dst_ip, dst_port, backend) -> dict[str, Any]:
    dst_ip = normalize_ip(dst_ip)
    return {"pid": pid, "process_name": name, "family": f"ipv{family}",
            "src_ip": normalize_ip(src_ip), "src_port": src_port, "dst_ip": dst_ip,
            "dst_port": dst_port, "dst": f"{dst_ip}:{dst_port}", "direction": "outbound",
            "backend": backend}


def accept_event(pid, name, family, local_ip, local_port, src_ip, src_port, backend) -> dict[str, Any]:
    return {"pid": pid, "process_name": name, "family": f"ipv{family}",
            "local_ip": normalize_ip(local_ip), "local_port": local_port,
            "src_ip": normalize_ip(src_ip), "src_port": src_port, "direction": "inbound",
            "backend": backend}


def listen_event(pid, name, family, local_ip, local_port, backend) -> dict[str, Any]:
    return {"pid": pid, "process_name": name, "family": f"ipv{family}",
            "local_ip": normalize_ip(local_ip), "local_port": local_port,
            "direction": "listen", "backend": backend}


class NetworkMonitor(Monitor):
    name = "network"

    def __init__(self, publish: Publish, backend: str = "auto", poll_interval: float = 0.5,
                 proc_root: str = procfs.PROC) -> None:
        super().__init__(publish)
        if backend not in ("auto", "ebpf", "proc"):
            raise ValueError(f"unknown network backend {backend!r}")
        self.requested_backend = backend
        self.poll_interval = poll_interval
        self.proc_root = proc_root
        self.ignore_pids: set[int] = {os.getpid()}
        self.fallback_reason: str | None = None
        self._bpf: BpftraceProcess | None = None
        self._seen: set[int] = set()
        self._inode_pid: dict[int, int] = {}

    def _start(self) -> None:
        if self.requested_backend in ("auto", "ebpf"):
            ok, why = ebpf_supported()
            if ok and self._start_ebpf():
                return
            reason = why if not ok else f"bpftrace failed to attach: {self.last_error}"
            if self.requested_backend == "ebpf":
                raise RuntimeError(f"eBPF network backend unavailable: {reason}")
            self.fallback_reason = reason
            self.log.warning("eBPF unavailable (%s); falling back to /proc/net polling", reason)
        self.backend = "proc"
        self.snapshot()
        self.spawn(self._poll_loop, "proc-poller")

    def _stop(self) -> None:
        if self._bpf:
            self._bpf.stop()

    def status(self) -> dict[str, Any]:
        st = super().status()
        st["fallback_reason"] = self.fallback_reason
        return st

    # ------------------------------------------------------------ eBPF
    def _start_ebpf(self) -> bool:
        self._bpf = BpftraceProcess(BPF_DIR / "net.bt")
        try:
            self._bpf.start()
        except Exception as e:
            self.record_error(str(e))
            return False
        if self._bpf.pid:
            self.ignore_pids.add(self._bpf.pid)
        self.spawn(self._ebpf_reader, "ebpf-reader")
        if not self._bpf.wait_attached():
            self.record_error(self._bpf.stderr_tail or "attach timeout")
            self._bpf.stop()
            self._bpf = None
            return False
        self.backend = "ebpf"
        return True

    def _ebpf_reader(self) -> None:
        bpf = self._bpf
        assert bpf is not None
        for rec in bpf.records():
            if self.stopping:
                return
            try:
                self.handle_bpf_record(rec)
            except Exception as e:
                self.record_error(f"bad bpf record {rec!r}: {e}")
        if not self.stopping:
            self.record_error(f"bpftrace exited: {bpf.stderr_tail}")

    def handle_bpf_record(self, rec: list) -> None:
        if not isinstance(rec, list) or len(rec) != 9:
            return
        kind, _kpid, pid, comm, fam, lip, lport, rip, rport = rec
        pid = int(pid) or None  # 0 = outside our PID namespace
        if pid in self.ignore_pids:
            return
        if kind == "connect":
            self.emit(NET_CONNECT, connect_event(pid, comm, fam, lip, int(lport), rip, int(rport), "ebpf"))
        elif kind == "accept":
            self.emit(NET_ACCEPT, accept_event(pid, comm, fam, lip, int(lport), rip, int(rport), "ebpf"))
        elif kind == "listen":
            self.emit(NET_LISTEN, listen_event(pid, comm, fam, lip, int(lport), "ebpf"))

    # ------------------------------------------------------------ /proc polling
    def read_sockets(self) -> list[SockEntry]:
        socks: list[SockEntry] = []
        for fname, fam in (("tcp", 4), ("tcp6", 6)):
            try:
                with open(f"{self.proc_root}/net/{fname}") as f:
                    socks.extend(parse_proc_net_tcp(f.read(), fam))
            except OSError:
                continue
        return socks

    def snapshot(self) -> None:
        """Baseline existing sockets so startup doesn't report every open connection."""
        self._seen = {s.inode for s in self.read_sockets() if s.inode}

    def _poll_loop(self) -> None:
        while not self.sleep(self.poll_interval):
            self.poll_once()

    def _owner(self, inode: int, refresh: bool) -> tuple[int | None, str | None]:
        if refresh:
            self._inode_pid = procfs.socket_inodes_by_pid(self.proc_root)
        pid = self._inode_pid.get(inode)
        return pid, (procfs.read_comm(pid, self.proc_root) if pid else None)

    def poll_once(self) -> int:
        socks = self.read_sockets()
        current = {s.inode for s in socks if s.inode}
        new = [s for s in socks if s.inode and s.inode not in self._seen]
        self._seen = current
        if not new:
            return 0
        listening = {s.local_port for s in socks if s.state == 10}
        refreshed = False
        emitted = 0
        for s in new:
            if s.state not in TCP_STATES:
                continue
            pid, name = self._owner(s.inode, refresh=not refreshed)
            refreshed = True
            if pid in self.ignore_pids:
                continue
            if s.state == 10:
                self.emit(NET_LISTEN, listen_event(pid, name, s.family, s.local_ip, s.local_port, "proc"))
            elif s.local_port in listening:
                self.emit(NET_ACCEPT, accept_event(pid, name, s.family, s.local_ip, s.local_port,
                                                   s.remote_ip, s.remote_port, "proc"))
            else:
                self.emit(NET_CONNECT, connect_event(pid, name, s.family, s.local_ip, s.local_port,
                                                     s.remote_ip, s.remote_port, "proc"))
            emitted += 1
        return emitted
