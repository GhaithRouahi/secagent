"""Process execution monitoring.

Backends
--------
``ebpf``  bpftrace on the ``sched:sched_process_exec`` tracepoint (see bpf/exec.bt).
          Sees *every* exec, including processes that live for microseconds, and reads
          credentials straight from the kernel task struct after setuid is applied.
``proc``  Polls /proc every ``poll_interval`` seconds and diffs the process table.
          Needs no privileges or tooling, but can miss processes that start and exit
          between two polls. Detects both new processes and exec-in-place
          (same pid, new image), and filters fork-without-exec children.

``auto`` (default) picks eBPF when running as root with bpftrace + kernel BTF available,
and falls back to /proc otherwise, recording why in ``status()``.

Emitted event: ``process_exec`` with fields
  pid, ppid, uid, euid, parent_euid, child_name, parent_name, exe, argv, cmdline,
  ancestors (nearest first), privilege_escalation, exe_deleted, start_time, backend
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from typing import Any

from secagent.daemon import procfs
from secagent.daemon.bpftrace import (BPF_DIR, MAX_STRLEN, BpftraceProcess, decode_argv,
                                      decode_buf, ebpf_supported)
from secagent.daemon.canary import Canary
from secagent.daemon.monitor import Monitor, Publish
from secagent.events import PROCESS_EXEC


def build_exec_event(*, pid: int, ppid: int, uid: int | None, euid: int | None,
                     parent_euid: int | None, child_name: str, parent_name: str | None,
                     exe: str | None, argv: list[str], backend: str,
                     cmdline_truncated: bool = False, proc_root: str = procfs.PROC,
                     ancestors_depth: int = 8) -> dict[str, Any]:
    chain = procfs.ancestors(ppid, ancestors_depth, proc_root) if ppid else []
    if parent_name and (not chain or chain[0] != parent_name):
        # parent already gone (or pid reused): trust the name we captured at exec time
        chain = [parent_name]
    exe_deleted = False
    if exe and exe.endswith(" (deleted)"):
        exe, exe_deleted = exe[: -len(" (deleted)")], True
    return {
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "euid": euid,
        "parent_euid": parent_euid,
        "child_name": child_name,
        "parent_name": parent_name or (chain[0] if chain else None),
        "exe": exe,
        "argv": argv,
        "cmdline": " ".join(argv) if argv else (exe or child_name),
        "cmdline_truncated": cmdline_truncated,
        "ancestors": chain,
        # Gained root across the exec boundary (setuid binary, kernel exploit, ...)
        "privilege_escalation": euid == 0 and parent_euid is not None and parent_euid != 0,
        "exe_deleted": exe_deleted,
        "start_time": procfs.read_start_time(pid, proc_root),
        "backend": backend,
    }


class ProcessMonitor(Monitor):
    name = "process"
    PENDING_TTL = 1.0  # seconds to wait for the argv record of an eBPF exec

    def __init__(self, publish: Publish, backend: str = "auto", poll_interval: float = 0.2,
                 ancestors_depth: int = 8, proc_root: str = procfs.PROC) -> None:
        super().__init__(publish)
        if backend not in ("auto", "ebpf", "proc"):
            raise ValueError(f"unknown process backend {backend!r}")
        self.requested_backend = backend
        self.poll_interval = poll_interval
        self.ancestors_depth = ancestors_depth
        self.proc_root = proc_root
        self.ignore_pids: set[int] = {os.getpid()}
        self.fallback_reason: str | None = None
        self.ns_invisible = 0
        self.canary: Canary | None = None
        self._bpf: BpftraceProcess | None = None
        self._pending: dict[int, tuple[float, list]] = {}
        self._pending_lock = threading.Lock()
        self._known: dict[int, tuple[int | None, str | None]] = {}

    # ------------------------------------------------------------ backend selection
    def _start(self) -> None:
        if self.requested_backend in ("auto", "ebpf"):
            ok, why = ebpf_supported()
            if ok and self._start_ebpf():
                return
            reason = why if not ok else f"bpftrace failed to attach: {self.last_error}"
            if self.requested_backend == "ebpf":
                raise RuntimeError(f"eBPF process backend unavailable: {reason}")
            self.fallback_reason = reason
            self.log.warning("eBPF unavailable (%s); falling back to /proc polling", reason)
        self._start_proc()

    def status(self) -> dict[str, Any]:
        st = super().status()
        st["fallback_reason"] = self.fallback_reason
        st["self_test"] = self.canary.result if self.canary and self.backend == "ebpf" else None
        return st

    def _stop(self) -> None:
        if self._bpf:
            self._bpf.stop()

    # ------------------------------------------------------------ eBPF backend
    def _start_ebpf(self) -> bool:
        self._bpf = BpftraceProcess(BPF_DIR / "exec.bt")
        try:
            self._bpf.start()
        except Exception as e:
            self.record_error(str(e))
            return False
        if self._bpf.pid:
            self.ignore_pids.add(self._bpf.pid)
        self.spawn(self._ebpf_reader, "ebpf-reader")
        self.spawn(self._pending_flusher, "ebpf-pending")
        bpf = self._bpf
        self.canary = Canary()
        true_bin = shutil.which("true") or "/bin/true"
        ok = bpf.wait_attached() and self.canary.run(
            lambda: subprocess.run([true_bin, self.canary.token], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
            alive=bpf.alive)
        if not ok:
            self.record_error(f"eBPF self-test {self.canary.result}; {bpf.stderr_tail}".strip("; "))
            bpf.stop()
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

    def handle_bpf_record(self, rec: list, now: float | None = None) -> None:
        """Join the two records exec.bt emits per exec (header, then argv) on the
        root-namespace pid, which is unique system-wide."""
        now = time.monotonic() if now is None else now
        if not isinstance(rec, list):
            return
        if len(rec) == 9:
            with self._pending_lock:
                self._pending[int(rec[0])] = (now, rec)
        elif len(rec) == 2:
            pid = int(rec[0])
            with self._pending_lock:
                pending = self._pending.pop(pid, None)
            if pending is not None:
                self._emit_bpf(pending[1], rec[1])

    def flush_pending(self, now: float | None = None) -> None:
        """Emit headers whose argv record never arrived (lost/reordered sample)."""
        now = time.monotonic() if now is None else now
        with self._pending_lock:
            stale = [pid for pid, (t, _) in self._pending.items() if now - t > self.PENDING_TTL]
            records = [self._pending.pop(pid)[1] for pid in stale]
        for header in records:
            self._emit_bpf(header, None)

    def _pending_flusher(self) -> None:
        while not self.sleep(0.5):
            self.flush_pending()

    def _emit_bpf(self, header: list, argv_buf: str | None) -> None:
        _kpid, pid, ppid, uid, euid, peuid, comm, pcomm, filename = header
        pid, ppid = int(pid), int(ppid)
        if pid == 0:
            self.ns_invisible += 1  # task lives outside our PID namespace
            return
        if pid in self.ignore_pids:  # our own bpftrace helper
            return
        if argv_buf is not None:
            argv = decode_argv(argv_buf)
            truncated = len(decode_buf(argv_buf)) >= MAX_STRLEN
        else:
            argv, truncated = [], True
        if self.canary is not None and self.canary.token in argv:
            self.canary.seen()  # our own startup self-test exec - not a real event
            return
        if truncated:
            # kernel copy hit the BPF string limit: top up from /proc if still alive
            info = procfs.read_proc(pid, self.proc_root)
            if info and info.comm == comm and info.argv:
                argv, truncated = info.argv, False
        exe = filename
        if exe and not exe.startswith("/"):
            # relative exec (./payload) - resolve against the process cwd
            try:
                exe = os.path.normpath(os.path.join(os.readlink(f"{self.proc_root}/{pid}/cwd"), exe))
            except OSError:
                pass
        try:
            if os.readlink(f"{self.proc_root}/{pid}/exe").endswith(" (deleted)"):
                exe = f"{exe} (deleted)"
        except OSError:
            pass
        data = build_exec_event(pid=pid, ppid=ppid, uid=int(uid), euid=int(euid),
                                parent_euid=int(peuid), child_name=comm, parent_name=pcomm,
                                exe=exe, argv=argv, backend="ebpf",
                                cmdline_truncated=truncated, proc_root=self.proc_root,
                                ancestors_depth=self.ancestors_depth)
        self.emit(PROCESS_EXEC, data)

    # ------------------------------------------------------------ /proc backend
    def _start_proc(self) -> None:
        self.backend = "proc"
        self.snapshot()
        self.spawn(self._poll_loop, "proc-poller")

    def snapshot(self) -> None:
        """Record the current process table without emitting events (baseline)."""
        self._known = {}
        for pid in procfs.list_pids(self.proc_root):
            self._known[pid] = self._identity(pid)

    def _identity(self, pid: int) -> tuple[int | None, str | None]:
        try:
            exe = os.readlink(f"{self.proc_root}/{pid}/exe")
        except OSError:
            exe = None
        return procfs.read_start_time(pid, self.proc_root), exe

    def _poll_loop(self) -> None:
        while not self.sleep(self.poll_interval):
            self.poll_once()

    def poll_once(self) -> int:
        """One diff of the process table. Returns the number of events emitted."""
        emitted = 0
        current: dict[int, tuple[int | None, str | None]] = {}
        for pid in procfs.list_pids(self.proc_root):
            ident = self._identity(pid)
            current[pid] = ident
            if pid in self.ignore_pids:
                continue
            prev = self._known.get(pid)
            if prev is None or prev[0] != ident[0]:
                emitted += self._on_new_process(pid)
            elif prev[1] != ident[1] and ident[1] is not None:
                emitted += self._on_new_process(pid, exec_in_place=True)
        self._known = current
        return emitted

    def _on_new_process(self, pid: int, exec_in_place: bool = False) -> int:
        info = procfs.read_proc(pid, self.proc_root)
        if info is None or (info.exe is None and not info.argv):
            return 0  # vanished, or a kernel thread
        parent = procfs.read_proc(info.ppid, self.proc_root) if info.ppid else None
        if (not exec_in_place and parent is not None and parent.exe == info.exe
                and parent.argv == info.argv):
            return 0  # fork() without exec(): not a new program
        data = build_exec_event(pid=pid, ppid=info.ppid, uid=info.uid, euid=info.euid,
                                parent_euid=parent.euid if parent else None,
                                child_name=info.comm, parent_name=parent.comm if parent else None,
                                exe=info.exe, argv=info.argv, backend="proc",
                                proc_root=self.proc_root, ancestors_depth=self.ancestors_depth)
        self.emit(PROCESS_EXEC, data)
        return 1
