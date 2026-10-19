"""Runs a bpftrace script as a subprocess and yields its JSON-mode output records.

We use bpftrace rather than bcc because it compiles against kernel BTF
(/sys/kernel/btf/vmlinux) and needs no kernel headers. That makes it work on stock
Ubuntu/Debian *and* on kernels like WSL2 that ship without a headers package.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

log = logging.getLogger(__name__)

BPF_DIR = Path(__file__).parent / "bpf"
MAX_STRLEN = 128  # largest value that fits the exec probe in the 512-byte BPF stack


class BpftraceUnavailable(RuntimeError):
    pass


def bpftrace_path() -> str | None:
    return shutil.which("bpftrace")


def ebpf_supported() -> tuple[bool, str]:
    """Cheap pre-flight check: root, bpftrace on PATH, kernel BTF present."""
    if not hasattr(os, "geteuid"):
        return False, "not a Linux host"
    if os.geteuid() != 0:
        return False, "eBPF requires root (CAP_BPF/CAP_SYS_ADMIN)"
    if bpftrace_path() is None:
        return False, "bpftrace not installed"
    if not Path("/sys/kernel/btf/vmlinux").exists():
        return False, "kernel BTF (/sys/kernel/btf/vmlinux) not available"
    return True, "ok"


_HEX = re.compile(r"\\x([0-9a-fA-F]{2})")


def decode_buf(s: str) -> bytes:
    r"""Decode a bpftrace ``buf()`` value rendered with \xNN escapes."""
    out = bytearray()
    pos = 0
    for m in _HEX.finditer(s):
        out += s[pos:m.start()].encode("utf-8", "surrogateescape")
        out.append(int(m.group(1), 16))
        pos = m.end()
    out += s[pos:].encode("utf-8", "surrogateescape")
    return bytes(out)


def decode_argv(s: str) -> list[str]:
    return [a.decode("utf-8", "replace") for a in decode_buf(s).split(b"\0") if a]


class BpftraceProcess:
    """Owns one bpftrace subprocess. ``records()`` yields the ``data`` payload of every
    ``{"type": "value"}`` line until the process exits or ``stop()`` is called."""

    def __init__(self, script: str | Path, max_strlen: int = MAX_STRLEN,
                 attach_timeout: float = 20.0) -> None:
        self.script = str(script)
        self.max_strlen = max_strlen
        self.attach_timeout = attach_timeout
        self.proc: subprocess.Popen | None = None
        self._stderr_lines: list[str] = []
        self._attached = threading.Event()

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    def start(self) -> None:
        exe = bpftrace_path()
        if exe is None:
            raise BpftraceUnavailable("bpftrace not installed")
        env = dict(os.environ, BPFTRACE_MAX_STRLEN=str(self.max_strlen))
        self.proc = subprocess.Popen(
            [exe, "-f", "json", self.script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, env=env,
        )
        threading.Thread(target=self._drain_stderr, daemon=True, name="bpftrace-stderr").start()

    def _drain_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            line = line.rstrip()
            if line:
                self._stderr_lines.append(line)
                del self._stderr_lines[:-50]
                log.debug("bpftrace: %s", line)

    @property
    def stderr_tail(self) -> str:
        return " | ".join(self._stderr_lines[-5:])

    def records(self, on_attached: Callable[[], None] | None = None) -> Iterator[Any]:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = msg.get("type")
            if kind == "attached_probes":
                self._attached.set()
                if on_attached:
                    on_attached()
            elif kind == "value":
                yield msg.get("data")

    def wait_attached(self, timeout: float | None = None) -> bool:
        """Block until bpftrace reports its probes, or the process dies / times out.

        NB: bpftrace emits this message *before* kprobes are live (attaching takes a
        few hundred ms more), so monitors must follow up with ``self_test`` before
        declaring themselves ready."""
        deadline = time.monotonic() + (timeout or self.attach_timeout)
        while time.monotonic() < deadline:
            if self._attached.is_set():
                return True
            if self.proc is None or self.proc.poll() is not None:
                return False
            time.sleep(0.05)
        return self._attached.is_set()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
