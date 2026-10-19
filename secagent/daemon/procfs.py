"""Small, dependency-free readers for /proc. Every function takes ``proc_root`` so unit
tests can point it at a fake directory tree. All readers return None (never raise)
when a process disappears mid-read, which is routine on a live system."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROC = "/proc"


@dataclass
class ProcInfo:
    pid: int
    ppid: int
    comm: str
    exe: str | None
    argv: list[str] = field(default_factory=list)
    uid: int | None = None
    euid: int | None = None
    start_time: int | None = None  # clock ticks since boot (stat field 22)

    @property
    def cmdline(self) -> str:
        return " ".join(self.argv)


def _read(path: str, binary: bool = False):
    try:
        with open(path, "rb" if binary else "r", errors=None if binary else "replace") as f:
            return f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, NotADirectoryError, OSError):
        return None


def parse_stat(text: str) -> tuple[str, int, int] | None:
    """Return (comm, ppid, starttime) from /proc/<pid>/stat. The comm field is wrapped in
    parentheses and may itself contain spaces or ')' - split on the *last* ')'."""
    try:
        lpar = text.index("(")
        rpar = text.rindex(")")
    except ValueError:
        return None
    comm = text[lpar + 1:rpar]
    rest = text[rpar + 2:].split()
    # rest[0] = state (field 3), rest[1] = ppid (field 4), starttime is field 22 -> rest[19]
    try:
        return comm, int(rest[1]), int(rest[19])
    except (IndexError, ValueError):
        return None


def parse_status_uids(text: str) -> tuple[int, int] | None:
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            try:
                return int(parts[1]), int(parts[2])
            except (IndexError, ValueError):
                return None
    return None


def read_proc(pid: int, proc_root: str = PROC) -> ProcInfo | None:
    base = f"{proc_root}/{pid}"
    stat = _read(f"{base}/stat")
    if stat is None:
        return None
    parsed = parse_stat(stat)
    if parsed is None:
        return None
    comm, ppid, start = parsed
    raw_cmd = _read(f"{base}/cmdline", binary=True) or b""
    argv = [a.decode("utf-8", "replace") for a in raw_cmd.split(b"\0") if a]
    try:
        exe = os.readlink(f"{base}/exe")
    except OSError:
        exe = None
    uids = parse_status_uids(_read(f"{base}/status") or "")
    return ProcInfo(pid=pid, ppid=ppid, comm=comm, exe=exe, argv=argv,
                    uid=uids[0] if uids else None, euid=uids[1] if uids else None,
                    start_time=start)


def read_comm(pid: int, proc_root: str = PROC) -> str | None:
    c = _read(f"{proc_root}/{pid}/comm")
    return c.strip() if c else None


def read_ppid(pid: int, proc_root: str = PROC) -> int | None:
    stat = _read(f"{proc_root}/{pid}/stat")
    parsed = parse_stat(stat) if stat else None
    return parsed[1] if parsed else None


def read_start_time(pid: int, proc_root: str = PROC) -> int | None:
    stat = _read(f"{proc_root}/{pid}/stat")
    parsed = parse_stat(stat) if stat else None
    return parsed[2] if parsed else None


def read_euid(pid: int, proc_root: str = PROC) -> int | None:
    uids = parse_status_uids(_read(f"{proc_root}/{pid}/status") or "")
    return uids[1] if uids else None


def ancestors(pid: int, max_depth: int = 8, proc_root: str = PROC) -> list[str]:
    """Names of ``pid`` and its ancestors, nearest first, stopping at pid 1."""
    names: list[str] = []
    seen: set[int] = set()
    cur: int | None = pid
    while cur and cur not in seen and len(names) < max_depth:
        seen.add(cur)
        stat = _read(f"{proc_root}/{cur}/stat")
        parsed = parse_stat(stat) if stat else None
        if not parsed:
            break
        names.append(parsed[0])
        if cur == 1:
            break
        cur = parsed[1]
    return names


def list_pids(proc_root: str = PROC) -> list[int]:
    try:
        return [int(d) for d in os.listdir(proc_root) if d.isdigit()]
    except OSError:
        return []


def socket_inodes_by_pid(proc_root: str = PROC, pids: list[int] | None = None) -> dict[int, int]:
    """Map socket inode -> owning pid by scanning /proc/<pid>/fd symlinks
    (``socket:[12345]``). Needs root to see other users' processes."""
    out: dict[int, int] = {}
    for pid in pids if pids is not None else list_pids(proc_root):
        fd_dir = f"{proc_root}/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                try:
                    out.setdefault(int(target[8:-1]), pid)
                except ValueError:
                    pass
    return out


def proc_exists(pid: int, proc_root: str = PROC) -> bool:
    return Path(f"{proc_root}/{pid}").exists()
