"""Minimal inotify(7) binding via ctypes - no third-party dependency (pyinotify is
unmaintained). Only what the file-integrity monitor needs."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import select
import struct
from dataclasses import dataclass

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_ISDIR = 0x40000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

DIR_MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE
            | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR)

_EVENT_HDR = struct.Struct("iIII")  # wd, mask, cookie, len


@dataclass(frozen=True)
class InotifyEvent:
    wd: int
    mask: int
    cookie: int
    name: str

    def has(self, flag: int) -> bool:
        return bool(self.mask & flag)


def parse_events(buf: bytes) -> list[InotifyEvent]:
    """Decode a buffer of packed ``struct inotify_event`` records."""
    out = []
    off = 0
    while off + _EVENT_HDR.size <= len(buf):
        wd, mask, cookie, length = _EVENT_HDR.unpack_from(buf, off)
        off += _EVENT_HDR.size
        raw = buf[off:off + length]
        off += length
        name = raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
        out.append(InotifyEvent(wd, mask, cookie, name))
    return out


class InotifyError(OSError):
    pass


class Inotify:
    def __init__(self) -> None:
        libname = ctypes.util.find_library("c") or "libc.so.6"
        self._libc = ctypes.CDLL(libname, use_errno=True)
        fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            e = ctypes.get_errno()
            raise InotifyError(e, f"inotify_init1: {os.strerror(e)}")
        self.fd = fd

    def add_watch(self, path: str, mask: int = DIR_MASK) -> int:
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(path), ctypes.c_uint32(mask))
        if wd < 0:
            e = ctypes.get_errno()
            hint = " (raise fs.inotify.max_user_watches)" if e == errno.ENOSPC else ""
            raise InotifyError(e, f"inotify_add_watch({path}): {os.strerror(e)}{hint}")
        return wd

    def rm_watch(self, wd: int) -> None:
        self._libc.inotify_rm_watch(self.fd, wd)

    def read(self, timeout: float = 0.5) -> list[InotifyEvent]:
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            return parse_events(os.read(self.fd, 256 * 1024))
        except BlockingIOError:
            return []

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
