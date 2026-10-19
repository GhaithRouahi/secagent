"""File integrity monitoring (FIM).

How it works
------------
1. Each configured path is a *watch spec*: a file, or a directory (optionally recursive),
   tagged with a ``group`` (identity, ssh, binaries, ...) that rules match on.
2. At start we hash every covered file (SHA-256) and compare against the baseline
   persisted in SQLite, so tampering that happened *while the agent was stopped* is
   reported too (``detected_at_startup: true``).
3. inotify watches are placed on *directories* (the parent of watched files). Watching a
   file's inode directly breaks on atomic replace - ``sed -i``, editors and ``passwd``
   write a temp file and rename() it over the original.
4. inotify events only mark a path dirty; after a short debounce the path is re-hashed
   and compared with its baseline, and a ``file_change`` event is emitted if content,
   permissions or ownership changed. A plain ``touch`` is not a change.
5. A periodic full rescan is the safety net for inotify queue overflow and for watch
   specs whose directory didn't exist at startup.

Backends: ``inotify`` (default) or ``poll`` (periodic rescan only, every ``poll_interval``).

Emitted event ``file_change``: path, change (created|modified|deleted|permissions), group,
  old_sha256, new_sha256, old_hash, new_hash (12-char prefixes), old_mode, new_mode,
  old_uid, new_uid, size, detected_at_startup
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_mod
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from secagent.daemon.inotify import (IN_DELETE_SELF, IN_IGNORED, IN_ISDIR, IN_MOVE_SELF,
                                     IN_Q_OVERFLOW, Inotify, InotifyError)
from secagent.daemon.monitor import Monitor, Publish
from secagent.events import FILE_CHANGE

if TYPE_CHECKING:
    from secagent.daemon.storage import Storage

MAX_DEPTH = 8


@dataclass(frozen=True)
class WatchSpec:
    path: str
    group: str = "custom"
    recursive: bool = False

    @classmethod
    def parse(cls, raw: Any) -> "WatchSpec":
        if isinstance(raw, str):
            return cls(path=os.path.normpath(raw))
        return cls(path=os.path.normpath(str(raw["path"])), group=str(raw.get("group", "custom")),
                   recursive=bool(raw.get("recursive", False)))

    def covers(self, path: str) -> bool:
        if path == self.path:
            return True
        prefix = self.path.rstrip("/") + "/"
        if not path.startswith(prefix):
            return False
        return self.recursive or "/" not in path[len(prefix):]


def file_record(path: str, max_hash_size: int) -> dict[str, Any] | None:
    """Stat + hash a regular file. Returns None if it doesn't exist (or isn't a file)."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat_mod.S_ISLNK(st.st_mode):
        # report symlinks by target, a swapped link target is a change
        try:
            target = os.readlink(path)
        except OSError:
            return None
        digest = "link:" + hashlib.sha256(target.encode()).hexdigest()
    elif stat_mod.S_ISREG(st.st_mode):
        if st.st_size > max_hash_size:
            digest = f"size:{st.st_size}:mtime:{st.st_mtime_ns}"
        else:
            h = hashlib.sha256()
            try:
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
            except OSError:
                return None
            digest = h.hexdigest()
    else:
        return None
    return {"sha256": digest, "size": st.st_size, "mode": stat_mod.S_IMODE(st.st_mode),
            "uid": st.st_uid, "gid": st.st_gid, "mtime": st.st_mtime}


def classify(old: dict | None, new: dict | None) -> str | None:
    """Compare two file records; return the kind of change or None if unchanged."""
    if old is None and new is None:
        return None
    if old is None:
        return "created"
    if new is None:
        return "deleted"
    if old.get("sha256") != new.get("sha256"):
        return "modified"
    if (old.get("mode"), old.get("uid"), old.get("gid")) != (new.get("mode"), new.get("uid"), new.get("gid")):
        return "permissions"
    return None


def _short(h: str | None) -> str:
    return h[:12] if h else "-"


def _octal(mode: int | None) -> str | None:
    return None if mode is None else f"{mode:04o}"


class FileIntegrityMonitor(Monitor):
    name = "file"

    def __init__(self, publish: Publish, watch: list[Any], store: "Storage | None" = None,
                 backend: str = "auto", debounce: float = 0.2, rescan_interval: float = 300.0,
                 poll_interval: float = 2.0, max_hash_size: int = 100 * 1024 * 1024) -> None:
        super().__init__(publish)
        if backend not in ("auto", "inotify", "poll"):
            raise ValueError(f"unknown file backend {backend!r}")
        self.specs = [WatchSpec.parse(w) for w in watch]
        self.store = store
        self.requested_backend = backend
        self.debounce = debounce
        self.rescan_interval = rescan_interval
        self.poll_interval = poll_interval
        self.max_hash_size = max_hash_size
        self._baseline: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._dirty: dict[str, float] = {}
        self._ino: Inotify | None = None
        self._wd_dirs: dict[int, str] = {}
        self._dir_wds: dict[str, int] = {}
        self.fallback_reason: str | None = None
        self.overflows = 0
        self._had_baseline = True
        self._rescan_now = False
        self._new_dir = False

    # ------------------------------------------------------------ coverage
    def spec_for(self, path: str) -> WatchSpec | None:
        # most specific spec wins (longest path)
        best = None
        for s in self.specs:
            if s.covers(path) and (best is None or len(s.path) > len(best.path)):
                best = s
        return best

    def covered_files(self) -> set[str]:
        files: set[str] = set()
        for s in self.specs:
            p = Path(s.path)
            if p.is_dir() and not p.is_symlink():
                base_depth = s.path.rstrip("/").count("/")
                for root, dirs, names in os.walk(s.path):
                    depth = root.rstrip("/").count("/") - base_depth
                    if not s.recursive or depth >= MAX_DEPTH:
                        dirs[:] = []
                    for n in names:
                        files.add(os.path.join(root, n))
            elif p.exists() or p.is_symlink():
                files.add(s.path)
        return files

    def watch_dirs(self) -> set[str]:
        """Directories that need an inotify watch to observe every spec."""
        dirs: set[str] = set()
        for s in self.specs:
            p = Path(s.path)
            if p.is_dir() and not p.is_symlink():
                dirs.add(s.path)
                if s.recursive:
                    base_depth = s.path.rstrip("/").count("/")
                    for root, subdirs, _ in os.walk(s.path):
                        if root.rstrip("/").count("/") - base_depth >= MAX_DEPTH:
                            subdirs[:] = []
                        dirs.add(root)
            # a file (or a not-yet-existing path): watch the parent so creation and
            # atomic replacement are both visible
            parent = os.path.dirname(s.path) or "/"
            if os.path.isdir(parent) and not p.is_dir():
                dirs.add(parent)
        return dirs

    # ------------------------------------------------------------ lifecycle
    def _start(self) -> None:
        self._load_baseline()
        self.scan(startup=True)
        backend = self.requested_backend
        if backend in ("auto", "inotify"):
            try:
                self._ino = Inotify()
                self._sync_watches()
                self.backend = "inotify"
                self.spawn(self._inotify_reader, "inotify-reader")
                self.spawn(self._worker, "checker")
                return
            except (OSError, InotifyError) as e:
                if backend == "inotify":
                    raise
                self.fallback_reason = str(e)
                self.log.warning("inotify unavailable (%s); falling back to polling", e)
                if self._ino:
                    self._ino.close()
                    self._ino = None
        self.backend = "poll"
        self.spawn(self._poll_loop, "poller")

    def stop(self, timeout: float = 5.0) -> None:
        super().stop(timeout)  # reader exits on its next select() timeout
        if self._ino:
            self._ino.close()
            self._ino = None

    def status(self) -> dict[str, Any]:
        st = super().status()
        st.update(fallback_reason=self.fallback_reason, files_tracked=len(self._baseline),
                  dirs_watched=len(self._dir_wds), overflows=self.overflows)
        return st

    # ------------------------------------------------------------ baseline
    def _load_baseline(self) -> None:
        if self.store is not None:
            stored = self.store.all_baselines()
            self._baseline = {p: r for p, r in stored.items() if self.spec_for(p)}
        else:
            self._baseline = {}

    def _save(self, path: str, rec: dict | None) -> None:
        if rec is None:
            self._baseline.pop(path, None)
        else:
            self._baseline[path] = rec
        if self.store is not None:
            self.store.set_baseline(path, rec)

    def baseline(self, path: str) -> dict | None:
        return self._baseline.get(path)

    # ------------------------------------------------------------ checking
    def check(self, path: str, startup: bool = False) -> str | None:
        """Re-hash ``path``, compare with its baseline, emit an event on change."""
        spec = self.spec_for(path)
        if spec is None:
            return None
        with self._lock:
            old = self._baseline.get(path)
            new = file_record(path, self.max_hash_size)
            change = classify(old, new)
            # very first run (no baseline at all): record silently, don't report every
            # file as "created"
            first_sight = startup and old is None and not self._had_baseline
            if change is None:
                if new is not None and old != new:
                    self._save(path, new)  # e.g. mtime-only touch: refresh silently
                return None
            self._save(path, new)
        if first_sight:
            return None  # initial baseline on a fresh install is not a "creation"
        self.emit(FILE_CHANGE, {
            "path": path,
            "change": change,
            "group": spec.group,
            "watch": spec.path,
            "old_sha256": old.get("sha256") if old else None,
            "new_sha256": new.get("sha256") if new else None,
            "old_hash": _short(old.get("sha256") if old else None),
            "new_hash": _short(new.get("sha256") if new else None),
            "old_mode": _octal(old.get("mode")) if old else None,
            "new_mode": _octal(new.get("mode")) if new else None,
            "old_uid": old.get("uid") if old else None,
            "new_uid": new.get("uid") if new else None,
            "size": new.get("size") if new else None,
            "detected_at_startup": startup,
        })
        return change

    def scan(self, startup: bool = False) -> int:
        """Full comparison of everything covered vs. the baseline."""
        self._had_baseline = bool(self._baseline)
        changes = 0
        paths = self.covered_files() | set(self._baseline)
        for path in sorted(paths):
            if self.stopping:
                break
            if self.check(path, startup=startup):
                changes += 1
        return changes

    def mark_dirty(self, path: str) -> None:
        with self._lock:
            self._dirty.setdefault(path, time.monotonic() + self.debounce)

    def process_dirty(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        with self._lock:
            due = [p for p, t in self._dirty.items() if t <= now]
            for p in due:
                del self._dirty[p]
        return sum(1 for p in due if self.check(p))

    # ------------------------------------------------------------ inotify plumbing
    def _sync_watches(self) -> None:
        assert self._ino is not None
        wanted = self.watch_dirs()
        for d in wanted - set(self._dir_wds):
            try:
                wd = self._ino.add_watch(d)
            except InotifyError as e:
                self.record_error(str(e))
                continue
            self._wd_dirs[wd] = d
            self._dir_wds[d] = wd

    def _inotify_reader(self) -> None:
        ino = self._ino
        assert ino is not None
        while not self.stopping:
            for ev in ino.read(timeout=0.5):
                self._on_inotify(ev)

    def _on_inotify(self, ev) -> None:
        if ev.has(IN_Q_OVERFLOW):
            self.overflows += 1
            self.record_error("inotify queue overflow; full rescan scheduled")
            self._rescan_now = True
            return
        d = self._wd_dirs.get(ev.wd)
        if d is None:
            return
        if ev.has(IN_IGNORED) or ev.has(IN_DELETE_SELF) or ev.has(IN_MOVE_SELF):
            self._wd_dirs.pop(ev.wd, None)
            self._dir_wds.pop(d, None)
            for p in list(self._baseline):  # files under a vanished dir
                if p.startswith(d.rstrip("/") + "/"):
                    self.mark_dirty(p)
            return
        if not ev.name:
            return
        path = os.path.join(d, ev.name)
        if ev.has(IN_ISDIR):
            spec = self.spec_for(path + "/x")
            if spec and spec.recursive:
                self._new_dir = True  # new subdir: pick it up on the worker thread
            return
        if self.spec_for(path):
            self.mark_dirty(path)

    def _worker(self) -> None:
        last_rescan = time.monotonic()
        while not self.sleep(min(0.05, self.debounce or 0.05)):
            self.process_dirty()
            now = time.monotonic()
            if self._new_dir:
                self._new_dir = False
                self._sync_watches()
                for p in self.covered_files() - set(self._baseline):
                    self.check(p)
            if self._rescan_now or now - last_rescan >= self.rescan_interval:
                self._rescan_now = False
                last_rescan = now
                self._sync_watches()
                self.scan()

    def _poll_loop(self) -> None:
        while not self.sleep(self.poll_interval):
            self.scan()
