"""File-integrity monitor: inotify parsing, coverage, hashing, change classification."""

import hashlib
import os
import struct

import pytest

from secagent.daemon.file_monitor import FileIntegrityMonitor, WatchSpec, classify, file_record
from secagent.daemon.inotify import IN_CLOSE_WRITE, IN_ISDIR, parse_events
from secagent.daemon.storage import Storage
from tests.conftest import requires_linux


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_parse_inotify_events():
    def pack(wd, mask, name):
        raw = name.encode() + b"\0" * (16 - len(name))
        return struct.pack("iIII", wd, mask, 0, len(raw)) + raw
    buf = pack(1, IN_CLOSE_WRITE, "passwd") + pack(2, IN_ISDIR, "sub") + struct.pack("iIII", 3, 4, 0, 0)
    evs = parse_events(buf)
    assert [(e.wd, e.name) for e in evs] == [(1, "passwd"), (2, "sub"), (3, "")]
    assert evs[1].has(IN_ISDIR) and not evs[0].has(IN_ISDIR)


@pytest.mark.parametrize("spec,path,expected", [
    (WatchSpec("/etc/passwd"), "/etc/passwd", True),
    (WatchSpec("/etc/passwd"), "/etc/passwd-", False),
    (WatchSpec("/etc/ssh"), "/etc/ssh/sshd_config", True),
    (WatchSpec("/etc/ssh"), "/etc/ssh/sshd_config.d/x.conf", False),
    (WatchSpec("/etc/ssh", recursive=True), "/etc/ssh/sshd_config.d/x.conf", True),
    (WatchSpec("/etc/ssh", recursive=True), "/etc/sshx/a", False),
])
def test_watchspec_covers(spec, path, expected):
    assert spec.covers(path) is expected


def test_watchspec_parse():
    assert WatchSpec.parse("/etc//passwd") == WatchSpec("/etc/passwd", "custom", False)
    assert WatchSpec.parse({"path": "/etc/ssh/", "group": "ssh", "recursive": True}) == \
        WatchSpec("/etc/ssh", "ssh", True)


@pytest.mark.parametrize("old,new,expected", [
    (None, None, None),
    (None, {"sha256": "a"}, "created"),
    ({"sha256": "a"}, None, "deleted"),
    ({"sha256": "a", "mode": 0o644}, {"sha256": "b", "mode": 0o644}, "modified"),
    ({"sha256": "a", "mode": 0o644, "uid": 0}, {"sha256": "a", "mode": 0o4755, "uid": 0}, "permissions"),
    ({"sha256": "a", "mode": 0o644, "uid": 0}, {"sha256": "a", "mode": 0o644, "uid": 1000}, "permissions"),
    ({"sha256": "a", "mode": 0o644, "uid": 0, "mtime": 1}, {"sha256": "a", "mode": 0o644, "uid": 0, "mtime": 2}, None),
])
def test_classify(old, new, expected):
    assert classify(old, new) == expected


def test_file_record_hashes_content(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"hello")
    rec = file_record(str(f), max_hash_size=1 << 20)
    assert rec["sha256"] == sha(b"hello") and rec["size"] == 5
    assert file_record(str(tmp_path / "missing"), 1 << 20) is None
    assert file_record(str(tmp_path), 1 << 20) is None  # directories aren't files


def test_file_record_large_file_uses_size_mtime(tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"x" * 100)
    assert file_record(str(f), max_hash_size=10)["sha256"].startswith("size:100:")


@requires_linux
def test_file_record_symlink_tracks_target(tmp_path):
    link = tmp_path / "l"
    os.symlink("/etc/hosts", link)
    a = file_record(str(link), 1 << 20)
    link.unlink()
    os.symlink("/etc/shadow", link)
    assert file_record(str(link), 1 << 20)["sha256"] != a["sha256"]


def make_monitor(tmp_path, specs, store=None):
    events = []
    mon = FileIntegrityMonitor(events.append, specs, store=store, backend="poll")
    return mon, events


def test_spec_for_prefers_most_specific(tmp_path):
    mon, _ = make_monitor(tmp_path, [{"path": "/etc", "group": "etc", "recursive": True},
                                     {"path": "/etc/ssh", "group": "ssh", "recursive": True}])
    assert mon.spec_for("/etc/ssh/sshd_config").group == "ssh"
    assert mon.spec_for("/etc/hosts").group == "etc"
    assert mon.spec_for("/var/log/x") is None


def test_check_detects_each_change_type(tmp_path):
    f = tmp_path / "shadow"
    f.write_text("root:x:1\n")
    os.chmod(f, 0o640)
    mon, events = make_monitor(tmp_path, [{"path": str(f), "group": "identity"}])
    assert mon.scan(startup=True) == 0  # first run: silent baseline
    old_hash = sha(b"root:x:1\n")

    f.write_text("root:x:1\nevil:x:0\n")
    assert mon.check(str(f)) == "modified"
    d = events[-1].data
    assert (d["old_sha256"], d["new_sha256"]) == (old_hash, sha(b"root:x:1\nevil:x:0\n"))
    assert d["group"] == "identity" and d["old_hash"] == old_hash[:12]

    os.utime(f, (1, 1))
    assert mon.check(str(f)) is None  # touch only

    os.chmod(f, 0o666)
    assert mon.check(str(f)) == "permissions"
    assert (events[-1].data["old_mode"], events[-1].data["new_mode"]) == ("0640", "0666")

    f.unlink()
    assert mon.check(str(f)) == "deleted"
    assert events[-1].data["new_sha256"] is None

    f.write_text("back")
    assert mon.check(str(f)) == "created"
    assert len(events) == 4


def test_new_file_in_watched_dir_is_created(tmp_path):
    d = tmp_path / ".ssh"
    d.mkdir()
    (d / "known_hosts").write_text("x")
    mon, events = make_monitor(tmp_path, [{"path": str(d), "group": "ssh"}])
    mon.scan(startup=True)
    (d / "authorized_keys").write_text("ssh-ed25519 AAAA attacker")
    assert mon.scan() == 1
    assert events[0].data["change"] == "created"
    assert events[0].data["path"] == str(d / "authorized_keys")


def test_offline_tampering_detected_on_restart(tmp_path):
    f = tmp_path / "passwd"
    f.write_text("root:x:0:0\n")
    store = Storage(tmp_path / "db.sqlite")
    mon, events = make_monitor(tmp_path, [{"path": str(f), "group": "identity"}], store=store)
    mon._load_baseline()
    mon.scan(startup=True)
    assert events == []

    f.write_text("root:x:0:0\nbackdoor:x:0:0\n")  # agent is "down"

    mon2, events2 = make_monitor(tmp_path, [{"path": str(f), "group": "identity"}], store=store)
    mon2._load_baseline()
    mon2.scan(startup=True)
    assert len(events2) == 1
    assert events2[0].data["change"] == "modified"
    assert events2[0].data["detected_at_startup"] is True
    store.close()


def test_debounce_coalesces_bursts(tmp_path):
    f = tmp_path / "f"
    f.write_text("a")
    mon, events = make_monitor(tmp_path, [str(f)])
    mon.debounce = 0.2
    mon.scan(startup=True)
    for i in range(20):
        f.write_text(f"v{i}")
        mon.mark_dirty(str(f))
    import time
    assert mon.process_dirty(now=time.monotonic()) == 0  # not due yet
    assert mon.process_dirty(now=time.monotonic() + 1) == 1
    assert len(events) == 1


@requires_linux
def test_watch_dirs_watch_parent_of_files(tmp_path):
    (tmp_path / "ssh" / "sub").mkdir(parents=True)
    f = tmp_path / "passwd"
    f.write_text("x")
    mon, _ = make_monitor(tmp_path, [str(f), {"path": str(tmp_path / "ssh"), "recursive": True},
                                     str(tmp_path / "not-yet-created")])
    dirs = mon.watch_dirs()
    assert str(tmp_path) in dirs  # parent of passwd and of the missing path
    assert str(tmp_path / "ssh") in dirs and str(tmp_path / "ssh" / "sub") in dirs
