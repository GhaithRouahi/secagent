"""Simulated tampering against the real file-integrity monitor (real inotify)."""

import hashlib
import os
import subprocess
import time

import pytest

from secagent.daemon.file_monitor import FileIntegrityMonitor

DETECT_TIMEOUT = 5.0  # seconds; inotify + 0.2 s debounce normally detects in < 0.5 s


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


@pytest.fixture
def fim_env(tmp_path, harness):
    """A fake /etc with passwd + ssh dir watched under the default policy's groups."""
    etc = tmp_path / "etc"
    (etc / "ssh").mkdir(parents=True)
    passwd = etc / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n")
    (etc / "ssh" / "sshd_config").write_text("PermitRootLogin no\n")
    specs = [{"path": str(passwd), "group": "identity"},
             {"path": str(etc / "ssh"), "group": "ssh", "recursive": True},
             {"path": str(etc / "ld.so.preload"), "group": "preload"},
             {"path": str(etc / "notes.txt"), "group": "custom"}]
    return etc, passwd, specs


def start_fim(harness, specs, backend="inotify"):
    mon = FileIntegrityMonitor(harness.bus.publish, specs, store=harness.storage,
                               backend=backend, debounce=0.1, poll_interval=0.3)
    harness.start(mon)
    assert mon.backend == backend
    return mon


@pytest.mark.parametrize("backend", ["inotify", "poll"])
def test_modify_watched_file_alerts_with_hashes(harness, fim_env, backend):
    etc, passwd, specs = fim_env
    start_fim(harness, specs, backend)
    before = sha(passwd)
    t0 = time.monotonic()
    with open(passwd, "a") as f:
        f.write("backdoor:x:0:0::/root:/bin/bash\n")   # classic uid-0 backdoor account
    after = sha(passwd)
    alert = harness.wait_alert("identity-file-changed", timeout=DETECT_TIMEOUT)
    latency = time.monotonic() - t0
    assert alert, "no alert for modified passwd"
    d = alert["event"]["data"]
    assert (d["old_sha256"], d["new_sha256"], d["change"]) == (before, after, "modified")
    assert before[:12] in alert["message"] and after[:12] in alert["message"]
    print(f"\n[{backend}] detection latency: {latency * 1000:.0f} ms")


def test_atomic_replace_is_detected(harness, fim_env):
    """Editors / sed -i / passwd(1) write a temp file and rename() it over the target."""
    etc, passwd, specs = fim_env
    start_fim(harness, specs)
    tmp = etc / ".passwd.tmp"
    tmp.write_text("root:x:0:0:root:/root:/bin/bash\nmallory:x:0:0::/:/bin/sh\n")
    os.replace(tmp, passwd)
    assert harness.wait_alert("identity-file-changed", lambda d: d["change"] == "modified",
                              timeout=DETECT_TIMEOUT)
    # and the watch survives the replace: a second edit is still seen
    with open(passwd, "a") as f:
        f.write("eve:x:0:0::/:/bin/sh\n")
    assert harness.wait_alert("identity-file-changed",
                              lambda d: d["new_sha256"] == sha(passwd), timeout=DETECT_TIMEOUT)


def test_sed_in_place_edit_of_sshd_config(harness, fim_env):
    etc, _, specs = fim_env
    start_fim(harness, specs)
    cfg = etc / "ssh" / "sshd_config"
    subprocess.run(["sed", "-i", "s/PermitRootLogin no/PermitRootLogin yes/", str(cfg)], check=True)
    alert = harness.wait_alert("ssh-config-or-keys-changed", timeout=DETECT_TIMEOUT)
    assert alert and alert["event"]["data"]["path"] == str(cfg)


def test_authorized_keys_planted_in_new_subdir(harness, fim_env):
    etc, _, specs = fim_env
    start_fim(harness, specs)
    sub = etc / "ssh" / "keys.d"
    sub.mkdir()
    (sub / "authorized_keys").write_text("ssh-ed25519 AAAAC3Nz attacker@evil\n")
    alert = harness.wait_alert("ssh-config-or-keys-changed",
                               lambda d: d["path"].endswith("keys.d/authorized_keys"),
                               timeout=DETECT_TIMEOUT)
    assert alert and alert["event"]["data"]["change"] == "created"


def test_ld_preload_creation_is_critical(harness, fim_env):
    etc, _, specs = fim_env
    start_fim(harness, specs)
    (etc / "ld.so.preload").write_text("/lib/x86_64-linux-gnu/libevil.so\n")
    alert = harness.wait_alert("ld-preload-tampering", timeout=DETECT_TIMEOUT)
    assert alert and alert["severity"] == "critical"
    assert alert["event"]["data"]["change"] == "created"


def test_permission_change_and_delete(harness, fim_env):
    etc, passwd, specs = fim_env
    start_fim(harness, specs)
    os.chmod(passwd, 0o666)
    assert harness.wait_alert("identity-file-changed", lambda d: d["change"] == "permissions"
                              and d["new_mode"] == "0666", timeout=DETECT_TIMEOUT)
    passwd.unlink()
    assert harness.wait_alert("identity-file-changed", lambda d: d["change"] == "deleted",
                              timeout=DETECT_TIMEOUT)


def test_touch_without_content_change_is_silent(harness, fim_env):
    etc, passwd, specs = fim_env
    mon = start_fim(harness, specs)
    os.utime(passwd, None)
    subprocess.run(["touch", str(passwd)], check=True)
    time.sleep(1.0)
    harness.bus.wait_idle(3)
    assert harness.alerts() == []
    assert mon.status()["files_tracked"] >= 2


def test_tampering_while_agent_down_detected_at_startup(harness, fim_env):
    etc, passwd, specs = fim_env
    mon = start_fim(harness, specs)
    mon.stop()
    harness.monitors.remove(mon)
    passwd.write_text("root::0:0:root:/root:/bin/bash\n")   # empty root password, offline
    start_fim(harness, specs)
    alert = harness.wait_alert("identity-file-changed", timeout=DETECT_TIMEOUT)
    assert alert and alert["event"]["data"]["detected_at_startup"] is True
