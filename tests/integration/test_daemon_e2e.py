"""Full end-to-end: run the real secagentd as a subprocess with all four monitors, attack
the host four different ways, and verify via secagentctl, the live tail stream and the
dashboard HTTP API. Then reload policy and shut down cleanly."""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from secagent.daemon import control
from secagent.policy import DEFAULT_POLICY_PATH
from tests.conftest import REPO_ROOT, wait_for


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def daemon(tmp_path, scratch_dir):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    authlog = tmp_path / "auth.log"
    authlog.write_text("")
    doc = yaml.safe_load(DEFAULT_POLICY_PATH.read_text())
    doc["monitors"]["file"]["watch"] = [{"path": str(etc / "passwd"), "group": "identity"}]
    doc["monitors"]["auth"] = {"enabled": True, "backend": "file", "log_path": str(authlog)}
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump(doc))
    port = free_port()
    paths = {"policy": policy, "db": tmp_path / "secagent.db", "socket": tmp_path / "secagentd.sock",
             "etc": etc, "authlog": authlog, "scratch": scratch_dir, "port": port}
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    log = open(tmp_path / "secagentd.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "secagent.daemon.main", "--policy", str(policy),
                             "--db", str(paths["db"]), "--socket", str(paths["socket"]),
                             "--dashboard-port", str(port)], env=env, stdout=log, stderr=subprocess.STDOUT)
    paths["proc"] = proc
    paths["log"] = tmp_path / "secagentd.log"

    def ready():
        try:
            st = control.request(paths["socket"], {"cmd": "status"}, timeout=1)["status"]
            return st if len(st["monitors"]) == 4 else None
        except OSError:
            return None
    st = wait_for(ready, timeout=60, interval=0.25)
    assert st, f"daemon did not come up:\n{paths['log'].read_text()}"
    paths["status"] = st
    yield paths
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
    log.close()


def ctl(d, *args):
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), NO_COLOR="1")
    return subprocess.run([sys.executable, "-m", "secagent.cli.secagentctl", "--socket", str(d["socket"]),
                           "--db", str(d["db"]), "--policy", str(d["policy"]), *args],
                          capture_output=True, text=True, env=env, timeout=30)


def alerts_json(d):
    r = ctl(d, "alerts", "--json", "--limit", "1000")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def wait_rule(d, rule_id, timeout=15):
    return wait_for(lambda: [a for a in alerts_json(d) if a["rule_id"] == rule_id], timeout=timeout, interval=0.3)


def test_full_daemon_detects_attacks_and_cli_reports_them(daemon):
    d = daemon
    st = d["status"]
    assert {m["name"] for m in st["monitors"]} == {"process", "file", "network", "auth"}
    assert all(m["running"] for m in st["monitors"])

    # --- CLI status (human-readable) ---
    r = ctl(d, "status")
    assert r.returncode == 0 and "secagentd running" in r.stdout and "process" in r.stdout

    # --- live tail: subscribe before attacking ---
    streamed = []
    def tail():
        try:
            for msg in control.subscribe(d["socket"], alerts_only=True):
                if msg.get("kind") == "alert":
                    streamed.append(msg["data"]["rule_id"])
        except OSError:
            pass
    threading.Thread(target=tail, daemon=True).start()
    time.sleep(0.5)

    # 1. web shell: "nginx" spawns bash
    nginx = d["scratch"] / "nginx"
    nginx.write_text("#!/bin/sh\nbash -c 'sleep 1.5; true'\n")
    nginx.chmod(0o755)
    subprocess.Popen([str(nginx)]).wait(10)
    # 2. tamper with a watched identity file
    with open(d["etc"] / "passwd", "a") as f:
        f.write("backdoor:x:0:0::/root:/bin/bash\n")
    # 3. SSH brute force in the auth log
    ts = datetime.now(timezone.utc).astimezone().isoformat()
    with open(d["authlog"], "a") as f:
        for i in range(5):
            f.write(f"{ts} host sshd[99]: Failed password for root from 203.0.113.50 port {40000 + i} ssh2\n")
    # 4. port scan of 20 local listeners from a separate process
    socks = []
    for _ in range(20):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(); socks.append(s)
    ports = [s.getsockname()[1] for s in socks]
    subprocess.run([sys.executable, "-c",
                    f"import socket,time; c=[socket.create_connection(('127.0.0.1',p)) for p in {ports}]; time.sleep(1.5)"],
                   timeout=30)
    for s in socks:
        s.close()

    expected = ["suspicious-shell-from-webserver", "identity-file-changed", "ssh-brute-force", "outbound-port-scan"]
    for rule in expected:
        assert wait_rule(d, rule), f"{rule} not raised. daemon log:\n{d['log'].read_text()[-3000:]}"

    # --- CLI alerts table + show ---
    r = ctl(d, "alerts", "--severity", "high")
    assert r.returncode == 0
    for rule in expected:
        assert rule in r.stdout
    brute = [a for a in alerts_json(d) if a["rule_id"] == "ssh-brute-force"][0]
    assert brute["action_result"].startswith("not executed: response disabled")
    r = ctl(d, "show", str(brute["id"]))
    assert "203.0.113.50" in r.stdout

    # --- live stream saw them too ---
    assert wait_for(lambda: set(expected) <= set(streamed), timeout=5), streamed

    # --- dashboard API served by the daemon ---
    base = f"http://127.0.0.1:{d['port']}"
    api_alerts = json.load(urllib.request.urlopen(f"{base}/api/alerts?limit=1000", timeout=5))
    assert set(expected) <= {a["rule_id"] for a in api_alerts}
    api_status = json.load(urllib.request.urlopen(f"{base}/api/status", timeout=5))
    assert api_status["daemon"] is True and api_status["alerts"]["total"] >= 4
    assert b"SecAgent" in urllib.request.urlopen(base, timeout=5).read()

    # --- policy list from the running daemon, then reload ---
    r = ctl(d, "policy", "list")
    assert "loaded in secagentd" in r.stdout
    r = ctl(d, "policy", "reload")
    assert r.returncode == 0 and "rules active" in r.stdout

    # --- graceful shutdown ---
    d["proc"].send_signal(signal.SIGTERM)
    assert d["proc"].wait(15) == 0
    assert not Path(d["socket"]).exists()
    # alerts remain queryable with the daemon stopped
    assert ctl(d, "alerts").returncode == 0
    r = ctl(d, "status")
    assert r.returncode == 3 and "not running" in r.stderr


def test_invalid_policy_refuses_to_start(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: x\n    match: {a: 1}\n    severity: apocalyptic\n")
    r = subprocess.run([sys.executable, "-m", "secagent.daemon.main", "--policy", str(bad),
                        "--db", str(tmp_path / "x.db"), "--socket", str(tmp_path / "s.sock"), "--no-dashboard"],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(REPO_ROOT)), timeout=30)
    assert r.returncode == 2 and "invalid policy" in r.stderr
