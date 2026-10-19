"""Local control API for secagentctl: newline-delimited JSON over a Unix socket.

Request:  {"cmd": "status"}            -> one JSON response line
          {"cmd": "reload"}
          {"cmd": "rules"}
          {"cmd": "subscribe", "alerts_only": false}
                                       -> stream of {"kind": "event"|"alert", "data": ...}
                                          lines until the client disconnects

The socket is created mode 0600 (root only): it can reload policy and stream every event
on the host, so access is equivalent to reading the agent's data.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import socketserver
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from secagent.daemon.agent import Agent

log = logging.getLogger(__name__)


class _Handler(socketserver.StreamRequestHandler):
    server: "ControlServer"

    def handle(self) -> None:
        try:
            line = self.rfile.readline(1 << 20)
            if not line:
                return
            req = json.loads(line)
        except (json.JSONDecodeError, OSError) as e:
            self._send({"ok": False, "error": f"bad request: {e}"})
            return
        cmd = req.get("cmd")
        agent = self.server.agent
        try:
            if cmd == "status":
                self._send({"ok": True, "status": agent.status()})
            elif cmd == "reload":
                self._send({"ok": True, "rules": agent.reload_policy()})
            elif cmd == "rules":
                self._send({"ok": True, "rules": [r.to_dict() for r in agent.engine.rules],
                            "source": agent.engine.policy.source})
            elif cmd == "subscribe":
                self._stream(bool(req.get("alerts_only", False)))
            else:
                self._send({"ok": False, "error": f"unknown command {cmd!r}"})
        except Exception as e:  # report, don't crash the server thread
            log.exception("control command %s failed", cmd)
            self._send({"ok": False, "error": str(e)})

    def _send(self, obj: dict[str, Any]) -> None:
        self.wfile.write((json.dumps(obj, default=str) + "\n").encode())
        self.wfile.flush()

    def _stream(self, alerts_only: bool) -> None:
        q: queue.Queue = queue.Queue(maxsize=5000)
        dropped = [0]

        def listener(kind: str, payload: dict) -> None:
            if alerts_only and kind != "alert":
                return
            try:
                q.put_nowait({"kind": kind, "data": payload})
            except queue.Full:
                dropped[0] += 1  # slow client: drop rather than stall the pipeline

        pipeline = self.server.agent.pipeline
        pipeline.add_listener(listener)
        try:
            self._send({"ok": True, "subscribed": True})
            while not self.server.stopping.is_set():
                try:
                    msg = q.get(timeout=1.0)
                except queue.Empty:
                    self._send({"kind": "heartbeat", "dropped": dropped[0]})
                    continue
                self._send(msg)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            pipeline.remove_listener(listener)


class ControlServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: Path, agent: "Agent") -> None:
        self.agent = agent
        self.stopping = threading.Event()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()  # stale socket from a previous run
        old_umask = os.umask(0o177)
        try:
            super().__init__(str(self.path), _Handler)
        finally:
            os.umask(old_umask)

    def start(self) -> None:
        threading.Thread(target=self.serve_forever, name="control", daemon=True).start()

    def stop(self) -> None:
        self.stopping.set()
        self.shutdown()
        self.server_close()
        try:
            self.path.unlink()
        except OSError:
            pass


def request(path: str | Path, cmd: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Client side: send one command, return the single response line."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(path))
        s.sendall((json.dumps(cmd) + "\n").encode())
        f = s.makefile("rb")
        line = f.readline()
    if not line:
        raise ConnectionError("daemon closed the connection")
    return json.loads(line)


def subscribe(path: str | Path, alerts_only: bool = False):
    """Client side: yield streamed messages from the daemon."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(path))
    s.sendall((json.dumps({"cmd": "subscribe", "alerts_only": alerts_only}) + "\n").encode())
    f = s.makefile("rb")
    try:
        for line in f:
            yield json.loads(line)
    finally:
        s.close()
