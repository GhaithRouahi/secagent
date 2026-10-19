"""The Agent wires everything together: policy -> monitors -> bus -> pipeline -> storage,
plus the control socket and (optionally) the dashboard."""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

from secagent import __version__
from secagent.daemon.auth_monitor import AuthMonitor
from secagent.daemon.control import ControlServer
from secagent.daemon.event_bus import AlertPipeline, EventBus
from secagent.daemon.file_monitor import FileIntegrityMonitor
from secagent.daemon.monitor import Monitor
from secagent.daemon.network_monitor import NetworkMonitor
from secagent.daemon.policy_engine import Policy, PolicyEngine
from secagent.daemon.process_monitor import ProcessMonitor
from secagent.daemon.responder import Responder
from secagent.daemon.storage import Storage

log = logging.getLogger("secagent.agent")

MONITOR_ORDER = ("process", "file", "network", "auth")


class Agent:
    def __init__(self, policy_path: str | Path, db_path: str | Path,
                 socket_path: str | Path | None = None, dashboard: bool = False,
                 dashboard_host: str = "127.0.0.1", dashboard_port: int = 8787) -> None:
        self.policy_path = Path(policy_path)
        self.db_path = Path(db_path)
        self.socket_path = Path(socket_path) if socket_path else None
        self.dashboard_enabled = dashboard
        self.dashboard_host = dashboard_host
        self.dashboard_port = dashboard_port

        policy = Policy.from_file(self.policy_path)  # fail fast on a broken policy
        self.storage = Storage(self.db_path)
        self.engine = PolicyEngine(policy)
        self.responder = Responder(policy.response)
        settings = policy.settings
        self.max_events = int(settings.get("max_events", 100_000))
        self.pipeline = AlertPipeline(self.engine, self.storage, self.responder,
                                      record_events=bool(settings.get("record_events", True)))
        self.bus = EventBus()
        self.bus.subscribe(self.pipeline)
        self.monitors: dict[str, Monitor] = {}
        self.monitor_failures: dict[str, str] = {}
        self.control: ControlServer | None = None
        self._dashboard_server = None
        self.started_at: float | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ monitors
    def build_monitor(self, name: str, cfg: dict[str, Any]) -> Monitor:
        pub = self.bus.publish
        if name == "process":
            return ProcessMonitor(pub, backend=cfg.get("backend", "auto"),
                                  poll_interval=float(cfg.get("poll_interval", 0.2)))
        if name == "file":
            return FileIntegrityMonitor(pub, cfg.get("watch", []), store=self.storage,
                                        backend=cfg.get("backend", "auto"),
                                        debounce=float(cfg.get("debounce", 0.2)),
                                        rescan_interval=float(cfg.get("rescan_interval", 300)),
                                        max_hash_size=int(cfg.get("max_hash_size", 100 << 20)))
        if name == "network":
            return NetworkMonitor(pub, backend=cfg.get("backend", "auto"),
                                  poll_interval=float(cfg.get("poll_interval", 0.5)))
        if name == "auth":
            return AuthMonitor(pub, backend=cfg.get("backend", "auto"), log_path=cfg.get("log_path"))
        raise ValueError(f"unknown monitor {name!r}")

    def start(self) -> None:
        self.started_at = time.time()
        self.bus.start()
        monitors_cfg = self.engine.policy.monitors
        for name in MONITOR_ORDER:
            cfg = monitors_cfg.get(name) or {}
            if not cfg.get("enabled", False):
                continue
            try:
                mon = self.build_monitor(name, cfg)
                mon.start()
                self.monitors[name] = mon
            except Exception as e:  # one broken monitor must not take down the agent
                self.monitor_failures[name] = str(e)
                log.error("monitor %s failed to start: %s", name, e)
        if self.socket_path:
            self.control = ControlServer(self.socket_path, self)
            self.control.start()
        if self.dashboard_enabled:
            self._start_dashboard()
        threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True).start()
        log.info("secagentd %s started: monitors=%s rules=%d db=%s", __version__,
                 ",".join(f"{n}:{m.backend}" for n, m in self.monitors.items()),
                 len(self.engine.rules), self.db_path)

    def _start_dashboard(self) -> None:
        try:
            import uvicorn

            from secagent.dashboard.api import create_app
        except ImportError as e:
            self.monitor_failures["dashboard"] = f"dashboard dependencies missing: {e}"
            log.error("dashboard disabled: %s (pip install 'secagent[dashboard]')", e)
            return
        app = create_app(self.storage, status_provider=self.status)
        config = uvicorn.Config(app, host=self.dashboard_host, port=self.dashboard_port,
                                log_level="warning", lifespan="off")
        self._dashboard_server = uvicorn.Server(config)
        threading.Thread(target=self._dashboard_server.run, name="dashboard", daemon=True).start()
        log.info("dashboard on http://%s:%d", self.dashboard_host, self.dashboard_port)

    def _housekeeping(self) -> None:
        while not self._stop.wait(60):
            try:
                self.storage.prune_events(self.max_events)
            except Exception:
                log.exception("event pruning failed")

    def stop(self) -> None:
        self._stop.set()
        if self.control:
            self.control.stop()
        if self._dashboard_server is not None:
            self._dashboard_server.should_exit = True
        for mon in self.monitors.values():
            try:
                mon.stop()
            except Exception:
                log.exception("error stopping monitor %s", mon.name)
        self.bus.wait_idle(5)
        self.bus.stop()
        self.storage.close()
        log.info("secagentd stopped")

    def wait(self) -> None:
        while not self._stop.wait(1.0):  # timed wait keeps signal handlers responsive
            pass

    def request_stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------ control
    def reload_policy(self) -> int:
        """Re-read the policy file. Rules and response settings apply immediately;
        monitor settings (paths, backends) need a restart."""
        policy = Policy.from_file(self.policy_path)
        self.engine.reload(policy)
        self.responder.configure(policy.response)
        log.info("policy reloaded: %d rules", len(policy.rules))
        return len(policy.rules)

    def status(self) -> dict[str, Any]:
        stats = self.storage.stats(timeline_hours=1, bucket_seconds=300)
        return {
            "version": __version__,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "started_at": self.started_at,
            "uptime": time.time() - self.started_at if self.started_at else 0,
            "policy": str(self.policy_path),
            "rules": len(self.engine.rules),
            "db": str(self.db_path),
            "monitors": [m.status() for m in self.monitors.values()],
            "monitor_failures": self.monitor_failures,
            "bus": {"published": self.bus.published, "processed": self.bus.processed,
                    "dropped": self.bus.dropped, "queue": self.bus.queue_depth,
                    "errors": self.bus.errors},
            "alerts": {"total": stats["alerts_total"], "by_severity": stats["alerts_by_severity"]},
            "events_stored": stats["events_total"],
            "response": {"enabled": self.responder.enabled, "dry_run": self.responder.dry_run,
                         "executed": self.responder.executed, "skipped": self.responder.skipped,
                         "firewall": self.responder.firewall.backend},
            "dashboard": (f"http://{self.dashboard_host}:{self.dashboard_port}"
                          if self._dashboard_server is not None else None),
        }
