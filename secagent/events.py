"""Core data model: events emitted by monitors and alerts produced by the policy engine."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

# Canonical event types emitted by the built-in monitors.
PROCESS_EXEC = "process_exec"
FILE_CHANGE = "file_change"
NET_CONNECT = "net_connect"
NET_ACCEPT = "net_accept"
NET_LISTEN = "net_listen"
AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
AUTH_SUDO = "auth_sudo"


@dataclass
class Event:
    """A single observation from a monitor (e.g. one execve, one file change)."""

    type: str
    source: str
    data: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def get(self, path: str, default: Any = None) -> Any:
        """Look up a field by name. ``event_type`` / ``source`` are virtual fields;
        dotted paths (``a.b.c``) descend into nested dicts."""
        if path == "event_type":
            return self.type
        if path == "source":
            return self.source
        cur: Any = self.data
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        """Build an event from either the canonical shape
        (``{"type", "source", "data", ...}``) or a flat dict of fields."""
        reserved = ("type", "event_type", "source", "timestamp", "id", "data")
        data = d.get("data")
        if not isinstance(data, dict):
            data = {k: v for k, v in d.items() if k not in reserved}
        return cls(
            type=d.get("type") or d.get("event_type") or "unknown",
            source=d.get("source", "manual"),
            data=dict(data),
            timestamp=float(d.get("timestamp", time.time())),
            id=d.get("id") or uuid.uuid4().hex,
        )


@dataclass
class Alert:
    """A policy rule match, persisted to the alert store."""

    rule_id: str
    severity: str
    message: str
    event: Event
    action: str = "alert"
    action_result: str | None = None
    timestamp: float = field(default_factory=time.time)
    id: int | None = None  # assigned by storage

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "action": self.action,
            "action_result": self.action_result,
            "event": self.event.to_dict(),
        }
