"""SQLite persistence for alerts, raw events and file-integrity baselines."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from secagent.events import SEVERITIES, SEVERITY_RANK, Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    rule_id       TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    severity_rank INTEGER NOT NULL,
    message       TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    source        TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    action_result TEXT,
    event_json    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    event_type  TEXT NOT NULL,
    source      TEXT NOT NULL,
    data_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS file_baseline (
    path    TEXT PRIMARY KEY,
    sha256  TEXT,
    size    INTEGER,
    mode    INTEGER,
    uid     INTEGER,
    gid     INTEGER,
    mtime   REAL,
    updated REAL NOT NULL
);
"""


class Storage:
    """A single shared connection guarded by a lock. Writes are tiny and infrequent
    relative to SQLite throughput, so this is simpler and safer than a pool. WAL mode
    lets the CLI and dashboard read concurrently while the daemon writes."""

    def __init__(self, path: str | Path, readonly: bool = False) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        if readonly:
            uri = f"file:{Path(self.path).resolve().as_posix()}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=5)
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        self._conn.row_factory = sqlite3.Row

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ alerts
    def insert_alert(self, alert: Alert) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (ts, rule_id, severity, severity_rank, message, event_type,"
                " source, action, action_result, event_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (alert.timestamp, alert.rule_id, alert.severity, SEVERITY_RANK[alert.severity],
                 alert.message, alert.event.type, alert.event.source, alert.action,
                 alert.action_result, alert.event.to_json()),
            )
            self._conn.commit()
            alert.id = int(cur.lastrowid)
            return alert.id

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp": row["ts"],
            "rule_id": row["rule_id"],
            "severity": row["severity"],
            "message": row["message"],
            "event_type": row["event_type"],
            "source": row["source"],
            "action": row["action"],
            "action_result": row["action_result"],
            "event": json.loads(row["event_json"]),
        }

    def query_alerts(self, since: float | None = None, min_severity: str | None = None,
                     rule_id: str | None = None, after_id: int | None = None,
                     limit: int = 100, ascending: bool = False) -> list[dict[str, Any]]:
        clauses, params = [], []
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if min_severity:
            if min_severity not in SEVERITY_RANK:
                raise ValueError(f"unknown severity {min_severity!r}; use one of {SEVERITIES}")
            clauses.append("severity_rank >= ?")
            params.append(SEVERITY_RANK[min_severity])
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if after_id is not None:
            clauses.append("id > ?")
            params.append(after_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if ascending else "DESC"
        sql = f"SELECT * FROM alerts {where} ORDER BY id {order} LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._alert_row(r) for r in rows]

    # ------------------------------------------------------------------ events
    def insert_event(self, event: Event) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (ts, event_type, source, data_json) VALUES (?,?,?,?)",
                (event.timestamp, event.type, event.source, json.dumps(event.data, default=str)),
            )
            self._conn.commit()

    def query_events(self, after_id: int | None = None, event_type: str | None = None,
                     limit: int = 100) -> list[dict[str, Any]]:
        clauses, params = [], []
        if after_id is not None:
            clauses.append("id > ?")
            params.append(after_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?", (*params, int(limit))
            ).fetchall()
        return [{"id": r["id"], "timestamp": r["ts"], "type": r["event_type"],
                 "source": r["source"], "data": json.loads(r["data_json"])} for r in rows]

    def prune_events(self, max_events: int) -> int:
        """Keep the newest ``max_events`` raw events (alerts are never pruned)."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM events) - ?",
                (int(max_events),))
            self._conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------ stats
    def stats(self, timeline_hours: int = 24, bucket_seconds: int = 3600) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            by_sev = dict(self._conn.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            by_rule = self._conn.execute(
                "SELECT rule_id, COUNT(*) AS n FROM alerts GROUP BY rule_id ORDER BY n DESC LIMIT 10"
            ).fetchall()
            total_events = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            since = now - timeline_hours * 3600
            buckets = self._conn.execute(
                "SELECT CAST(ts / ? AS INTEGER) * ? AS b, severity, COUNT(*) FROM alerts "
                "WHERE ts >= ? GROUP BY b, severity ORDER BY b",
                (bucket_seconds, bucket_seconds, since)).fetchall()
        timeline: dict[int, dict[str, int]] = {}
        for b, sev, n in buckets:
            timeline.setdefault(int(b), {s: 0 for s in SEVERITIES})[sev] = n
        return {
            "alerts_by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
            "alerts_total": sum(by_sev.values()),
            "top_rules": [{"rule_id": r[0], "count": r[1]} for r in by_rule],
            "events_total": total_events,
            "timeline": [{"bucket": b, **counts} for b, counts in sorted(timeline.items())],
            "bucket_seconds": bucket_seconds,
        }

    # ------------------------------------------------------------------ FIM baseline
    def get_baseline(self, path: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM file_baseline WHERE path = ?", (path,)).fetchone()
        return dict(row) if row else None

    def all_baselines(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM file_baseline").fetchall()
        return {r["path"]: dict(r) for r in rows}

    def set_baseline(self, path: str, rec: dict[str, Any] | None) -> None:
        with self._lock:
            if rec is None:
                self._conn.execute("DELETE FROM file_baseline WHERE path = ?", (path,))
            else:
                self._conn.execute(
                    "INSERT OR REPLACE INTO file_baseline (path, sha256, size, mode, uid, gid, mtime,"
                    " updated) VALUES (?,?,?,?,?,?,?,?)",
                    (path, rec.get("sha256"), rec.get("size"), rec.get("mode"), rec.get("uid"),
                     rec.get("gid"), rec.get("mtime"), time.time()))
            self._conn.commit()
