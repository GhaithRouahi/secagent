"""Local web dashboard: a small read-only JSON API plus one static HTML page.

Served by secagentd on 127.0.0.1 (see ``--dashboard-host/--dashboard-port``). It can
also run standalone against an existing database, e.g. on a box where the daemon is
stopped:  python -m secagent.dashboard.api --db /var/lib/secagent/secagent.db
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from secagent.daemon.storage import Storage
from secagent.events import SEVERITIES

STATIC = Path(__file__).parent / "static"


def create_app(storage: Storage, status_provider: Callable[[], dict[str, Any]] | None = None) -> FastAPI:
    app = FastAPI(title="SecAgent", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        if status_provider is None:
            return {"daemon": False, "now": time.time()}
        return {"daemon": True, "now": time.time(), **status_provider()}

    @app.get("/api/alerts")
    def alerts(after_id: int | None = None, limit: int = Query(100, le=1000),
               severity: str | None = None, rule_id: str | None = None) -> list[dict[str, Any]]:
        if severity and severity not in SEVERITIES:
            raise HTTPException(400, f"severity must be one of {SEVERITIES}")
        return storage.query_alerts(after_id=after_id, limit=limit, min_severity=severity,
                                    rule_id=rule_id)

    @app.get("/api/events")
    def events(after_id: int | None = None, limit: int = Query(100, le=1000),
               event_type: str | None = None) -> list[dict[str, Any]]:
        return storage.query_events(after_id=after_id, limit=limit, event_type=event_type)

    @app.get("/api/stats")
    def stats(hours: int = Query(1, ge=1, le=168), bucket: int = Query(60, ge=10, le=86400)) -> dict[str, Any]:
        return storage.stats(timeline_hours=hours, bucket_seconds=bucket)

    return app


def main() -> None:  # standalone, read-only mode
    import uvicorn

    from secagent import config
    p = argparse.ArgumentParser(description="SecAgent dashboard (standalone, read-only)")
    p.add_argument("--db", default=str(config.db_path()))
    p.add_argument("--host", default=config.DASHBOARD_HOST)
    p.add_argument("--port", type=int, default=config.DASHBOARD_PORT)
    a = p.parse_args()
    uvicorn.run(create_app(Storage(a.db, readonly=True)), host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
