"""secagentd entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import sys

from secagent import __version__, config
from secagent.daemon.policy_engine import PolicyError


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="secagentd", description="SecAgent host intrusion detection daemon")
    p.add_argument("--policy", default=str(config.policy_path()), help="policy YAML (default: %(default)s)")
    p.add_argument("--db", default=str(config.db_path()), help="SQLite database (default: %(default)s)")
    p.add_argument("--socket", default=str(config.socket_path()), help="control socket (default: %(default)s)")
    p.add_argument("--dashboard", action=argparse.BooleanOptionalAction, default=True,
                   help="serve the local web dashboard (default: on)")
    p.add_argument("--dashboard-host", default=config.DASHBOARD_HOST)
    p.add_argument("--dashboard-port", type=int, default=config.DASHBOARD_PORT)
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--version", action="version", version=f"secagentd {__version__}")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    log = logging.getLogger("secagentd")
    if sys.platform != "linux":
        log.error("secagentd only runs on Linux")
        return 2

    from secagent.daemon.agent import Agent  # import after logging is configured

    try:
        agent = Agent(args.policy, args.db, args.socket, dashboard=args.dashboard,
                      dashboard_host=args.dashboard_host, dashboard_port=args.dashboard_port)
    except PolicyError as e:
        log.error("invalid policy: %s", e)
        return 2
    except OSError as e:
        log.error("startup failed: %s", e)
        return 1

    def on_signal(signum, _frame):
        if signum == signal.SIGHUP:
            try:
                agent.reload_policy()
            except PolicyError as e:
                log.error("reload rejected, keeping current policy: %s", e)
            return
        log.info("received %s, shutting down", signal.Signals(signum).name)
        agent.request_stop()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)

    agent.start()
    agent.wait()
    agent.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
