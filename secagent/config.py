"""Default filesystem locations, shared by secagentd, secagentctl and the dashboard.
Each can be overridden by an environment variable (handy for running unprivileged
during development) or a command-line flag."""

from __future__ import annotations

import os
from pathlib import Path

from secagent.policy import DEFAULT_POLICY_PATH

ETC_POLICY = Path("/etc/secagent/policy.yaml")


def policy_path() -> Path:
    env = os.environ.get("SECAGENT_POLICY")
    if env:
        return Path(env)
    return ETC_POLICY if ETC_POLICY.exists() else DEFAULT_POLICY_PATH


def db_path() -> Path:
    return Path(os.environ.get("SECAGENT_DB", "/var/lib/secagent/secagent.db"))


def socket_path() -> Path:
    return Path(os.environ.get("SECAGENT_SOCKET", "/run/secagent/secagentd.sock"))


DASHBOARD_HOST = os.environ.get("SECAGENT_DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.environ.get("SECAGENT_DASHBOARD_PORT", "8787"))
