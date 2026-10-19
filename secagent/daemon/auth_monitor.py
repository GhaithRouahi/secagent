"""Authentication monitoring: sshd, sudo, su and account creation.

Backends
--------
``file``      Tails /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL), following
              log rotation (inode change or truncation). Starts at end-of-file: history
              is not replayed, so restarting the daemon never re-alerts on old lines.
``journald``  Follows ``journalctl -f -o json`` for the sshd/sudo/su/useradd identifiers
              (hosts without rsyslog).
``auto``      file if a log file exists, else journald.

Emitted events
  auth_failure       sshd failed password/publickey: user, src_ip, src_port, method, invalid_user
  auth_invalid_user  sshd "Invalid user X from IP" (connection-level, no password tried yet)
  auth_success       sshd accepted login: user, src_ip, src_port, method
  auth_sudo          sudo command or failure: user, target_user, command, tty, success, reason
  auth_su            su attempt: user, target_user, success
  account_created    useradd: user, uid, gid, home, shell
(all carry ``service``, ``host`` and the raw ``line``; the event timestamp is the log
timestamp, so threshold windows are measured in log time)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Any

from secagent.daemon.monitor import Monitor, Publish

DEFAULT_LOG_PATHS = ("/var/log/auth.log", "/var/log/secure")

# "2026-10-19T16:03:58.280980+01:00 host sshd[123]: msg"  (rsyslog RFC 3339, Ubuntu 24.04+)
_RFC3339 = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)\s+"
                      r"(?P<host>\S+)\s+(?P<ident>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
# "Oct 19 16:03:58 host sshd[123]: msg"  (traditional BSD syslog)
_BSD = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+"
                  r"(?P<ident>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

_SSH_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) "
                         r"from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) "
                           r"port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<reason>.+?) ; )?TTY=(?P<tty>[^;]*?) ; "
                   r"PWD=(?P<pwd>[^;]*?) ; USER=(?P<target>[^;]*?) ;(?: [A-Z]+=[^;]*;)* "
                   r"COMMAND=(?P<cmd>.*)$")
_SU_FAILED = re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_SU_OK = re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_USERADD = re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
                      r"home=(?P<home>[^,]+), shell=(?P<shell>[^,]+)")


def parse_timestamp(ts: str, now: datetime | None = None) -> float | None:
    try:
        if ts[0].isdigit():
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        now = now or datetime.now()
        dt = datetime.strptime(f"{now.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
        if (dt - now).days >= 1:  # "Dec 31" read on Jan 1: last year
            dt = dt.replace(year=now.year - 1)
        return dt.timestamp()
    except ValueError:
        return None


def parse_message(ident: str, msg: str) -> tuple[str, dict[str, Any]] | None:
    """Classify one syslog message body from a given program identifier."""
    ident = ident.lower()
    if ident in ("sshd", "sshd-session"):
        if m := _SSH_FAILED.match(msg):
            return "auth_failure", {"user": m["user"], "src_ip": m["ip"], "src_port": int(m["port"]),
                                    "method": m["method"], "invalid_user": bool(m["invalid"]),
                                    "service": "sshd"}
        if m := _SSH_ACCEPTED.match(msg):
            return "auth_success", {"user": m["user"], "src_ip": m["ip"], "src_port": int(m["port"]),
                                    "method": m["method"], "service": "sshd"}
        if m := _SSH_INVALID.match(msg):
            return "auth_invalid_user", {"user": m["user"], "src_ip": m["ip"],
                                         "src_port": int(m["port"]) if m["port"] else None,
                                         "service": "sshd"}
    elif ident == "sudo":
        if m := _SUDO.match(msg):
            reason = (m["reason"] or "").strip()
            if "NOT in sudoers" in reason:
                why = "not_in_sudoers"
            elif "incorrect password" in reason:
                why = "incorrect_password"
            elif reason:
                why = reason
            else:
                why = None
            data: dict[str, Any] = {"user": m["user"], "target_user": m["target"].strip(),
                                    "command": m["cmd"].strip(), "tty": m["tty"].strip(),
                                    "pwd": m["pwd"].strip(), "success": why is None,
                                    "reason": why, "service": "sudo"}
            if n := re.match(r"(\d+) incorrect password attempts?", reason):
                data["attempts"] = int(n.group(1))
            return "auth_sudo", data
    elif ident == "su":
        if m := _SU_FAILED.match(msg):
            return "auth_su", {"user": m["user"], "target_user": m["target"], "tty": m["tty"],
                               "success": False, "service": "su"}
        if m := _SU_OK.match(msg):
            return "auth_su", {"user": m["user"], "target_user": m["target"], "tty": m["tty"],
                               "success": True, "service": "su"}
    elif ident == "useradd":
        if m := _USERADD.match(msg):
            return "account_created", {"user": m["user"], "uid": int(m["uid"]), "gid": int(m["gid"]),
                                       "home": m["home"], "shell": m["shell"].strip(),
                                       "service": "useradd"}
    return None


def parse_auth_line(line: str, now: datetime | None = None) -> tuple[str, dict[str, Any], float | None] | None:
    """Parse one auth.log line -> (event_type, data, log_timestamp) or None."""
    line = line.rstrip("\n")
    m = _RFC3339.match(line) or _BSD.match(line)
    if not m:
        return None
    parsed = parse_message(m["ident"], m["msg"])
    if parsed is None:
        return None
    etype, data = parsed
    data["host"] = m["host"]
    data["line"] = line
    return etype, data, parse_timestamp(m["ts"], now)


class AuthMonitor(Monitor):
    name = "auth"
    JOURNAL_IDENTS = ("sshd", "sshd-session", "sudo", "su", "useradd")

    def __init__(self, publish: Publish, backend: str = "auto", log_path: str | None = None,
                 poll_interval: float = 0.25, from_start: bool = False) -> None:
        super().__init__(publish)
        if backend not in ("auto", "file", "journald"):
            raise ValueError(f"unknown auth backend {backend!r}")
        self.requested_backend = backend
        self.log_path = log_path
        self.poll_interval = poll_interval
        self.from_start = from_start
        self.lines_read = 0
        self.lines_parsed = 0
        self._journal: subprocess.Popen | None = None

    def _resolve_path(self) -> str | None:
        if self.log_path:
            return self.log_path
        return next((p for p in DEFAULT_LOG_PATHS if os.path.exists(p)), None)

    def _start(self) -> None:
        backend = self.requested_backend
        path = self._resolve_path()
        if backend == "file" or (backend == "auto" and path):
            if not path:
                raise RuntimeError("no auth log found (looked for %s)" % ", ".join(DEFAULT_LOG_PATHS))
            self.log_path = path
            self.backend = "file"
            # Open + seek synchronously so that every line written after start()
            # returns is guaranteed to be read (no startup race with the thread).
            f = self._open_log(seek_end=not self.from_start)
            self.spawn(lambda: self._tail_loop(f), "tail")
            return
        if not shutil.which("journalctl"):
            raise RuntimeError("no auth log file and no journalctl available")
        self.backend = "journald"
        self.spawn(self._journal_loop, "journal")

    def _stop(self) -> None:
        if self._journal and self._journal.poll() is None:
            self._journal.terminate()

    def status(self) -> dict[str, Any]:
        st = super().status()
        st.update(source=self.log_path if self.backend == "file" else "journald",
                  lines_read=self.lines_read, lines_parsed=self.lines_parsed)
        return st

    def handle_line(self, line: str) -> bool:
        self.lines_read += 1
        parsed = parse_auth_line(line)
        if parsed is None:
            return False
        etype, data, ts = parsed
        self.lines_parsed += 1
        self.emit(etype, data, timestamp=ts)
        return True

    # ------------------------------------------------------------ file tail
    def _open_log(self, seek_end: bool):
        assert self.log_path
        try:
            f = open(self.log_path, "r", errors="replace")
        except OSError as e:
            self.record_error(f"open {self.log_path}: {e}")
            return None
        if seek_end:
            f.seek(0, os.SEEK_END)
        return f

    def _tail_loop(self, f) -> None:
        buf = ""
        inode = os.fstat(f.fileno()).st_ino if f else None
        while not self.stopping:
            if f is None:
                f = self._open_log(seek_end=False)  # (re)opened after rotation: read all
                if f is None:
                    if self.sleep(1.0):
                        break
                    continue
                inode = os.fstat(f.fileno()).st_ino
            chunk = f.read()
            if chunk:
                buf += chunk
                *lines, buf = buf.split("\n")
                for line in lines:
                    if line:
                        self.handle_line(line)
                continue
            # no new data: check for rotation / truncation
            try:
                st = os.stat(self.log_path)
                if st.st_ino != inode or st.st_size < f.tell():
                    f.close()
                    f = None  # rotated: reopen and read the new file from the start
                    continue
            except FileNotFoundError:
                pass  # mid-rotation; keep the old handle until the new file appears
            if self.sleep(self.poll_interval):
                break
        if f:
            f.close()

    # ------------------------------------------------------------ journald
    def _journal_loop(self) -> None:
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json", "--no-pager"]
        for i, ident in enumerate(self.JOURNAL_IDENTS):
            if i:
                cmd.append("+")
            cmd.append(f"SYSLOG_IDENTIFIER={ident}")
        self._journal = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        assert self._journal.stdout
        for raw in self._journal.stdout:
            if self.stopping:
                break
            self.handle_journal_entry(raw)

    def handle_journal_entry(self, raw: str) -> bool:
        self.lines_read += 1
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return False
        msg = entry.get("MESSAGE")
        if isinstance(msg, list):  # journald encodes non-UTF8 messages as byte arrays
            msg = bytes(msg).decode("utf-8", "replace")
        ident = entry.get("SYSLOG_IDENTIFIER", "")
        if not isinstance(msg, str):
            return False
        parsed = parse_message(ident, msg)
        if parsed is None:
            return False
        etype, data = parsed
        data["host"] = entry.get("_HOSTNAME")
        data["line"] = f"{ident}[{entry.get('SYSLOG_PID', entry.get('_PID', '?'))}]: {msg}"
        ts = entry.get("__REALTIME_TIMESTAMP")
        self.lines_parsed += 1
        self.emit(etype, data, timestamp=int(ts) / 1e6 if ts else None)
        return True
