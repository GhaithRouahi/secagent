"""secagentctl - operate and query SecAgent.

Works standalone: ``alerts``, ``show`` and ``policy list|test|validate`` read the SQLite
store / policy file directly, so they work even when the daemon (or dashboard) is down.
``status``, ``policy reload`` and live ``tail`` talk to secagentd over its Unix socket.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from secagent import __version__, config
from secagent.daemon import control
from secagent.daemon.policy_engine import Policy, PolicyEngine, PolicyError
from secagent.events import SEVERITIES, Event

# ----------------------------------------------------------------------------- output

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
SEV_COLOR = {"critical": "1;97;41", "high": "1;91", "medium": "1;93", "low": "1;96"}


def c(text: Any, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def dim(t: Any) -> str:
    return c(t, "2")


def bold(t: Any) -> str:
    return c(t, "1")


def sev(s: str, width: int = 0) -> str:
    label = s.upper().ljust(width)
    return c(label, SEV_COLOR.get(s, "0"))


def term_width() -> int:
    return shutil.get_terminal_size((120, 24)).columns


def trunc(s: Any, n: int) -> str:
    s = str(s if s is not None else "")
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def table(headers: list[str], rows: list[list[Any]], flex: int = -1,
          colorize: dict[int, Any] | None = None) -> None:
    """Print a table; column ``flex`` absorbs the remaining terminal width."""
    widths = [max(len(h), *(len(str(r[i])) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    flex = flex % len(headers)
    fixed = sum(w for i, w in enumerate(widths) if i != flex) + 2 * (len(headers) - 1)
    widths[flex] = max(20, min(widths[flex], term_width() - fixed - 1))
    print(bold("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))).rstrip())
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            txt = trunc(v, widths[i]).ljust(widths[i]) if i != len(r) - 1 else trunc(v, widths[i])
            if colorize and i in colorize:
                txt = colorize[i](v, txt)
            cells.append(txt)
        print("  ".join(cells).rstrip())


def fmt_ts(ts: float, date: bool = True) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S" if date else "%H:%M:%S")


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    return " ".join(p for p in (f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m" if m else "",
                                f"{s}s" if not (d or h) else "") if p) or "0s"


def parse_since(text: str) -> float:
    """'30s', '15m', '2h', '7d', or an ISO date/time."""
    m = re.fullmatch(r"(\d+)\s*([smhd])", text.strip())
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return time.time() - int(m.group(1)) * mult
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad time {text!r}: use 30m, 2h, 1d or 2026-10-19T10:00")


def die(msg: str, code: int = 1) -> None:
    print(c("error: ", "1;91") + msg, file=sys.stderr)
    sys.exit(code)


def open_storage(path: str):
    from secagent.daemon.storage import Storage
    if not Path(path).exists():
        die(f"no database at {path} (has secagentd run yet? override with --db)")
    try:
        return Storage(path, readonly=True)
    except Exception as e:
        die(f"cannot open {path}: {e} (try sudo)")


def daemon_request(args, cmd: dict) -> dict:
    try:
        resp = control.request(args.socket, cmd)
    except FileNotFoundError:
        die(f"secagentd is not running (no socket at {args.socket})", 3)
    except PermissionError:
        die(f"permission denied on {args.socket} (run with sudo)", 4)
    except (ConnectionError, OSError) as e:
        die(f"cannot reach secagentd at {args.socket}: {e}", 3)
    if not resp.get("ok"):
        die(resp.get("error", "daemon returned an error"))
    return resp


# ----------------------------------------------------------------------------- event text

def summarize_event(etype: str, d: dict[str, Any]) -> str:
    g = lambda k: d.get(k, "?")  # noqa: E731
    if etype == "process_exec":
        return f"{g('parent_name')}({g('ppid')}) → {g('child_name')}({g('pid')}) uid={g('uid')}  {g('cmdline')}"
    if etype == "file_change":
        return f"{g('change')} {g('path')}  [{g('group')}] {d.get('old_hash') or '-'} → {d.get('new_hash') or '-'}"
    if etype == "net_connect":
        return f"{g('process_name')}({g('pid')}) → {g('dst')}"
    if etype == "net_accept":
        return f"{g('src_ip')}:{g('src_port')} → {g('process_name')}({g('pid')}) :{g('local_port')}"
    if etype == "net_listen":
        return f"{g('process_name')}({g('pid')}) listening on {g('local_ip')}:{g('local_port')}"
    if etype in ("auth_failure", "auth_success", "auth_invalid_user"):
        return f"{g('service')} user={g('user')} from {g('src_ip')} ({d.get('method', '-')})"
    if etype in ("auth_sudo", "auth_su"):
        return f"{g('user')} → {g('target_user')} {'ok' if d.get('success') else 'FAILED'} {d.get('command', '')}"
    return " ".join(f"{k}={v}" for k, v in d.items() if k not in ("line", "argv"))


# ----------------------------------------------------------------------------- commands

def cmd_status(args) -> int:
    st = daemon_request(args, {"cmd": "status"})["status"]
    if args.json:
        print(json.dumps(st, indent=2))
        return 0
    print(f"{c('●', '1;92')} {bold('secagentd')} running  "
          f"(pid {st['pid']}, up {fmt_duration(st['uptime'])}, v{st['version']}, host {st['hostname']})")
    print(f"  {'policy':<10} {st['policy']}  ({st['rules']} rules)")
    print(f"  {'database':<10} {st['db']}  ({st['events_stored']} events stored)")
    print(f"  {'dashboard':<10} {st['dashboard'] or dim('off')}")
    r = st["response"]
    resp = (c("ENABLED", "1;91") + (" (dry-run)" if r["dry_run"] else "")) if r["enabled"] else dim("disabled (alert-only)")
    print(f"  {'response':<10} {resp}  firewall={r['firewall']} executed={r['executed']}")
    print()
    rows = []
    for m in st["monitors"]:
        note = m.get("self_test") and f"self-test {m['self_test']}"
        if m["name"] == "file":
            note = f"{m.get('files_tracked', 0)} files, {m.get('dirs_watched', 0)} dirs watched"
        elif m["name"] == "auth":
            note = f"{m.get('source')} ({m.get('lines_parsed', 0)}/{m.get('lines_read', 0)} lines matched)"
        if m.get("fallback_reason"):
            note = f"fallback: {m['fallback_reason']}"
        if m.get("last_error"):
            note = f"{note or ''}  last error: {m['last_error']}".strip()
        rows.append([m["name"], m["backend"], "running" if m["running"] else "STOPPED", m["events"], note or ""])
    for name, err in st.get("monitor_failures", {}).items():
        rows.append([name, "-", "FAILED", 0, err])
    table(["MONITOR", "BACKEND", "STATE", "EVENTS", "NOTES"], rows,
          colorize={2: lambda v, t: c(t, "92" if v == "running" else "1;91")})
    print()
    a = st["alerts"]["by_severity"]
    print(bold("  ALERTS   ") + "  ".join(f"{sev(s)} {a.get(s, 0)}" for s in reversed(SEVERITIES))
          + f"   (total {st['alerts']['total']})")
    b = st["bus"]
    print(bold("  PIPELINE ") + f"published {b['published']}  processed {b['processed']}  "
          f"dropped {b['dropped']}  queue {b['queue']}")
    return 0


def cmd_alerts(args) -> int:
    store = open_storage(args.db)
    rows = store.query_alerts(since=args.since, min_severity=args.severity, rule_id=args.rule,
                              limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print(dim("no alerts match"))
        return 0
    table(["ID", "TIME", "SEVERITY", "RULE", "MESSAGE"],
          [[a["id"], fmt_ts(a["timestamp"]), a["severity"].upper(), a["rule_id"],
            a["message"] + (f"  [{a['action_result']}]" if a["action_result"] else "")]
           for a in reversed(rows)],
          colorize={2: lambda v, t: c(t, SEV_COLOR.get(v.lower(), "0"))})
    print(dim(f"\n{len(rows)} alert(s). Details: secagentctl show <ID>"))
    return 0


def cmd_show(args) -> int:
    store = open_storage(args.db)
    rows = store.query_alerts(after_id=args.id - 1, limit=1, ascending=True)
    if not rows or rows[0]["id"] != args.id:
        die(f"no alert with id {args.id}")
    a = rows[0]
    if args.json:
        print(json.dumps(a, indent=2, default=str))
        return 0
    print(f"{bold('Alert #' + str(a['id']))}  {sev(a['severity'])}  {a['rule_id']}")
    print(f"  time     {fmt_ts(a['timestamp'])}")
    print(f"  message  {a['message']}")
    print(f"  action   {a['action']}" + (f" → {a['action_result']}" if a["action_result"] else ""))
    print(f"  source   {a['source']} / {a['event_type']}")
    print(bold("\n  event data"))
    for k, v in a["event"]["data"].items():
        print(f"    {k:<22} {json.dumps(v, default=str) if isinstance(v, (dict, list)) else v}")
    return 0


def load_policy(args) -> Policy:
    try:
        return Policy.from_file(args.policy)
    except FileNotFoundError:
        die(f"policy file not found: {args.policy}")
    except PolicyError as e:
        die(f"invalid policy: {e}", 2)


def cmd_policy_list(args) -> int:
    rules, source = None, args.policy
    if not args.file:
        try:  # prefer what the daemon has actually loaded
            resp = control.request(args.socket, {"cmd": "rules"}, timeout=2)
            if resp.get("ok"):
                rules, source = resp["rules"], f"{resp['source']} (loaded in secagentd)"
        except OSError:
            pass
    if rules is None:
        rules = [r.to_dict() for r in load_policy(args).rules]
    if args.json:
        print(json.dumps(rules, indent=2))
        return 0
    print(dim(f"source: {source}\n"))
    table(["ID", "SEVERITY", "ACTION", "MITRE", "DESCRIPTION"],
          [[r["id"] + ("" if r["enabled"] else " (disabled)"), r["severity"].upper(), r["action"],
            r.get("mitre") or "-", r["description"] + (" [threshold]" if r.get("threshold") else "")]
           for r in rules],
          colorize={1: lambda v, t: c(t, SEV_COLOR.get(v.lower(), "0"))})
    return 0


def _coerce(v: str) -> Any:
    try:
        return json.loads(v)
    except json.JSONDecodeError:
        return v


def cmd_policy_test(args) -> int:
    engine = PolicyEngine(load_policy(args))
    if args.event_file:
        raw = json.load(sys.stdin if args.event_file == "-" else open(args.event_file))
    elif args.event:
        raw = json.loads(args.event)
    elif args.fields:
        raw = {}
        for kv in args.fields:
            if "=" not in kv:
                die(f"expected key=value, got {kv!r}")
            k, v = kv.split("=", 1)
            raw[k] = _coerce(v)
    else:
        die("give an event: key=value pairs, --event JSON, or --event-file FILE")
    event = Event.from_dict(raw)
    try:
        res = engine.explain(args.rule_id, event)
    except KeyError:
        die(f"no rule {args.rule_id!r} in {args.policy}")
    if args.json:
        print(json.dumps(res, indent=2, default=str))
        return 0 if res["matched"] else 1
    print(f"{bold('rule')} {res['rule_id']}  {sev(res['severity'])}  action={res['action']}"
          + ("" if res["enabled"] else c("  (disabled)", "93")))
    print(f"{bold('event')} {event.type} {json.dumps(event.data, default=str)}\n")
    for cond in res["conditions"]:
        mark = c("✓", "1;92") if cond["passed"] else c("✗", "1;91")
        actual = json.dumps(cond["actual"], default=str) if cond["present"] else c("<missing>", "93")
        print(f"  {mark} {cond['condition']:<60} {dim('actual:')} {actual}")
    print()
    if res["matched"]:
        print(c("MATCH", "1;92") + f"  → would raise: {res['message']}")
        if res["threshold"]:
            t = res["threshold"]
            print(dim(f"  (stateful rule: alerts once {t['count']} matching events occur within "
                      f"{t['window']}s per {t['group_by']}" + (f", counting distinct {t['distinct']}" if t["distinct"] else "") + ")"))
        return 0
    print(c("NO MATCH", "1;93"))
    return 1


def cmd_policy_validate(args) -> int:
    p = load_policy(args)
    print(c("✓", "1;92") + f" {args.policy}: {len(p.rules)} rules, monitors: "
          + ", ".join(n for n, m in p.monitors.items() if (m or {}).get("enabled")))
    return 0


def cmd_policy_reload(args) -> int:
    n = daemon_request(args, {"cmd": "reload"})["rules"]
    print(c("✓", "1;92") + f" policy reloaded: {n} rules active")
    return 0


def render_stream_msg(msg: dict, args) -> None:
    kind, d = msg.get("kind"), msg.get("data") or {}
    if kind == "alert":
        if args.severity and SEVERITIES.index(d["severity"]) < SEVERITIES.index(args.severity):
            return
        label = d["severity"].upper()
        banner = c(f" ▲ {label:<8}", SEV_COLOR[d["severity"]]) if USE_COLOR else f"[{label}]"
        line = f"{dim(fmt_ts(d['timestamp'], date=False))} {banner} {bold(d['rule_id'])}  {d['message']}"
        if d.get("action_result"):
            line += c(f"  [{d['action']}: {d['action_result']}]", "95")
        print(line, flush=True)
    elif kind == "event" and not args.alerts_only:
        if args.type and d.get("type") not in args.type:
            return
        width = term_width() - 32
        print(dim(f"{fmt_ts(d['timestamp'], date=False)}   {d['type']:<16} "
                  f"{trunc(summarize_event(d['type'], d.get('data', {})), width)}"), flush=True)


def cmd_tail(args) -> int:
    if args.type:
        args.type = set(args.type.split(","))
    try:
        stream = control.subscribe(args.socket, alerts_only=args.alerts_only)
        first = next(stream)
        if not first.get("ok"):
            die(first.get("error", "subscribe failed"))
    except (FileNotFoundError, ConnectionRefusedError):
        return tail_db(args)
    except PermissionError:
        die(f"permission denied on {args.socket} (run with sudo)", 4)
    print(dim(f"streaming from secagentd ({args.socket}) - Ctrl-C to stop"
              + (" - alerts only" if args.alerts_only else "")), flush=True)
    try:
        for msg in stream:
            render_stream_msg(msg, args)
    except KeyboardInterrupt:
        pass
    return 0


def tail_db(args) -> int:
    """Fallback when the daemon socket is unavailable: follow new alerts in SQLite."""
    store = open_storage(args.db)
    last = (store.query_alerts(limit=1) or [{"id": 0}])[0]["id"]
    print(dim(f"secagentd socket unavailable - following alerts in {args.db} - Ctrl-C to stop"), flush=True)
    try:
        while True:
            for a in store.query_alerts(after_id=last, ascending=True, limit=500):
                last = a["id"]
                render_stream_msg({"kind": "alert", "data": a}, args)
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


# ----------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secagentctl", description="Control and query the SecAgent HIDS.")
    p.add_argument("--socket", default=str(config.socket_path()), help="secagentd control socket")
    p.add_argument("--db", default=str(config.db_path()), help="SQLite alert database")
    p.add_argument("--policy", default=str(config.policy_path()), help="policy file")
    p.add_argument("--version", action="version", version=f"secagentctl {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("status", help="daemon health, uptime and monitors")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("alerts", help="list alerts (reads the database; works without the daemon)")
    s.add_argument("--since", type=parse_since, help="e.g. 30m, 2h, 1d, 2026-10-19T09:00")
    s.add_argument("--severity", choices=SEVERITIES, help="minimum severity")
    s.add_argument("--rule", help="only this rule id")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_alerts)

    s = sub.add_parser("show", help="full details of one alert, including the raw event")
    s.add_argument("id", type=int)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("tail", help="live-stream events and alerts")
    s.add_argument("--alerts-only", "-a", action="store_true", help="hide raw events")
    s.add_argument("--severity", choices=SEVERITIES, help="minimum alert severity to show")
    s.add_argument("--type", help="only these event types (comma-separated), e.g. process_exec")
    s.set_defaults(func=cmd_tail)

    pol = sub.add_parser("policy", help="inspect, test and reload detection rules")
    psub = pol.add_subparsers(dest="policy_cmd", required=True)
    s = psub.add_parser("list", help="show loaded rules")
    s.add_argument("--file", action="store_true", help="read the policy file even if the daemon is up")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_policy_list)
    s = psub.add_parser("test", help="dry-run one rule against a sample event",
                        description="Example: secagentctl policy test suspicious-shell-from-webserver "
                                    "event_type=process_exec parent_name=nginx child_name=bash pid=4242")
    s.add_argument("rule_id")
    s.add_argument("fields", nargs="*", metavar="key=value", help="event fields (values parsed as JSON when possible)")
    s.add_argument("--event", help="event as a JSON object")
    s.add_argument("--event-file", help="file with a JSON event ('-' for stdin)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_policy_test)
    s = psub.add_parser("validate", help="check a policy file for errors")
    s.set_defaults(func=cmd_policy_validate)
    s = psub.add_parser("reload", help="tell secagentd to re-read the policy file")
    s.set_defaults(func=cmd_policy_reload)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. piped into `head`
        return 0


if __name__ == "__main__":
    sys.exit(main())
