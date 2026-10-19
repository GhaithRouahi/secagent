"""Policy engine: loads YAML rules and matches events against them.

Rule format::

    rules:
      - id: suspicious-shell-from-webserver
        description: Web server spawned an interactive shell
        mitre: T1505.003
        match:
          event_type: process_exec
          parent_name: [nginx, apache2]          # list  -> value is one of
          child_name: [sh, bash, nc]
          exe: {startswith: ["/tmp/", "/dev/shm/"]}   # dict -> operators
        severity: high
        action: alert                            # alert | kill_process | block_ip
        message: "{parent_name} spawned {child_name} (pid {pid})"
        threshold:                               # optional, makes the rule stateful
          count: 5
          window: 60
          group_by: [src_ip]
          distinct: dst_port                     # optional: count distinct values
          cooldown: 60                           # optional, default = window

Matching semantics
------------------
* All conditions in ``match`` must hold (logical AND).
* A scalar value means equality, a list means "any of".
* If the *event* value is a list (e.g. ``ancestors``), a positive operator holds if it
  holds for any element; a negative operator (``ne``, ``not_in``, ...) holds only if it
  holds for every element.
* A missing field fails every operator except ``exists: false``. Rules never fire on
  data they cannot see.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import string
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from secagent.events import SEVERITIES, Alert, Event

ACTIONS = ("alert", "kill_process", "block_ip")
_MISSING = object()


class PolicyError(ValueError):
    """Raised for invalid policy files; message points at the offending rule."""


# --------------------------------------------------------------------------- operators

def _as_list(v: Any) -> list:
    return list(v) if isinstance(v, (list, tuple, set, frozenset)) else [v]


def _norm(v: Any) -> Any:
    """Compare numbers numerically even if YAML/event types differ (\"22\" vs 22)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return v
    return v


def _eq(actual: Any, expected: Any) -> bool:
    return _norm(actual) == _norm(expected)


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _cidr(actual: Any, nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(str(actual))
    except ValueError:
        return False
    for n in nets:
        try:
            if ip in ipaddress.ip_network(str(n), strict=False):
                return True
        except ValueError:
            continue
    return False


# Scalar operators: (actual_scalar, expected) -> bool
_POSITIVE_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": _eq,
    "in": lambda a, e: any(_eq(a, x) for x in _as_list(e)),
    "contains": lambda a, e: any(str(x) in str(a) for x in _as_list(e)),
    "startswith": lambda a, e: any(str(a).startswith(str(x)) for x in _as_list(e)),
    "endswith": lambda a, e: any(str(a).endswith(str(x)) for x in _as_list(e)),
    "glob": lambda a, e: any(fnmatch.fnmatchcase(str(a), str(x)) for x in _as_list(e)),
    "regex": lambda a, e: any(re.search(str(x), str(a)) for x in _as_list(e)),
    "gt": lambda a, e: (n := _num(a)) is not None and n > float(e),
    "gte": lambda a, e: (n := _num(a)) is not None and n >= float(e),
    "lt": lambda a, e: (n := _num(a)) is not None and n < float(e),
    "lte": lambda a, e: (n := _num(a)) is not None and n <= float(e),
    "cidr": lambda a, e: _cidr(a, _as_list(e)),
}
# Negative operators are defined as "positive op fails"; with list-valued event fields
# they must hold for *every* element.
_NEGATIVE_OPS: dict[str, str] = {
    "ne": "eq",
    "not_in": "in",
    "not_contains": "contains",
    "not_startswith": "startswith",
    "not_glob": "glob",
    "not_regex": "regex",
    "not_cidr": "cidr",
}
OPERATORS = set(_POSITIVE_OPS) | set(_NEGATIVE_OPS) | {"exists"}


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: Any

    def evaluate(self, event: Event) -> bool:
        actual = event.get(self.field, _MISSING)
        if self.op == "exists":
            return (actual is not _MISSING and actual is not None) == bool(self.value)
        if actual is _MISSING or actual is None:
            return False
        values = actual if isinstance(actual, (list, tuple)) else [actual]
        if self.op in _NEGATIVE_OPS:
            fn = _POSITIVE_OPS[_NEGATIVE_OPS[self.op]]
            return all(not fn(v, self.value) for v in values)
        fn = _POSITIVE_OPS[self.op]
        return any(fn(v, self.value) for v in values)

    def describe(self) -> str:
        return f"{self.field} {self.op} {self.value!r}"


def _parse_conditions(rule_id: str, match: dict) -> list[Condition]:
    if not isinstance(match, dict) or not match:
        raise PolicyError(f"rule {rule_id!r}: 'match' must be a non-empty mapping")
    conds: list[Condition] = []
    for fld, spec in match.items():
        if isinstance(spec, dict):
            if not spec:
                raise PolicyError(f"rule {rule_id!r}: empty operator block for field {fld!r}")
            for op, val in spec.items():
                if op not in OPERATORS:
                    raise PolicyError(
                        f"rule {rule_id!r}: unknown operator {op!r} on field {fld!r} "
                        f"(valid: {', '.join(sorted(OPERATORS))})")
                if op == "regex" or op == "not_regex":
                    for pat in _as_list(val):
                        try:
                            re.compile(str(pat))
                        except re.error as e:
                            raise PolicyError(f"rule {rule_id!r}: bad regex {pat!r}: {e}") from e
                if op in ("gt", "gte", "lt", "lte") and _num(val) is None:
                    raise PolicyError(f"rule {rule_id!r}: {op} on {fld!r} needs a number")
                conds.append(Condition(str(fld), op, val))
        elif isinstance(spec, list):
            conds.append(Condition(str(fld), "in", spec))
        else:
            conds.append(Condition(str(fld), "eq", spec))
    return conds


# --------------------------------------------------------------------------- rules

@dataclass
class Threshold:
    count: int
    window: float
    group_by: list[str] = field(default_factory=list)
    distinct: str | None = None
    cooldown: float | None = None

    @property
    def effective_cooldown(self) -> float:
        return self.window if self.cooldown is None else self.cooldown


@dataclass
class Rule:
    id: str
    severity: str
    conditions: list[Condition]
    action: str = "alert"
    description: str = ""
    message: str | None = None
    enabled: bool = True
    threshold: Threshold | None = None
    mitre: str | None = None
    tags: list[str] = field(default_factory=list)

    def matches(self, event: Event) -> bool:
        return self.enabled and all(c.evaluate(event) for c in self.conditions)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "description": self.description,
            "severity": self.severity,
            "action": self.action,
            "enabled": self.enabled,
            "mitre": self.mitre,
            "match": [c.describe() for c in self.conditions],
        }
        if self.threshold:
            t = self.threshold
            d["threshold"] = {"count": t.count, "window": t.window, "group_by": t.group_by,
                              "distinct": t.distinct, "cooldown": t.effective_cooldown}
        return d


def _parse_threshold(rule_id: str, raw: Any) -> Threshold | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyError(f"rule {rule_id!r}: 'threshold' must be a mapping")
    try:
        count = int(raw["count"])
        window = float(raw["window"])
    except (KeyError, TypeError, ValueError) as e:
        raise PolicyError(f"rule {rule_id!r}: threshold needs numeric 'count' and 'window'") from e
    if count < 1 or window <= 0:
        raise PolicyError(f"rule {rule_id!r}: threshold count must be >=1 and window > 0")
    group_by = _as_list(raw.get("group_by", []))
    cooldown = raw.get("cooldown")
    return Threshold(count=count, window=window, group_by=[str(g) for g in group_by],
                     distinct=raw.get("distinct"),
                     cooldown=None if cooldown is None else float(cooldown))


def parse_rule(raw: dict) -> Rule:
    if not isinstance(raw, dict):
        raise PolicyError(f"rule entry must be a mapping, got {type(raw).__name__}")
    rule_id = raw.get("id")
    if not rule_id or not isinstance(rule_id, str):
        raise PolicyError(f"rule is missing a string 'id': {raw!r}")
    severity = str(raw.get("severity", "medium")).lower()
    if severity not in SEVERITIES:
        raise PolicyError(f"rule {rule_id!r}: severity must be one of {SEVERITIES}")
    action = str(raw.get("action", "alert"))
    if action not in ACTIONS:
        raise PolicyError(f"rule {rule_id!r}: action must be one of {ACTIONS}")
    return Rule(
        id=rule_id,
        severity=severity,
        conditions=_parse_conditions(rule_id, raw.get("match")),
        action=action,
        description=str(raw.get("description", "")),
        message=raw.get("message"),
        enabled=bool(raw.get("enabled", True)),
        threshold=_parse_threshold(rule_id, raw.get("threshold")),
        mitre=raw.get("mitre"),
        tags=[str(t) for t in _as_list(raw.get("tags", []))],
    )


@dataclass
class Policy:
    """A parsed policy file: rules plus monitor and response settings."""

    rules: list[Rule]
    monitors: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    source: str | None = None

    @classmethod
    def from_dict(cls, doc: dict | None, source: str | None = None) -> "Policy":
        doc = doc or {}
        if not isinstance(doc, dict):
            raise PolicyError("policy document must be a mapping")
        raw_rules = doc.get("rules") or []
        if not isinstance(raw_rules, list):
            raise PolicyError("'rules' must be a list")
        rules = [parse_rule(r) for r in raw_rules]
        seen: set[str] = set()
        for r in rules:
            if r.id in seen:
                raise PolicyError(f"duplicate rule id {r.id!r}")
            seen.add(r.id)
        return cls(rules=rules, monitors=dict(doc.get("monitors") or {}),
                   response=dict(doc.get("response") or {}),
                   settings=dict(doc.get("settings") or {}), source=source)

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        path = Path(path)
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            raise PolicyError(f"{path}: invalid YAML: {e}") from e
        return cls.from_dict(doc, source=str(path))

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        return cls.from_dict(yaml.safe_load(text))


# --------------------------------------------------------------------------- engine

class _SafeFields(dict):
    def __missing__(self, key: str) -> str:
        return "?"


def render_message(template: str | None, rule: Rule, event: Event, extra: dict | None = None) -> str:
    if not template:
        return rule.description or rule.id
    fields = _SafeFields(event.data)
    fields.update(event_type=event.type, source=event.source, rule_id=rule.id)
    if extra:
        fields.update(extra)
    try:
        return string.Formatter().vformat(template, (), fields)
    except (ValueError, IndexError, AttributeError, KeyError):
        return template


class _ThresholdState:
    __slots__ = ("hits", "last_fired")

    def __init__(self) -> None:
        self.hits: deque[tuple[float, Any]] = deque()
        self.last_fired: float | None = None


class PolicyEngine:
    """Evaluates events against a ``Policy``. Not thread-safe for ``evaluate`` by design:
    the EventBus calls it from a single dispatcher thread. ``reload`` is safe from any
    thread."""

    MAX_GROUPS_PER_RULE = 10_000  # bound memory if an attacker sprays source IPs

    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._lock = threading.Lock()
        self._state: dict[str, OrderedDict[tuple, _ThresholdState]] = {}
        self.match_counts: dict[str, int] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        return cls(Policy.from_file(path))

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def rules(self) -> list[Rule]:
        return self._policy.rules

    def get_rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self._policy.rules if r.id == rule_id), None)

    def reload(self, policy: Policy) -> None:
        with self._lock:
            self._policy = policy
            known = {r.id for r in policy.rules}
            self._state = {k: v for k, v in self._state.items() if k in known}

    def evaluate(self, event: Event) -> list[Alert]:
        with self._lock:
            rules = list(self._policy.rules)
        alerts: list[Alert] = []
        for rule in rules:
            if not rule.matches(event):
                continue
            self.match_counts[rule.id] = self.match_counts.get(rule.id, 0) + 1
            if rule.threshold is None:
                alerts.append(self._make_alert(rule, event))
                continue
            ctx = self._threshold_hit(rule, event)
            if ctx is not None:
                alerts.append(self._make_alert(rule, event, ctx))
        return alerts

    def _make_alert(self, rule: Rule, event: Event, ctx: dict | None = None) -> Alert:
        alert_event = event
        if ctx:
            # Copy so threshold context never leaks into the event seen by other rules.
            alert_event = Event(type=event.type, source=event.source,
                                data={**event.data, "_threshold": ctx},
                                timestamp=event.timestamp, id=event.id)
        return Alert(rule_id=rule.id, severity=rule.severity,
                     message=render_message(rule.message, rule, event, ctx),
                     event=alert_event, action=rule.action)

    def _threshold_hit(self, rule: Rule, event: Event) -> dict | None:
        t = rule.threshold
        assert t is not None
        key = tuple(str(event.get(g)) for g in t.group_by)
        groups = self._state.setdefault(rule.id, OrderedDict())
        st = groups.get(key)
        if st is None:
            st = groups[key] = _ThresholdState()
            if len(groups) > self.MAX_GROUPS_PER_RULE:
                groups.popitem(last=False)
        else:
            groups.move_to_end(key)

        now = event.timestamp
        if st.last_fired is not None and now - st.last_fired < t.effective_cooldown:
            return None  # suppressed: already alerted for this group recently

        st.hits.append((now, event.get(t.distinct) if t.distinct else None))
        cutoff = now - t.window
        while st.hits and st.hits[0][0] < cutoff:
            st.hits.popleft()

        if t.distinct:
            distinct_vals = {v for _, v in st.hits if v is not None}
            observed = len(distinct_vals)
        else:
            distinct_vals = set()
            observed = len(st.hits)

        if observed < t.count:
            return None
        st.last_fired = now
        st.hits.clear()
        ctx: dict[str, Any] = {"count": observed, "window": t.window,
                               "group": dict(zip(t.group_by, key))}
        if t.distinct:
            ctx["distinct_field"] = t.distinct
            ctx["distinct_values"] = sorted(map(str, distinct_vals))[:50]
        return ctx

    def explain(self, rule_id: str, event: Event) -> dict[str, Any]:
        """Dry-run one rule against an event without touching threshold state.
        Used by ``secagentctl policy test``."""
        rule = self.get_rule(rule_id)
        if rule is None:
            raise KeyError(rule_id)
        results = []
        for c in rule.conditions:
            actual = event.get(c.field, _MISSING)
            results.append({
                "condition": c.describe(),
                "actual": None if actual is _MISSING else actual,
                "present": actual is not _MISSING,
                "passed": c.evaluate(event),
            })
        matched = rule.enabled and all(r["passed"] for r in results)
        return {
            "rule_id": rule.id,
            "enabled": rule.enabled,
            "matched": matched,
            "severity": rule.severity,
            "action": rule.action,
            "threshold": rule.to_dict().get("threshold"),
            "message": render_message(rule.message, rule, event) if matched else None,
            "conditions": results,
        }
