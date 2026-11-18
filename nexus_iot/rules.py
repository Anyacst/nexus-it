"""Examiner-supplied detection rules evaluated over the reconstructed timeline.

A rules file is JSON: ``{"rules": [ {...}, ... ]}``. Every rule has an ``id``, a
``title``, a ``type`` and an optional ``severity`` (info, low, medium, high) and
``description``. Rules match timeline rows with a *matcher*: an object whose keys
are any of ``event``, ``device`` and ``label`` and whose values are a string or a
list of strings. A matcher without ``label`` only matches rows labelled Confirmed
or Single-source, so Inferred rows and Unknown gaps never count as an observed
event unless a rule asks for them.

Rule types:

``match``
    One finding per matching row (``"match": matcher``).
``absent_within``
    One finding per ``trigger`` row with no ``expect`` row within
    ``window_seconds`` (``"direction"``: before, after or both; default both).
``sequence``
    One finding when a ``then`` row follows a ``first`` row within
    ``within_seconds`` (the earliest such ``then`` row is reported).
``count_within``
    One finding each time ``count`` matching rows fall within
    ``window_seconds``; counting restarts after each finding.
``time_of_day``
    One finding per matching row whose local time falls between ``start`` and
    ``end`` ("HH:MM", end exclusive; a window may wrap past midnight) in
    ``timezone`` (UTC, a fixed offset such as "+05:30", or an IANA name such as
    "Europe/London"), optionally only on some ``days`` (mon ... sun, the
    event's local date). A row whose best time is outside the window but whose
    time range reaches into it is reported too, and the detail says so.
``mqtt_client``
    One finding per matching row decoded from MQTT whose client identifier is
    not allowed by any pattern in ``allowed`` (shell-style wildcards; the
    placeholder ``{device}`` stands for the device the message was for, or the
    device mapped to a session's IP address). ``match`` is optional. Rows whose
    client identifier is unknown (its CONNECT is not in the capture) are only
    reported with ``"flag_unknown": true``.

Findings are leads for an examiner to review. They inherit the time uncertainty
of the rows they cite and are never proof of what happened.
"""
from __future__ import annotations

import glob
import hashlib
import json
import math
import re
from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta, timezone, tzinfo
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path

RULE_TYPES = ("match", "absent_within", "sequence", "count_within", "time_of_day", "mqtt_client")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
SEVERITIES = ("info", "low", "medium", "high")
MATCHER_KEYS = ("event", "device", "label")
DEFAULT_LABELS = ("Confirmed", "Single-source")
MAX_RULES_FILE_BYTES = 1_000_000
MAX_RULES = 200
MAX_FINDINGS_PER_RULE = 500
_CALIBRATED_BASES = {"gateway-clock-assumed", "device-clock-calibrated-to-gateway",
                     "device-clock-piecewise-calibrated-to-gateway", "capture-clock-as-recorded"}


def _strings(value, where: str) -> tuple[str, ...]:
    """Return a matcher value as a tuple of non-empty strings, or raise ValueError."""
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
        raise ValueError(f"{where} must be a non-empty string or list of non-empty strings")
    return tuple(values)


def _matcher(value, where: str) -> dict[str, tuple[str, ...]]:
    """Validate one matcher object and return it with every value as a tuple."""
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{where} must be a non-empty object with keys from {', '.join(MATCHER_KEYS)}")
    unknown = sorted(set(value) - set(MATCHER_KEYS))
    if unknown:
        raise ValueError(f"{where} has unknown key(s) {', '.join(unknown)}; allowed: {', '.join(MATCHER_KEYS)}")
    return {key: _strings(v, f"{where}.{key}") for key, v in value.items()}


def _seconds(value, where: str) -> float:
    """Validate a positive finite number of seconds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{where} must be a positive number of seconds")
    return float(value)


_CLOCK = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
_OFFSET = re.compile(r"([+-])(\d\d):([0-5]\d)")


def _clock(value, where: str) -> int:
    """Validate an "HH:MM" time of day and return it as seconds after midnight."""
    m = _CLOCK.fullmatch(value) if isinstance(value, str) else None
    if not m:
        raise ValueError(f"{where} must be a time of day as \"HH:MM\" (00:00 to 23:59)")
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60


@lru_cache(maxsize=64)
def _zone(name: str) -> tzinfo:
    """Resolve "UTC", a fixed offset "+HH:MM" or an IANA zone name; raise ValueError if unknown."""
    if name in ("UTC", "Z"):
        return timezone.utc
    m = _OFFSET.fullmatch(name)
    if m:
        minutes = int(m.group(2)) * 60 + int(m.group(3))
        if minutes > 14 * 60:
            raise ValueError(f"UTC offset {name} is outside -14:00 to +14:00")
        return timezone((-1 if m.group(1) == "-" else 1) * timedelta(minutes=minutes), name)
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError(f"unknown time zone '{name}' (use UTC, an offset such as +05:30, or an IANA name; "
                         "IANA names need the system time-zone database)") from None


def _rule(raw, index: int, seen: set[str]) -> dict:
    """Validate one raw rule and return its normalised form."""
    where = f"rule {index}"
    if not isinstance(raw, dict):
        raise ValueError(f"{where} must be an object")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError(f"{where} needs a non-empty string id")
    where = f"rule {index} ({rule_id})"
    if rule_id in seen:
        raise ValueError(f"{where}: duplicate id")
    seen.add(rule_id)
    title = raw.get("title")
    if not isinstance(title, str) or not title.strip():
        raise ValueError(f"{where} needs a non-empty title")
    kind = raw.get("type")
    if kind not in RULE_TYPES:
        raise ValueError(f"{where}: type must be one of {', '.join(RULE_TYPES)}")
    severity = raw.get("severity", "medium")
    if severity not in SEVERITIES:
        raise ValueError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise ValueError(f"{where}: description must be a string")
    rule = {"id": rule_id, "title": title, "type": kind, "severity": severity, "description": description}
    fields = {"match": ("match",), "absent_within": ("trigger", "expect", "window_seconds", "direction"),
              "sequence": ("first", "then", "within_seconds"), "count_within": ("match", "count", "window_seconds"),
              "time_of_day": ("match", "start", "end", "timezone", "days"),
              "mqtt_client": ("match", "allowed", "flag_unknown")}[kind]
    unknown = sorted(set(raw) - set(fields) - {"id", "title", "type", "severity", "description"})
    if unknown:
        raise ValueError(f"{where}: unknown field(s) {', '.join(unknown)} for type {kind}")
    if kind == "match":
        rule["match"] = _matcher(raw.get("match"), f"{where}.match")
    elif kind == "absent_within":
        rule["trigger"] = _matcher(raw.get("trigger"), f"{where}.trigger")
        rule["expect"] = _matcher(raw.get("expect"), f"{where}.expect")
        rule["window_seconds"] = _seconds(raw.get("window_seconds"), f"{where}.window_seconds")
        rule["direction"] = raw.get("direction", "both")
        if rule["direction"] not in ("before", "after", "both"):
            raise ValueError(f"{where}.direction must be before, after or both")
    elif kind == "sequence":
        rule["first"] = _matcher(raw.get("first"), f"{where}.first")
        rule["then"] = _matcher(raw.get("then"), f"{where}.then")
        rule["within_seconds"] = _seconds(raw.get("within_seconds"), f"{where}.within_seconds")
    elif kind == "time_of_day":
        rule["match"] = _matcher(raw.get("match"), f"{where}.match")
        rule["start"] = _clock(raw.get("start"), f"{where}.start")
        rule["end"] = _clock(raw.get("end"), f"{where}.end")
        if rule["start"] == rule["end"]:
            raise ValueError(f"{where}: start and end must differ")
        rule["timezone"] = raw.get("timezone", "UTC")
        if not isinstance(rule["timezone"], str):
            raise ValueError(f"{where}.timezone must be a string")
        try:
            _zone(rule["timezone"])
        except ValueError as e:
            raise ValueError(f"{where}.timezone: {e}") from None
        days = raw.get("days", list(DAYS))
        if not isinstance(days, list) or not days or not all(isinstance(d, str) and d.lower() in DAYS for d in days):
            raise ValueError(f"{where}.days must be a non-empty list of {', '.join(DAYS)}")
        rule["days"] = tuple(sorted({DAYS.index(d.lower()) for d in days}))
    elif kind == "mqtt_client":
        rule["match"] = _matcher(raw["match"], f"{where}.match") if "match" in raw else {}
        allowed = raw.get("allowed")
        if not isinstance(allowed, list) or not allowed or not all(isinstance(a, str) and a.strip() for a in allowed):
            raise ValueError(f"{where}.allowed must be a non-empty list of client-identifier patterns")
        rule["allowed"] = tuple(allowed)
        rule["flag_unknown"] = raw.get("flag_unknown", False)
        if not isinstance(rule["flag_unknown"], bool):
            raise ValueError(f"{where}.flag_unknown must be true or false")
    else:
        rule["match"] = _matcher(raw.get("match"), f"{where}.match")
        count = raw.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 2:
            raise ValueError(f"{where}.count must be an integer of at least 2")
        rule["count"] = count
        rule["window_seconds"] = _seconds(raw.get("window_seconds"), f"{where}.window_seconds")
    return rule


def parse_rules(data, source: str = "<rules>") -> list[dict]:
    """Validate a parsed rules document and return its normalised rules."""
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"{source}: expected an object with a 'rules' list")
    if len(data["rules"]) > MAX_RULES:
        raise ValueError(f"{source}: at most {MAX_RULES} rules are supported")
    seen: set[str] = set()
    try:
        return [_rule(raw, i, seen) for i, raw in enumerate(data["rules"], 1)]
    except ValueError as e:
        raise ValueError(f"{source}: {e}") from None


def load_rules(path: Path) -> dict:
    """Read and validate a rules file; return its rules plus the file's path and SHA-256."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise ValueError(f"cannot read rules file: {e}") from e
    if len(raw) > MAX_RULES_FILE_BYTES:
        raise ValueError(f"{path}: rules file is larger than {MAX_RULES_FILE_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"{path}: not valid UTF-8 JSON ({e})") from None
    return {"source": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest(), "rules": parse_rules(data, str(path))}


def _row_devices(row: dict) -> set[str]:
    """Return the individual device or source names of a timeline row."""
    return {part.strip() for part in str(row.get("device_or_source", "")).split(",") if part.strip()}


def _matches(row: dict, matcher: dict[str, tuple[str, ...]]) -> bool:
    """Return True when a timeline row satisfies every key of the matcher."""
    if str(row.get("label", "")) not in matcher.get("label", DEFAULT_LABELS):
        return False
    if "event" in matcher and str(row.get("event", "")) not in matcher["event"]:
        return False
    if "device" in matcher and not _row_devices(row) & set(matcher["device"]):
        return False
    return True


def _select(rows: list[dict], matcher: dict) -> list[dict]:
    """Return the rows that satisfy the matcher, in time order."""
    return sorted((r for r in rows if _matches(r, matcher)), key=lambda r: (r["timestamp"], str(r.get("event_id", ""))))


def _finding(rule: dict, rows: list[dict], detail: str) -> dict:
    """Build one finding that cites ``rows``; the first row's time is the finding time."""
    uncalibrated = sorted({str(r.get("time_basis", "unknown")) for r in rows if r.get("time_basis") not in _CALIBRATED_BASES})
    note = ""
    if uncalibrated:
        note = ("Cited times are not all calibrated to the gateway clock (" + ", ".join(uncalibrated) +
                "); the time window in this rule may not hold.")
    devices = sorted(set().union(*(_row_devices(r) for r in rows)))
    return {"rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"], "timestamp": rows[0]["timestamp"],
            "event_ids": [str(r.get("event_id", "")) for r in rows], "devices": devices, "detail": detail, "time_note": note}


def _describe(row: dict) -> str:
    """Short plain-text reference to a timeline row."""
    return f"'{row.get('event', '')}' ({row.get('device_or_source', '')}, {row.get('label', '')})"


def _hhmm(seconds: int) -> str:
    """Format seconds after midnight as HH:MM."""
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}"


def _in_window(t: float, rule: dict, zone: tzinfo) -> bool:
    """True when instant ``t`` falls inside the rule's local time-of-day window and days."""
    local = datetime.fromtimestamp(t, zone)
    if local.weekday() not in rule["days"]:
        return False
    s = local.hour * 3600 + local.minute * 60 + local.second + local.microsecond / 1e6
    start, end = rule["start"], rule["end"]
    return start <= s < end if start < end else (s >= start or s < end)


def _window_samples(lo: float, hi: float, rule: dict, zone: tzinfo) -> list[float] | None:
    """Instants that cover every piece of [lo, hi] between window boundaries, or None if the range is too long."""
    if hi - lo > 3 * 86400:
        return None
    samples = [lo, hi]
    first = datetime.fromtimestamp(lo, zone).date() - timedelta(days=1)
    boundaries = {rule["start"], rule["end"], 0}
    for day in range((datetime.fromtimestamp(hi, zone).date() - first).days + 2):
        date = first + timedelta(days=day)
        for b in boundaries:
            t = datetime(date.year, date.month, date.day, b // 3600, b % 3600 // 60, tzinfo=zone).timestamp()
            if lo < t <= hi:
                samples += [t, t - 1e-3]
    return samples


def _time_of_day(rule: dict, rows: list[dict]) -> list[dict]:
    """Findings for a time_of_day rule."""
    zone = _zone(rule["timezone"])
    window = f"{_hhmm(rule['start'])}-{_hhmm(rule['end'])} {rule['timezone']}"
    if len(rule["days"]) < 7:
        window += " on " + ", ".join(DAYS[d] for d in rule["days"])
    out = []
    for r in _select(rows, rule["match"]):
        t = r["timestamp"]
        span = r.get("time_range")
        lo, hi = (float(span[0]), float(span[1])) if isinstance(span, list) and len(span) == 2 and span[0] is not None else (t, t)
        lo, hi = min(lo, t), max(hi, t)
        inside = _in_window(t, rule, zone)
        samples = _window_samples(lo, hi, rule, zone)
        local = datetime.fromtimestamp(t, zone).isoformat(timespec="seconds")
        if samples is None:
            mixed = True
        else:
            mixed = any(_in_window(x, rule, zone) != inside for x in samples)
        if inside:
            detail = f"{_describe(r)} at local time {local}, inside {window}"
            if mixed:
                detail += "; its time range also extends outside the window"
        elif mixed:
            detail = (f"{_describe(r)} best estimate {local} is outside {window}, but its time range "
                      f"reaches into the window")
        else:
            continue
        out.append(_finding(rule, [r], detail))
    return out


def _mqtt_identities(row: dict) -> list[tuple[str | None, list[str], str]]:
    """(client_id, devices, kind) for each MQTT witness of a row; empty when the row has no MQTT origin."""
    publishers = row.get("mqtt_publishers")
    if isinstance(publishers, list):
        return [(p.get("client_id"), [str(p.get("device", ""))] if p.get("device") else [], "published")
                for p in publishers if isinstance(p, dict)]
    summary = row.get("network_summary")
    if isinstance(summary, dict) and isinstance(summary.get("mqtt"), dict):
        mapped = [str(d) for d in summary.get("mapped_devices") or []]
        return [(summary["mqtt"].get("client_id"), mapped, f"sent MQTT {summary['mqtt'].get('type', 'packet')}")]
    return []


def _client_allowed(client_id: str, devices: list[str], patterns: tuple[str, ...]) -> bool:
    """True when a pattern allows the client ID; ``{device}`` is replaced by each device name, taken literally."""
    for pattern in patterns:
        if "{device}" in pattern:
            if any(fnmatchcase(client_id, pattern.replace("{device}", glob.escape(d))) for d in devices):
                return True
        elif fnmatchcase(client_id, pattern):
            return True
    return False


def _mqtt_client(rule: dict, rows: list[dict]) -> list[dict]:
    """Findings for an mqtt_client rule."""
    out = []
    for r in _select(rows, rule["match"]):
        problems = []
        for client_id, devices, kind in _mqtt_identities(r):
            target = f"device {', '.join(devices)}" if devices else "no mapped device"
            if client_id is None:
                if rule["flag_unknown"]:
                    problems.append(f"an unknown client {kind} ({target}; its CONNECT is not in the capture)")
            elif not _client_allowed(str(client_id), devices, rule["allowed"]):
                problems.append(f"client '{client_id}' {kind} ({target})")
        if problems:
            out.append(_finding(rule, [r], f"{_describe(r)}: " + "; ".join(problems) +
                                f"; allowed: {', '.join(rule['allowed'])}"))
    return out


def _apply_one(rule: dict, rows: list[dict]) -> list[dict]:
    """Evaluate one validated rule over timeline rows."""
    out: list[dict] = []
    kind = rule["type"]
    if kind == "time_of_day":
        out = _time_of_day(rule, rows)
    elif kind == "mqtt_client":
        out = _mqtt_client(rule, rows)
    elif kind == "match":
        out = [_finding(rule, [r], f"Matched {_describe(r)}") for r in _select(rows, rule["match"])]
    elif kind == "absent_within":
        expected = _select(rows, rule["expect"])
        times = [r["timestamp"] for r in expected]
        window, direction = rule["window_seconds"], rule["direction"]
        for r in _select(rows, rule["trigger"]):
            lo = r["timestamp"] - (window if direction in ("before", "both") else 0.0)
            hi = r["timestamp"] + (window if direction in ("after", "both") else 0.0)
            near = [e for e in expected[bisect_left(times, lo):bisect_right(times, hi)] if e is not r]
            if not near:
                span = {"before": f"in the {window:g} s before", "after": f"in the {window:g} s after",
                        "both": f"within {window:g} s of"}[direction]
                out.append(_finding(rule, [r], f"No matching expected event {span} {_describe(r)}"))
    elif kind == "sequence":
        thens = _select(rows, rule["then"])
        times = [r["timestamp"] for r in thens]
        for r in _select(rows, rule["first"]):
            candidates = [t for t in thens[bisect_left(times, r["timestamp"]):bisect_right(times, r["timestamp"] + rule["within_seconds"])]
                          if t is not r]
            if candidates:
                t = candidates[0]
                out.append(_finding(rule, [r, t], f"{_describe(r)} followed by {_describe(t)} "
                                                  f"{t['timestamp'] - r['timestamp']:.3f} s later"))
    else:
        matched = _select(rows, rule["match"])
        start = 0
        for end in range(len(matched)):
            while matched[end]["timestamp"] - matched[start]["timestamp"] > rule["window_seconds"]:
                start += 1
            if end - start + 1 >= rule["count"]:
                group = matched[start:end + 1]
                out.append(_finding(rule, group, f"{len(group)} matching events within "
                                                 f"{group[-1]['timestamp'] - group[0]['timestamp']:.3f} s "
                                                 f"(threshold {rule['count']} in {rule['window_seconds']:g} s)"))
                start = end + 1
    if len(out) > MAX_FINDINGS_PER_RULE:
        kept = out[:MAX_FINDINGS_PER_RULE]
        kept[-1] = {**kept[-1], "detail": kept[-1]["detail"] +
                    f"; {len(out) - MAX_FINDINGS_PER_RULE} further finding(s) for this rule were not listed"}
        out = kept
    return out


def apply_rules(timeline: list[dict], rules: list[dict]) -> list[dict]:
    """Evaluate validated rules over timeline rows; return findings ordered by time then rule id."""
    rows = [r for r in timeline if isinstance(r, dict) and isinstance(r.get("timestamp"), (int, float))]
    findings = [f for rule in rules for f in _apply_one(rule, rows)]
    findings.sort(key=lambda f: (f["timestamp"], f["rule_id"]))
    return findings


def rules_summary(ruleset: dict) -> dict:
    """Describe the rules file applied to a report (source, hash and each rule's id/title/type/severity)."""
    return {"source": ruleset["source"], "sha256": ruleset["sha256"],
            "rules": [{k: r[k] for k in ("id", "title", "type", "severity", "description")} for r in ruleset["rules"]]}


RULES_LIMITATION = ("Rule findings come from the examiner-supplied rules file listed in the report; they flag patterns for "
                    "review and carry the time uncertainty of the rows they cite. A finding is not proof of an incident, "
                    "and no finding does not mean nothing happened.")
