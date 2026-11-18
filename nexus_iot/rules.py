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

Findings are leads for an examiner to review. They inherit the time uncertainty
of the rows they cite and are never proof of what happened.
"""
from __future__ import annotations

import hashlib
import json
import math
from bisect import bisect_left, bisect_right
from pathlib import Path

RULE_TYPES = ("match", "absent_within", "sequence", "count_within")
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
              "sequence": ("first", "then", "within_seconds"), "count_within": ("match", "count", "window_seconds")}[kind]
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


def _apply_one(rule: dict, rows: list[dict]) -> list[dict]:
    """Evaluate one validated rule over timeline rows."""
    out: list[dict] = []
    kind = rule["type"]
    if kind == "match":
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
