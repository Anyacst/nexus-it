"""Self-contained HTML rendering of a NEXUS-IoT ``report.json``.

The output is one HTML document with inline CSS and an inline SVG timeline.
It loads no external resources and needs no JavaScript, so it can be opened
from disk, attached to a case file, or printed to PDF from a browser.

Every string taken from the report is treated as untrusted input and escaped
before it reaches the markup. The renderer only relies on fields that exist
today and reads them defensively with ``.get()``; unknown labels, events and
extra row fields are displayed generically.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from typing import Any, Iterable
from urllib.parse import urlencode

from . import __version__

MAX_SVG_MARKS = 2000
"""Upper bound on marks drawn in the SVG timeline; the table always lists every row."""

MAX_LANES = 30
"""Upper bound on SVG lanes; further sources are merged into one overflow lane."""

DEFAULT_TITLE = "NEXUS-IoT incident timeline report"

KNOWN_LABELS: dict[str, str] = {
    "Confirmed": "confirmed",
    "Single-source": "single",
    "Inferred": "inferred",
    "Unknown gap": "gap",
    "Network observation": "network",
}
"""Display label to CSS class suffix. Any other label uses the ``other`` class."""

LABEL_ORDER = list(KNOWN_LABELS)

_FALLBACK_FILL: dict[str, str] = {
    "confirmed": "#16734b",
    "single": "#8a6100",
    "inferred": "#6941a5",
    "gap": "#b03a2e",
    "network": "#1f6fb2",
    "other": "#5b6773",
}
"""SVG presentation-attribute colours used when the stylesheet is unavailable."""

_MARK_PRIORITY: dict[str, int] = {
    "gap": 0,
    "inferred": 1,
    "confirmed": 2,
    "other": 3,
    "network": 4,
    "single": 5,
}
"""Lower value is kept first when the SVG mark cap is reached."""

_CALIBRATED_BASES = {"gateway-clock-assumed", "device-clock-calibrated-to-gateway"}

_ROW_CORE_FIELDS = {
    "timestamp",
    "time_range",
    "event",
    "device_or_source",
    "label",
    "supporting_evidence",
    "confidence_or_uncertainty",
}
"""Row fields shown in the main table columns; everything else goes in the raw-field list."""

REPORT_CSS = """
:root{color-scheme:light dark;--bg:#f5f7fa;--fg:#18212b;--muted:#536273;--card:#fff;--line:#d9dee5;--head:#eff3f7;--accent:#174c76;--accent-fg:#fff;--grid:#c9d1db;
--c-confirmed:#16734b;--c-single:#8a6100;--c-inferred:#6941a5;--c-gap:#b03a2e;--c-network:#1f6fb2;--c-other:#5b6773}
@media (prefers-color-scheme:dark){:root{--bg:#11161c;--fg:#e3e8ee;--muted:#9aa7b5;--card:#1a2129;--line:#2e3843;--head:#222b35;--accent:#4f93c9;--accent-fg:#0b1218;--grid:#3a4552;
--c-confirmed:#4fc58e;--c-single:#e0b43f;--c-inferred:#b18cf0;--c-gap:#f07a6c;--c-network:#62aef0;--c-other:#9aa7b5}}
*{box-sizing:border-box}
body{font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;max-width:1240px;margin:1.5rem auto;padding:0 1rem;color:var(--fg);background:var(--bg)}
h1{margin:0 0 .2rem;font-size:1.6rem}h2{font-size:1.2rem;margin:.2rem 0 .7rem}
a{color:var(--accent)}
.muted{color:var(--muted)}.small{font-size:.85rem}
.card{background:var(--card);padding:1rem 1.3rem;border-radius:10px;margin:1rem 0;box-shadow:0 2px 12px #16263812;border:1px solid var(--line)}
.scroll{overflow:auto}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--head);position:sticky;top:0}
code,.hash{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.82rem;overflow-wrap:anywhere}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem;margin:.6rem 0 0}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;overflow-wrap:anywhere}
.chips{display:flex;flex-wrap:wrap;gap:.5rem;margin:.3rem 0}
.chip{display:inline-flex;align-items:center;gap:.4rem;border:1px solid var(--line);border-radius:999px;padding:.2rem .7rem;text-decoration:none;color:var(--fg)}
.chip b{font-variant-numeric:tabular-nums}
.sw{display:inline-block;width:.8rem;height:.8rem;border-radius:3px;background:var(--c-other)}
.sw.bar{width:1.4rem;height:.6rem;opacity:.6}
.label{font-weight:700;white-space:nowrap}
.lbl-confirmed{color:var(--c-confirmed)}.lbl-single{color:var(--c-single)}.lbl-inferred{color:var(--c-inferred)}
.lbl-gap{color:var(--c-gap)}.lbl-network{color:var(--c-network)}.lbl-other{color:var(--c-other)}
.sw.lbl-confirmed{background:var(--c-confirmed)}.sw.lbl-single{background:var(--c-single)}.sw.lbl-inferred{background:var(--c-inferred)}
.sw.lbl-gap{background:var(--c-gap)}.sw.lbl-network{background:var(--c-network)}.sw.lbl-other{background:var(--c-other)}
svg.tl{width:100%;height:auto;display:block}
svg.tl text{fill:var(--fg);font:11px system-ui,sans-serif}
svg.tl .lane-bg{fill:var(--head)}svg.tl .grid{stroke:var(--grid);stroke-width:1}
svg.tl .mk.lbl-confirmed{fill:var(--c-confirmed);stroke:var(--c-confirmed)}svg.tl .mk.lbl-single{fill:var(--c-single);stroke:var(--c-single)}
svg.tl .mk.lbl-inferred{fill:var(--c-inferred);stroke:var(--c-inferred)}svg.tl .mk.lbl-gap{fill:var(--c-gap);stroke:var(--c-gap)}
svg.tl .mk.lbl-network{fill:var(--c-network);stroke:var(--c-network)}svg.tl .mk.lbl-other{fill:var(--c-other);stroke:var(--c-other)}
svg.tl rect.mk{fill-opacity:.45;stroke-width:1}svg.tl circle.mk{fill-opacity:.85;stroke-width:0}
.legend{display:flex;flex-wrap:wrap;gap:.4rem 1.1rem;margin:.4rem 0 .8rem;font-size:.85rem;align-items:center}
.legend span{display:inline-flex;align-items:center;gap:.35rem}
.note{border-left:3px solid var(--c-single);padding:.3rem .7rem;margin:.5rem 0;background:var(--head)}
ul.issues{margin:.2rem 0;padding-left:1.2rem}ul.issues li{padding:.15rem 0}
ul.ev{margin:.3rem 0;padding-left:1.1rem}
details summary{cursor:pointer}
details dl.meta{font-size:.8rem}
tr:target td{background:var(--head)}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
td.time{white-space:nowrap;font-variant-numeric:tabular-nums}
form.filters{display:flex;flex-wrap:wrap;gap:.6rem;align-items:end}
form.filters label{display:flex;flex-direction:column;font-size:.85rem;gap:.2rem}
input,select{padding:.55rem;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);font:inherit}
input.wide{width:min(700px,90%)}
button{padding:.6rem 1.2rem;background:var(--accent);color:var(--accent-fg);border:0;border-radius:6px;font:inherit;cursor:pointer}
.no-print{}
@media print{
:root{--bg:#fff;--fg:#000;--muted:#444;--card:#fff;--line:#bbb;--head:#eee;--grid:#ccc;
--c-confirmed:#16734b;--c-single:#8a6100;--c-inferred:#6941a5;--c-gap:#b03a2e;--c-network:#1f6fb2;--c-other:#5b6773}
html{font-size:9pt}
body{max-width:none;margin:0;padding:0;font-size:1rem}
.card{box-shadow:none;border:0;border-top:1px solid #999;border-radius:0;padding:.5rem 0;margin:.5rem 0}
.no-print{display:none!important}
th{position:static}
tr,svg.tl,.legend{break-inside:avoid}
h2{break-after:avoid}
a{color:inherit;text-decoration:none}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
.scroll{overflow:visible}
details.raw{display:none}
details.evidence>summary{list-style:none}
#timeline table{table-layout:fixed}
#timeline td,#timeline th{overflow-wrap:anywhere;white-space:normal}
#timeline th:nth-child(1){width:4%}#timeline th:nth-child(2){width:19%}#timeline th:nth-child(3){width:16%}
#timeline th:nth-child(4){width:13%}#timeline th:nth-child(5){width:10%}#timeline th:nth-child(6){width:38%}
}
""".strip()
"""Static stylesheet. It contains no report data, so a CSP hash of it stays valid."""


def css_sha256() -> str:
    """Return the CSP source expression (``'sha256-...'``) that allows ``REPORT_CSS`` inline."""
    digest = hashlib.sha256(REPORT_CSS.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


@dataclass
class ReportView:
    """Interactive (web) rendering options: active filters and link targets.

    Filter values must already be validated by the caller; they are still
    escaped on output. ``base_path`` is the URL path the filter form submits to.
    """

    device: str = ""
    label: str = ""
    query: str = ""
    base_path: str = "/"
    links: list[tuple[str, str]] = field(default_factory=list)

    def is_filtered(self) -> bool:
        """Return True when any filter is active."""
        return bool(self.device or self.label or self.query)

    def href(self, **changes: str) -> str:
        """Return an HTML-attribute-escaped filter URL with the current filters updated by ``changes``."""
        params = {"device": self.device, "label": self.label, "q": self.query}
        params.update(changes)
        kept = {k: v for k, v in params.items() if v}
        query = urlencode(kept)
        return escape(self.base_path + ("?" + query if query else ""), quote=True)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _e(value: Any) -> str:
    """Escape any value for HTML text or a quoted attribute."""
    if value is None:
        return ""
    return escape(str(value), quote=True)


def _num(value: Any) -> float | None:
    """Return ``value`` as a finite float, or None for bools, non-numbers, NaN and infinities."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _range(value: Any) -> tuple[float, float] | None:
    """Return a finite, ordered ``(start, end)`` pair from a ``time_range`` value, if usable."""
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return None
    start, end = _num(value[0]), _num(value[1])
    if start is None or end is None:
        return None
    return (start, end) if start <= end else (end, start)


def _iso(value: Any) -> str:
    """Format a Unix timestamp as UTC ISO-8601, or describe why it cannot be formatted."""
    number = _num(value)
    if number is None:
        return "unknown time" if value is None else f"invalid time ({value!r})"
    try:
        text = datetime.fromtimestamp(number, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return f"{number:.6f} (out of datetime range)"
    return text.replace("+00:00", "Z")


def _fmt(value: Any, spec: str, suffix: str = "", none_text: str = "unknown") -> str:
    """Format a number with ``spec`` or return ``none_text`` when it is missing or non-finite."""
    number = _num(value)
    if number is None:
        return none_text if value is None else str(value)
    return format(number, spec) + suffix


def _label_class(label: Any) -> str:
    """Map a label to its CSS class suffix; unknown labels map to ``other``."""
    return KNOWN_LABELS.get(str(label), "other")


def _as_list(value: Any) -> list:
    """Return ``value`` as a list (a scalar becomes a one-item list, None becomes empty)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _as_dict(value: Any) -> dict:
    """Return ``value`` if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def _rows(report: dict) -> list[dict]:
    """Return the timeline rows that are dicts, ignoring malformed entries."""
    return [row for row in _as_list(report.get("timeline")) if isinstance(row, dict)]


def row_sources(row: dict) -> list[str]:
    """Split a row's ``device_or_source`` into individual source names."""
    raw = row.get("device_or_source")
    if raw is None or str(raw).strip() == "":
        return ["(unspecified source)"]
    parts = [part.strip() for part in str(raw).split(",")]
    return [part for part in parts if part] or ["(unspecified source)"]


def ordered_labels(labels: Iterable[str]) -> list[str]:
    """Order labels with the known ones first (in canonical order) then the rest alphabetically."""
    unique = set(labels)
    known = [label for label in LABEL_ORDER if label in unique]
    return known + sorted(unique - set(known))


def time_text(row: dict) -> str:
    """Return the plain-text timestamp or range for a row, including a non-calibrated basis tag."""
    span = _range(row.get("time_range"))
    basis = row.get("time_basis")
    if span is None:
        text = _iso(row.get("timestamp"))
        if _num(row.get("timestamp")) is not None:
            text += f" (uncalibrated; {basis or 'time basis unknown'})"
        return text
    start, end = span
    text = _iso(start) if start == end else f"{_iso(start)} – {_iso(end)}"
    if basis not in _CALIBRATED_BASES:
        text += f" [{basis or 'time basis unknown'}]"
    return text


def row_matches(row: dict, view: ReportView) -> bool:
    """Return True when ``row`` passes the device, label and free-text filters of ``view``."""
    if view.device and view.device not in row_sources(row):
        return False
    if view.label and str(row.get("label", "")) != view.label:
        return False
    if view.query:
        needle = view.query.casefold()
        haystack = [
            row.get("event"),
            row.get("event_id"),
            row.get("device_or_source"),
            row.get("label"),
            row.get("confidence_or_uncertainty"),
            row.get("limitations"),
            row.get("time_basis"),
            time_text(row),
            *_as_list(row.get("supporting_evidence")),
        ]
        if not any(needle in str(item).casefold() for item in haystack if item is not None):
            return False
    return True


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _header(report: dict, title: str, case_info: dict | None, generated: str) -> str:
    """Render the case header card."""
    meta: list[tuple[str, Any]] = []
    for key, value in (case_info or {}).items():
        if value is not None and str(value).strip():
            meta.append((str(key), value))
    meta += [
        ("Report generated (HTML)", generated),
        ("Analysis created", report.get("created_at", "unknown")),
        ("Tool version", f"NEXUS-IoT {__version__}"),
        ("Report schema", report.get("schema_version", "unknown")),
        ("Evidence folder", report.get("evidence_directory", "unknown")),
        ("Evidence records parsed", report.get("evidence_record_count", "unknown")),
        ("Processing time", _fmt(report.get("processing_seconds"), ".3f", " s")),
    ]
    items = "".join(f"<dt>{_e(key)}</dt><dd>{_e(value)}</dd>" for key, value in meta)
    return (
        f"<header class=card><h1>{_e(title)}</h1>"
        "<div class='muted small'>Local evidence reconstruction · source files are read only · "
        "labels describe corroboration, not proof of authenticity</div>"
        f"<dl class=meta>{items}</dl></header>"
    )


def _summary(rows: list[dict], report: dict, view: ReportView | None, shown: int) -> str:
    """Render total counts and the per-label counts (as filter links in the web view)."""
    counts: dict[str, int] = {}
    for row in rows:
        label = str(row.get("label", "(no label)"))
        counts[label] = counts.get(label, 0) + 1
    chips = []
    for label in ordered_labels(counts):
        cls = _label_class(label)
        inner = f"<span class='sw lbl-{cls}'></span>{_e(label)} <b>{counts[label]}</b>"
        if view is not None:
            chips.append(f"<a class=chip href='{view.href(label=label)}'>{inner}</a>")
        else:
            chips.append(f"<span class=chip>{inner}</span>")
    sources = {source for row in rows for source in row_sources(row)}
    manifest = _as_list(report.get("evidence_manifest"))
    issues = _as_list(report.get("validation_issues"))
    totals = (
        f"<p>{len(rows)} timeline row(s) · {len(sources)} device/source lane(s) · "
        f"{len(manifest)} evidence file(s) · {len(issues)} validation finding(s)</p>"
    )
    filtered = ""
    if view is not None and view.is_filtered():
        filtered = f"<p class=note>Filters active: showing {shown} of {len(rows)} row(s).</p>"
    body = "".join(chips) if chips else "<span class=muted>No timeline rows.</span>"
    return f"<section class=card id=summary><h2>Summary</h2>{totals}<div class=chips>{body}</div>{filtered}</section>"


def _manifest(report: dict) -> str:
    """Render the evidence manifest table (file, size, SHA-256, snapshot stability)."""
    entries = [x for x in _as_list(report.get("evidence_manifest")) if isinstance(x, dict)]
    if not entries:
        return "<section class=card id=manifest><h2>Evidence manifest</h2><p>No evidence files were recorded.</p></section>"
    rows = []
    for entry in entries:
        name = entry.get("relative_path") or entry.get("filename") or "(unnamed)"
        stable = entry.get("snapshot_stable")
        stable_text = "yes" if stable is True else "NO" if stable is False else "unknown"
        rows.append(
            f"<tr><td><code>{_e(name)}</code></td><td class=num>{_e(_fmt(entry.get('bytes'), ',.0f'))}</td>"
            f"<td><span class=hash>{_e(entry.get('sha256', 'not recorded'))}</span></td>"
            f"<td>{_e(stable_text)}</td><td class=small>{_e(entry.get('collection_time', ''))}</td></tr>"
        )
    return (
        "<section class=card id=manifest><h2>Evidence manifest</h2><div class=scroll><table>"
        "<thead><tr><th>File</th><th>Bytes</th><th>SHA-256</th><th>Snapshot stable</th><th>Collected (UTC)</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></section>"
    )


def _validation(report: dict) -> str:
    """Render validation findings as a list."""
    issues = _as_list(report.get("validation_issues"))
    if not issues:
        body = "<p>No validation findings.</p>"
    else:
        body = "<ul class=issues>" + "".join(f"<li>{_e(issue)}</li>" for issue in issues) + "</ul>"
    return f"<section class=card id=validation><h2>Validation findings</h2>{body}</section>"


def _clocks(report: dict) -> str:
    """Render the clock-estimate table."""
    estimates = _as_dict(report.get("clock_estimates"))
    if not estimates:
        return "<section class=card id=clocks><h2>Clock estimates</h2><p>No clock estimates (no shared gateway anchors).</p></section>"
    rows = []
    for source, raw in estimates.items():
        est = _as_dict(raw)
        unc = est.get("uncertainty_seconds")
        unc_text = "unknown" if _num(unc) is None else f"±{_num(unc):.3f} s"
        segments = _as_list(est.get("segments"))
        applied = est.get("applied")
        rows.append(
            f"<tr><td><code>{_e(source)}</code></td><td class=num>{_e(_fmt(est.get('offset_seconds'), '+.3f', ' s'))}</td>"
            f"<td class=num>{_e(_fmt(est.get('drift_ppm'), '+.3f', ' ppm'))}</td><td class=num>{_e(unc_text)}</td>"
            f"<td class=num>{_e(est.get('anchor_count', 'unknown'))}</td>"
            f"<td class=num>{_e(_fmt(est.get('residual_range_seconds'), '.3f', ' s'))}</td>"
            f"<td>{_e('yes' if applied is True else 'no' if applied is False else 'unknown')}</td>"
            f"<td class=num>{len(segments) if segments else '–'}</td></tr>"
        )
    return (
        "<section class=card id=clocks><h2>Clock estimates</h2><div class=scroll><table>"
        "<thead><tr><th>Source</th><th>Offset</th><th>Drift</th><th>Uncertainty</th><th>Anchors</th>"
        "<th>Residual range</th><th>Applied</th><th>Segments</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        "<p class='muted small'>Offsets describe observed anchors relative to the gateway clock; they do not prove gateway time is correct.</p></section>"
    )


def _limitations(report: dict) -> str:
    """Render the report's stated limitations, if any."""
    items = _as_list(report.get("limitations"))
    if not items:
        return ""
    body = "".join(f"<li>{_e(item)}</li>" for item in items)
    return f"<section class=card id=limitations><h2>Limitations</h2><ul class=issues>{body}</ul></section>"


# ---------------------------------------------------------------------------
# SVG timeline
# ---------------------------------------------------------------------------

@dataclass
class _Mark:
    """One drawable mark in the SVG timeline."""

    lane: int
    start: float
    end: float
    cls: str
    is_bar: bool
    row_index: int
    tooltip: str
    merged: int = 1


def _axis_label(t: float, span: float) -> str:
    """Format an axis tick label with precision suited to the visible span."""
    try:
        moment = datetime.fromtimestamp(t, timezone.utc)
    except (ValueError, OverflowError, OSError):
        return f"{t:.0f}"
    if span < 10:
        return moment.strftime("%H:%M:%S.") + f"{moment.microsecond // 1000:03d}"
    if span < 2 * 86400:
        return moment.strftime("%H:%M:%S")
    return moment.strftime("%Y-%m-%d %H:%M")


def _svg_timeline(rows: list[tuple[int, dict]], view: ReportView | None) -> str:
    """Render the visual timeline: one lane per source, x = UTC time, marks coloured by label."""
    usable: list[tuple[int, dict, float, float, bool]] = []
    undrawn = 0
    for index, row in rows:
        span = _range(row.get("time_range"))
        ts = _num(row.get("timestamp"))
        if span is not None:
            usable.append((index, row, span[0], span[1], True))
        elif ts is not None:
            usable.append((index, row, ts, ts, False))
        else:
            undrawn += 1

    header = "<section class=card id=visual><h2>Visual timeline</h2>"
    if not usable:
        msg = "No timeline rows with a usable timestamp to draw." if rows else "The timeline is empty."
        return f"{header}<p>{msg}</p></section>"

    t0 = min(item[2] for item in usable)
    t1 = max(item[3] for item in usable)
    if t1 - t0 <= 0:
        t0 -= 1.0
        t1 += 1.0
    span = t1 - t0

    # Lanes ordered by first appearance in time; overflow lanes merge into one.
    first_seen: dict[str, float] = {}
    for _, row, start, _, _ in usable:
        for source in row_sources(row):
            if source not in first_seen or start < first_seen[source]:
                first_seen[source] = start
    lane_names = sorted(first_seen, key=lambda name: (first_seen[name], name))
    overflow_count = 0
    if len(lane_names) > MAX_LANES:
        overflow_count = len(lane_names) - (MAX_LANES - 1)
        lane_names = lane_names[: MAX_LANES - 1]
    lane_index = {name: i for i, name in enumerate(lane_names)}
    overflow_lane = len(lane_names) if overflow_count else None

    gutter, plot_w, right_pad = 200.0, 880.0, 20.0
    lane_h, top, axis_h = 26.0, 8.0, 34.0
    lane_total = len(lane_names) + (1 if overflow_count else 0)
    width = gutter + plot_w + right_pad
    height = top + lane_total * lane_h + axis_h

    def x_of(t: float) -> float:
        return gutter + (t - t0) / span * plot_w

    # Build marks, merging marks that would land on the same pixel in the same lane.
    merged: dict[tuple, _Mark] = {}
    for index, row, start, end, has_range in usable:
        cls = _label_class(row.get("label"))
        x0, x1 = x_of(start), x_of(end)
        is_bar = cls == "gap" or (has_range and x1 - x0 >= 5.0)
        tooltip = f"{time_text(row)}\n{row.get('event', '')}\n{row.get('label', '')} · {row.get('device_or_source', '')}"
        lanes = set()
        for source in row_sources(row):
            lane = lane_index.get(source, overflow_lane)
            if lane is not None:
                lanes.add(lane)
        for lane in sorted(lanes):
            key = (lane, cls, is_bar, round(x0), round(x1) if is_bar else 0)
            if key in merged:
                merged[key].merged += 1
            else:
                merged[key] = _Mark(lane, x0, x1, cls, is_bar, index, tooltip)
    marks = list(merged.values())
    total_marks = len(marks)
    capped = total_marks > MAX_SVG_MARKS
    if capped:
        marks.sort(key=lambda m: (_MARK_PRIORITY.get(m.cls, 3), m.start))
        marks = marks[:MAX_SVG_MARKS]
    marks.sort(key=lambda m: (not m.is_bar, m.start))  # bars underneath dots

    parts = [
        f"<svg class=tl xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width:.0f} {height:.0f}' "
        f"role='img' aria-label='Visual timeline: {len(lane_names)} lane(s), x axis is UTC time'>"
    ]
    lane_labels = list(lane_names) + ([f"({overflow_count} other sources)"] if overflow_count else [])
    for i, name in enumerate(lane_labels):
        y = top + i * lane_h
        if i % 2 == 0:
            parts.append(f"<rect class=lane-bg x='0' y='{y:.1f}' width='{width:.0f}' height='{lane_h:.0f}' fill='#eff3f7' fill-opacity='.5'/>")
        short = name if len(name) <= 30 else name[:29] + "…"
        label = f"<text x='6' y='{y + lane_h / 2 + 4:.1f}'><title>{_e(name)}</title>{_e(short)}</text>"
        if view is not None and i < len(lane_names):
            label = f"<a href='{view.href(device=name)}'>{label}</a>"
        parts.append(label)
    axis_y = top + lane_total * lane_h
    ticks = 6
    for k in range(ticks + 1):
        t = t0 + span * k / ticks
        x = x_of(t)
        anchor = "start" if k == 0 else "end" if k == ticks else "middle"
        parts.append(f"<line class=grid x1='{x:.1f}' x2='{x:.1f}' y1='{top:.1f}' y2='{axis_y + 4:.1f}' stroke='#c9d1db'/>")
        parts.append(f"<text x='{x:.1f}' y='{axis_y + 16:.1f}' text-anchor='{anchor}'>{_e(_axis_label(t, span))}</text>")
    parts.append(
        f"<text x='{gutter:.0f}' y='{axis_y + 30:.1f}' class=muted>UTC {_e(_iso(t0))} to {_e(_iso(t1))}</text>"
    )
    for mark in marks:
        y = top + mark.lane * lane_h
        fill = _FALLBACK_FILL.get(mark.cls, _FALLBACK_FILL["other"])
        extra = f"\n({mark.merged} rows drawn at this position)" if mark.merged > 1 else ""
        title = f"<title>{_e(mark.tooltip + extra)}</title>"
        if mark.is_bar:
            pad = 3.0 if mark.cls == "gap" else 8.0
            w = max(mark.end - mark.start, 4.0 if mark.cls == "gap" else 2.0)
            shape = (
                f"<rect class='mk lbl-{mark.cls}' x='{mark.start:.1f}' y='{y + pad:.1f}' width='{w:.1f}' "
                f"height='{lane_h - 2 * pad:.1f}' rx='2' fill='{fill}' stroke='{fill}'>{title}</rect>"
            )
        else:
            shape = (
                f"<circle class='mk lbl-{mark.cls}' cx='{mark.start:.1f}' cy='{y + lane_h / 2:.1f}' r='4' fill='{fill}'>{title}</circle>"
            )
        parts.append(f"<a href='#row-{mark.row_index}'>{shape}</a>")
    parts.append("</svg>")

    labels_present = ordered_labels(str(row.get("label", "(no label)")) for _, row, *_ in usable)
    legend = ["<div class=legend>"]
    for label in labels_present:
        legend.append(f"<span><i class='sw lbl-{_label_class(label)}'></i>{_e(label)}</span>")
    legend.append("<span class=muted>● instant · ▬ time range or Unknown gap · corroborated rows appear in each source's lane · click a mark to jump to its row</span>")
    legend.append("</div>")

    notes = []
    if undrawn:
        notes.append(f"{undrawn} row(s) have no usable timestamp and are listed only in the table.")
    if capped:
        notes.append(
            f"{len(usable)} drawable rows produced {total_marks} distinct marks; only {MAX_SVG_MARKS} are drawn "
            "(gaps, inferred and confirmed rows first). The table below lists every row."
        )
    elif total_marks < sum(len(row_sources(row)) for _, row, *_ in usable):
        notes.append("Marks that fall on the same pixel in the same lane are merged; hover a mark for its row count.")
    if overflow_count:
        notes.append(f"Only {MAX_LANES - 1} lanes are drawn individually; {overflow_count} further sources share the last lane.")
    note_html = "".join(f"<p class='note small'>{_e(note)}</p>" for note in notes)
    return f"{header}{''.join(legend)}<div class=scroll>{''.join(parts)}</div>{note_html}</section>"


# ---------------------------------------------------------------------------
# Timeline table
# ---------------------------------------------------------------------------

def _raw_value(value: Any) -> str:
    """Render an extra row field value as compact text (JSON for containers)."""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def _row_html(index: int, row: dict, interactive: bool) -> str:
    """Render one timeline table row with an expandable evidence/raw-field block."""
    label = str(row.get("label", "(no label)"))
    cls = _label_class(label)
    evidence = [str(item) for item in _as_list(row.get("supporting_evidence"))]
    preview = evidence[0] if evidence else "no supporting evidence listed"
    if len(preview) > 120:
        preview = preview[:119] + "…"
    items = "".join(f"<li>{_e(item)}</li>" for item in evidence) or "<li class=muted>none listed</li>"
    extras = []
    for key in sorted(k for k in row if k not in _ROW_CORE_FIELDS):
        value = row[key]
        if isinstance(value, dict):
            for sub_key in sorted(value):
                extras.append((f"{key}.{sub_key}", _raw_value(value[sub_key])))
        else:
            extras.append((str(key), _raw_value(value)))
    raw = "".join(f"<dt>{_e(k)}</dt><dd><code>{_e(v)}</code></dd>" for k, v in extras)
    # Static reports show evidence expanded (readable/printable) with raw fields folded;
    # the web view folds each row and shows raw fields once the row is expanded.
    open_attr = "" if interactive else " open"
    raw_open = " open" if interactive else ""
    if interactive:
        summary = f"{len(evidence)} evidence item(s): {_e(preview)}"
    else:
        summary = f"Supporting evidence ({len(evidence)})"
    uncertainty = row.get("confidence_or_uncertainty")
    return (
        f"<tr id='row-{index}'><td class=num>{index + 1}</td><td class=time>{_e(time_text(row))}</td>"
        f"<td>{_e(row.get('event', '(no event)'))}</td><td>{_e(row.get('device_or_source', ''))}</td>"
        f"<td class='label lbl-{cls}'>{_e(label)}</td>"
        f"<td><details class=evidence{open_attr}><summary>{summary}</summary><ul class=ev>{items}</ul>"
        f"<details class=raw{raw_open}><summary>Raw row fields</summary><dl class=meta>{raw}</dl></details></details>"
        f"<div class='muted small'>{_e(uncertainty) if uncertainty else 'Uncertainty not stated.'}</div></td></tr>"
    )


def _timeline_table(rows: list[tuple[int, dict]], total: int, interactive: bool) -> str:
    """Render the full timeline table for the given (index, row) pairs."""
    head = "<section class=card id=timeline><h2>Reconstructed timeline</h2>"
    if not rows:
        msg = "No rows match the current filters." if total else "The timeline is empty."
        return f"{head}<p>{msg}</p></section>"
    hint = (
        "<p class='muted small no-print'>Click a row's evidence summary to expand the raw supporting evidence and fields.</p>"
        if interactive else ""
    )
    body = "".join(_row_html(index, row, interactive) for index, row in rows)
    return (
        f"{head}{hint}<div class=scroll><table><thead><tr><th>#</th><th>UTC timestamp / range</th><th>Event</th>"
        "<th>Device / source</th><th>Label</th><th>Supporting evidence and uncertainty</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></section>"
    )


def _filter_form(all_rows: list[dict], view: ReportView) -> str:
    """Render the GET filter form (device, label, free text) for the web view."""
    sources = sorted({source for row in all_rows for source in row_sources(row)})
    labels = ordered_labels(str(row.get("label", "(no label)")) for row in all_rows)

    def options(values: list[str], selected: str, empty: str) -> str:
        opts = [f"<option value=''>{_e(empty)}</option>"]
        if selected and selected not in values:
            values = values + [selected]
        for value in values:
            sel = " selected" if value == selected else ""
            opts.append(f"<option value='{_e(value)}'{sel}>{_e(value)}</option>")
        return "".join(opts)

    clear = f" <a href='{_e(view.base_path)}'>Clear filters</a>" if view.is_filtered() else ""
    links = " · ".join(f"<a href='{_e(href)}'>{_e(text)}</a>" for text, href in view.links)
    links_html = f"<p class=small>Download: {links}</p>" if links else ""
    return (
        "<section class='card no-print' id=filters><h2>Filter timeline</h2>"
        f"<form class=filters method=get action='{_e(view.base_path)}'>"
        f"<label>Device / source<select name=device>{options(sources, view.device, 'All sources')}</select></label>"
        f"<label>Label<select name=label>{options(labels, view.label, 'All labels')}</select></label>"
        f"<label>Text search<input name=q maxlength=200 value='{_e(view.query)}' placeholder='event, ID, evidence…'></label>"
        f"<button>Apply</button>{clear}</form>{links_html}</section>"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_document(title: str, body_html: str, *, nonce: str | None = None) -> str:
    """Wrap trusted ``body_html`` in a complete HTML document with the report stylesheet.

    ``nonce`` (if given) is added to the ``<style>`` element for a CSP ``style-src 'nonce-...'``.
    """
    nonce_attr = f" nonce='{_e(nonce)}'" if nonce else ""
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<meta name=color-scheme content='light dark'>"
        f"<title>{_e(title)}</title><style{nonce_attr}>{REPORT_CSS}</style></head>"
        f"<body>{body_html}</body></html>"
    )


def render_report_body(
    report: dict,
    *,
    title: str | None = None,
    case_info: dict | None = None,
    view: ReportView | None = None,
    generated: str | None = None,
) -> str:
    """Render the report sections (no ``<html>`` wrapper).

    With ``view`` set, the output is the interactive web variant: a filter form,
    filtered SVG/table, and collapsed evidence blocks. Without it, every row is
    shown with its evidence expanded for reading and printing.
    """
    report = report if isinstance(report, dict) else {}
    all_rows = _rows(report)
    indexed = list(enumerate(all_rows))
    if view is not None:
        indexed = [(i, row) for i, row in indexed if row_matches(row, view)]
    generated = generated or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    sections = [
        _header(report, title or DEFAULT_TITLE, case_info, generated),
        _summary(all_rows, report, view, len(indexed)),
    ]
    if view is not None:
        sections.append(_filter_form(all_rows, view))
    sections += [
        _svg_timeline(indexed, view),
        _manifest(report),
        _validation(report),
        _clocks(report),
        _timeline_table(indexed, len(all_rows), view is not None),
        _limitations(report),
        f"<footer class='muted small'>Generated by NEXUS-IoT {_e(__version__)} at {_e(generated)}. "
        "This report reflects the supplied evidence only.</footer>",
    ]
    return "".join(sections)


def render_report(
    report: dict,
    *,
    title: str | None = None,
    case_info: dict | None = None,
    nonce: str | None = None,
    view: ReportView | None = None,
) -> str:
    """Render ``report`` (a parsed ``report.json``) as one self-contained HTML document.

    ``case_info`` maps display names (e.g. ``"Case number"``, ``"Examiner"``) to
    values shown in the header. ``nonce`` and ``view`` are used by the local web
    interface; the default output needs neither and contains no script.
    """
    body = render_report_body(report, title=title, case_info=case_info, view=view)
    return render_document(title or DEFAULT_TITLE, body, nonce=nonce)


def case_info_from(case_number: str | None, examiner: str | None) -> dict[str, str]:
    """Build a ``case_info`` mapping from optional CLI values, omitting empty ones."""
    info: dict[str, str] = {}
    if case_number:
        info["Case number"] = case_number
    if examiner:
        info["Examiner"] = examiner
    return info


_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(stem: str) -> str:
    """Return ``stem`` reduced to a conservative filename-safe token."""
    return _SLUG.sub("-", stem).strip("-.") or "report"
