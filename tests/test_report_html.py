"""Tests for the self-contained HTML report renderer and its CLI entry points."""
from __future__ import annotations

import contextlib
import io
import json
import math
import re
import tempfile
import unittest
from pathlib import Path

from nexus_iot.__main__ import main
from nexus_iot.pipeline import analyze
from nexus_iot.report_html import MAX_SVG_MARKS, ReportView, css_sha256, render_report, REPORT_CSS

ROOT = Path(__file__).resolve().parents[1]
XSS = "<script>alert(\"x\")</script>'"


def make_row(ts, label="Single-source", device="sensor-A", event="heartbeat", **extra) -> dict:
    """Build a timeline row shaped like today's pipeline output."""
    row = {
        "timestamp": ts,
        "time_range": [ts - 0.05, ts + 0.05] if isinstance(ts, (int, float)) else None,
        "time_basis": "gateway-clock-assumed",
        "event": event,
        "device_or_source": device,
        "event_id": f"{device}-{ts}",
        "label": label,
        "supporting_evidence": [f"{device}.jsonl record 1 ({event})"],
        "independent_source_count": 1,
        "uncertainty_seconds": 0.05,
        "confidence_or_uncertainty": "1 source",
        "limitations": "none",
    }
    row.update(extra)
    return row


def sample_report() -> dict:
    """A hand-built report covering every label, a new event type and hostile strings."""
    timeline = [
        make_row(1000.0, "Confirmed", "gateway, sensor-A", "boot"),
        make_row(1001.0, "Single-source", "sensor-B", "heartbeat"),
        make_row(1002.0, "Inferred", "sensor-A", "Possible missing periodic 'heartbeat' event"),
        make_row(1003.0, "Unknown gap", "sensor-B", "Unknown missing event(s), 2 sequence value(s)",
                 time_range=[1002.5, 1004.0]),
        make_row(1004.0, "Network observation", "capture.pcap", "mqtt_connect",
                 network_summary={"protocol": "tcp", "destination_port": 1883, "client_id": XSS}),
        make_row(1005.0, "Brand new label", "sensor-C", "mqtt_subscribe"),
        make_row(1006.0, "Single-source", XSS, XSS, supporting_evidence=[XSS]),
    ]
    return {
        "schema_version": "1.0.0",
        "created_at": "2026-11-18T00:00:00+00:00",
        "evidence_directory": "/cases/<b>evil</b>",
        "evidence_record_count": 7,
        "processing_seconds": 0.01,
        "evidence_manifest": [
            {"filename": "sensor-A.jsonl", "relative_path": "sensor-A.jsonl", "sha256": "a" * 64, "bytes": 10, "snapshot_stable": True},
            {"filename": XSS, "relative_path": XSS + ".jsonl", "sha256": "b" * 64, "bytes": 20, "snapshot_stable": False},
        ],
        "clock_estimates": {
            "sensor-A.jsonl": {"offset_seconds": 1.5, "drift_ppm": 2.0, "uncertainty_seconds": None, "anchor_count": 3, "applied": True},
            XSS: {"offset_seconds": float("nan"), "drift_ppm": None},
        },
        "validation_issues": [XSS + " conflicting claims"],
        "timeline": timeline,
        "limitations": ["Hash records bytes seen during this run."],
    }


def svg_part(html: str) -> str:
    """Return the inline SVG markup from a rendered report."""
    match = re.search(r"<svg.*?</svg>", html, re.S)
    return match.group(0) if match else ""


class RenderReportTests(unittest.TestCase):
    def test_sections_labels_lanes_and_hashes(self):
        report = sample_report()
        html = render_report(report, title="Case <X>", case_info={"Case number": "C-42", "Examiner": "A. Examiner"})
        self.assertTrue(html.startswith("<!doctype html>"))
        for section in ("Summary", "Visual timeline", "Evidence manifest", "Validation findings", "Clock estimates", "Reconstructed timeline"):
            self.assertIn(section, html)
        self.assertIn("Case &lt;X&gt;", html)
        self.assertIn("C-42", html)
        self.assertIn("A. Examiner", html)
        for label in ("Confirmed", "Single-source", "Inferred", "Unknown gap", "Network observation", "Brand new label"):
            self.assertIn(label, html)
        for entry in report["evidence_manifest"]:
            self.assertIn(entry["sha256"], html)
        svg = svg_part(html)
        self.assertTrue(svg)
        for lane in ("gateway", "sensor-A", "sensor-B", "sensor-C", "capture.pcap"):
            self.assertIn(f"<title>{lane}</title>", svg)
        self.assertIn("lbl-gap", svg)
        self.assertRegex(svg, r"<rect class='mk lbl-gap'")
        self.assertEqual(html.count("<tr id='row-"), len(report["timeline"]))
        self.assertIn("mqtt_connect", html)
        self.assertIn("destination_port", html)

    def test_self_contained_without_script_or_external_resources(self):
        html = render_report(sample_report())
        self.assertNotIn("<script", html)
        self.assertNotRegex(html, r"(src|href)=['\"]?(https?:)?//")
        self.assertNotIn("@import", html)
        self.assertIn("@media print", html)
        self.assertIn("prefers-color-scheme:dark", html)

    def test_untrusted_strings_are_escaped(self):
        html = render_report(sample_report(), case_info={"Examiner": XSS})
        self.assertNotIn("<script>", html)
        self.assertNotIn("<b>evil</b>", html)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&#x27;", html)
        view = ReportView(device=XSS, label=XSS, query=XSS)
        interactive = render_report(sample_report(), view=view, nonce="abc")
        self.assertNotIn("<script>", interactive)
        self.assertIn("<style nonce='abc'>", interactive)

    def test_empty_and_missing_fields(self):
        for report in ({}, {"timeline": []}, {"timeline": None, "evidence_manifest": None, "clock_estimates": []}):
            html = render_report(report)
            self.assertIn("The timeline is empty.", html)
            self.assertIn("No evidence files were recorded.", html)
        html = render_report({"timeline": [{}, "not a row", {"label": None}]})
        self.assertIn("unknown time", html)

    def test_none_and_non_finite_timestamps(self):
        rows = [
            make_row(None),
            make_row(float("nan")),
            make_row(float("inf"), time_range=[1.0, float("inf")]),
            make_row(1e300, time_range=None),
            make_row(500.0, time_range=["a", None]),
            make_row(True, time_range=None),
        ]
        html = render_report({"timeline": rows})
        self.assertIn("unknown time", html)
        self.assertIn("out of datetime range", html)
        self.assertIn("no usable timestamp", html)
        self.assertEqual(html.count("<tr id='row-"), len(rows))
        only_bad = render_report({"timeline": [make_row(None), make_row(math.nan)]})
        self.assertIn("No timeline rows with a usable timestamp to draw.", only_bad)

    def test_large_timeline_caps_svg_marks(self):
        rows = [make_row(1000.0 + i * 37.0, ("Single-source", "Confirmed")[i % 2], f"dev-{i % 25}") for i in range(5000)]
        html = render_report({"timeline": rows})
        svg = svg_part(html)
        self.assertEqual(svg.count("class='mk "), MAX_SVG_MARKS)
        self.assertIn(f"only {MAX_SVG_MARKS} are drawn", html)
        self.assertEqual(html.count("<tr id='row-"), 5000)

    def test_many_lanes_overflow(self):
        rows = [make_row(1000.0 + i, device=f"device-{i:03d}") for i in range(60)]
        html = render_report({"timeline": rows})
        self.assertIn("other sources)", html)

    def test_filters_in_view(self):
        report = sample_report()
        by_device = render_report(report, view=ReportView(device="sensor-A"))
        self.assertEqual(by_device.count("<tr id='row-"), 2)
        by_label = render_report(report, view=ReportView(label="Inferred"))
        self.assertEqual(by_label.count("<tr id='row-"), 1)
        by_text = render_report(report, view=ReportView(query="MQTT_"))
        self.assertEqual(by_text.count("<tr id='row-"), 2)
        none = render_report(report, view=ReportView(query="no-such-thing"))
        self.assertIn("No rows match the current filters.", none)

    def test_css_hash_matches_static_style(self):
        self.assertTrue(css_sha256().startswith("'sha256-"))
        self.assertIn(f"<style>{REPORT_CSS}</style>", render_report({}))


def find_testbed_evidence() -> Path | None:
    """Return one generated testbed evidence folder, preferring S7, if any exist."""
    candidates = sorted((ROOT / "testbed" / "cases").glob("*/S*/evidence"))
    preferred = [path for path in candidates if path.parent.name == "S7"]
    return (preferred or candidates or [None])[-1]


class RealCaseTests(unittest.TestCase):
    def test_real_testbed_case_renders(self):
        evidence = find_testbed_evidence()
        if evidence is None:
            self.skipTest("no testbed cases present")
        with tempfile.TemporaryDirectory() as td:
            report = analyze(evidence, Path(td) / "out")
        html = render_report(report, case_info={"Case number": "TB-1"})
        svg = svg_part(html)
        self.assertTrue(svg)
        for label in {row["label"] for row in report["timeline"]}:
            self.assertIn(f">{label}<", html)
        for entry in report["evidence_manifest"]:
            self.assertIn(entry["sha256"], html)
        sources = {part.strip() for row in report["timeline"] for part in row["device_or_source"].split(",")}
        for source in sources:
            short = source if len(source) <= 30 else source[:29] + "…"
            self.assertIn(short, svg)
        self.assertEqual(html.count("<tr id='row-"), len(report["timeline"]))


class CliTests(unittest.TestCase):
    def run_cli(self, *argv: str) -> str:
        """Run the CLI in-process and return its stdout."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(list(argv))
        self.assertEqual(code, 0)
        return buffer.getvalue()

    def test_analyze_writes_html_and_export_html(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence"
            evidence.mkdir()
            rows = [{"event_id": f"e-{i}", "sequence": i, "timestamp": 100 + i, "device": "sensor-A", "event": "heartbeat"} for i in range(1, 4)]
            (evidence / "sensor-A.jsonl").write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            out = root / "out"
            output = self.run_cli("analyze", str(evidence), "--out", str(out), "--case-number", "CN-<7>", "--examiner", "Examiner Q")
            html_path = out / "report.html"
            self.assertTrue(html_path.is_file())
            self.assertIn("HTML report:", output)
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("CN-&lt;7&gt;", html)
            self.assertIn("Examiner Q", html)
            self.assertIn("<svg", html)
            self.assertTrue((out / "report.md").is_file())

            target = root / "exports" / "case.html"
            self.run_cli("export-html", str(out / "report.json"), "--out", str(target), "--examiner", "Second Examiner")
            exported = target.read_text(encoding="utf-8")
            self.assertIn("Second Examiner", exported)
            self.assertEqual(exported.count("<tr id='row-"), 3)

            html_path.unlink()
            self.run_cli("export-html", str(out / "report.json"))
            self.assertTrue(html_path.is_file())


if __name__ == "__main__":
    unittest.main()
