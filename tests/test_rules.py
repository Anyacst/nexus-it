"""Detection rules: validation, each rule type, and integration with analyze and the reports."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from nexus_iot.pipeline import analyze
from nexus_iot.report_html import render_report
from nexus_iot.rules import MAX_FINDINGS_PER_RULE, apply_rules, load_rules, parse_rules

ROOT = Path(__file__).resolve().parents[1]
CALIBRATED = "device-clock-calibrated-to-gateway"


def row(t: float, event: str, device: str = "smart-lock", label: str = "Confirmed", basis: str = CALIBRATED) -> dict:
    return {"timestamp": t, "time_range": [t, t], "event": event, "device_or_source": f"{device}, gateway",
            "event_id": f"{device}-{event}-{t:g}", "label": label, "time_basis": basis}


def rules(*raw: dict) -> list[dict]:
    return parse_rules({"rules": list(raw)})


class ValidationTests(unittest.TestCase):
    def assertInvalid(self, raw: dict, message: str):
        with self.assertRaises(ValueError) as ctx:
            rules(raw)
        self.assertIn(message, str(ctx.exception))

    def test_example_rules_file_is_valid(self):
        ruleset = load_rules(ROOT / "rules" / "smart_home.json")
        self.assertEqual([r["id"] for r in ruleset["rules"]], ["R1", "R2", "R3", "R4", "R5"])
        self.assertEqual(len(ruleset["sha256"]), 64)

    def test_rejects_bad_rules(self):
        base = {"id": "X", "title": "t", "type": "match", "match": {"event": "a"}}
        self.assertInvalid({**base, "type": "nope"}, "type must be one of")
        self.assertInvalid({**base, "severity": "critical"}, "severity must be one of")
        self.assertInvalid({**base, "match": {"colour": "red"}}, "unknown key(s) colour")
        self.assertInvalid({**base, "match": {"event": []}}, "non-empty string or list")
        self.assertInvalid({**base, "window_seconds": 3}, "unknown field(s) window_seconds")
        self.assertInvalid({"id": "X", "title": "t", "type": "count_within", "match": {"event": "a"}, "count": 1,
                            "window_seconds": 5}, "count must be an integer of at least 2")
        self.assertInvalid({"id": "X", "title": "t", "type": "sequence", "first": {"event": "a"}, "then": {"event": "b"},
                            "within_seconds": -1}, "positive number of seconds")
        with self.assertRaises(ValueError) as ctx:
            rules(base, base)
        self.assertIn("duplicate id", str(ctx.exception))

    def test_rejects_unreadable_files(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules(path)
            with self.assertRaises(ValueError):
                load_rules(Path(td) / "missing.json")


class RuleTypeTests(unittest.TestCase):
    def test_absent_within(self):
        r = rules({"id": "R1", "title": "lock without motion", "type": "absent_within", "trigger": {"event": "lock_released"},
                   "expect": {"event": "motion_detected"}, "window_seconds": 30})
        timeline = [row(100, "motion_detected", "motion-sensor"), row(120, "lock_released"),  # motion 20 s before: fine
                    row(300, "lock_released"),                                                # nothing near: finding
                    row(500, "lock_released"), row(525, "motion_detected", "motion-sensor")]  # motion 25 s after: fine
        findings = apply_rules(timeline, r)
        self.assertEqual([f["timestamp"] for f in findings], [300])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("within 30 s", findings[0]["detail"])

    def test_absent_within_direction_after(self):
        r = rules({"id": "R1", "title": "t", "type": "absent_within", "trigger": {"event": "lock_released"},
                   "expect": {"event": "motion_detected"}, "window_seconds": 30, "direction": "after"})
        findings = apply_rules([row(100, "motion_detected", "motion-sensor"), row(120, "lock_released")], r)
        self.assertEqual(len(findings), 1)

    def test_inferred_rows_do_not_satisfy_expectations_by_default(self):
        r = rules({"id": "R1", "title": "t", "type": "absent_within", "trigger": {"event": "lock_released"},
                   "expect": {"event": "motion_detected"}, "window_seconds": 30})
        timeline = [row(100, "motion_detected", "motion-sensor", label="Inferred"), row(110, "lock_released")]
        self.assertEqual(len(apply_rules(timeline, r)), 1)

    def test_sequence(self):
        r = rules({"id": "R2", "title": "t", "type": "sequence", "first": {"event": "lock_released"},
                   "then": {"event": "door_open", "device": "door-sensor"}, "within_seconds": 10})
        timeline = [row(100, "lock_released"), row(104, "door_open", "door-sensor"), row(107, "door_open", "door-sensor"),
                    row(200, "lock_released"), row(215, "door_open", "door-sensor")]
        findings = apply_rules(timeline, r)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["event_ids"], ["smart-lock-lock_released-100", "door-sensor-door_open-104"])
        self.assertEqual(findings[0]["devices"], ["door-sensor", "gateway", "smart-lock"])

    def test_count_within_restarts_after_each_finding(self):
        r = rules({"id": "R3", "title": "t", "type": "count_within", "match": {"event": "door_open"}, "count": 3,
                   "window_seconds": 10})
        timeline = [row(t, "door_open", "door-sensor") for t in (0, 2, 4, 6, 8, 10, 40, 60)]
        findings = apply_rules(timeline, r)
        self.assertEqual([len(f["event_ids"]) for f in findings], [3, 3])
        self.assertEqual([f["timestamp"] for f in findings], [0, 6])

    def test_match_on_label_and_uncalibrated_note(self):
        r = rules({"id": "R5", "title": "gaps", "type": "match", "severity": "high", "match": {"label": "Unknown gap"}})
        timeline = [row(1, "Unknown missing event(s)", label="Unknown gap", basis="unreconciled-device-clocks"),
                    row(2, "boot")]
        findings = apply_rules(timeline, r)
        self.assertEqual(len(findings), 1)
        self.assertIn("unreconciled-device-clocks", findings[0]["time_note"])

    def test_findings_per_rule_are_capped(self):
        r = rules({"id": "R", "title": "t", "type": "match", "match": {"event": "boot"}})
        findings = apply_rules([row(t, "boot") for t in range(MAX_FINDINGS_PER_RULE + 7)], r)
        self.assertEqual(len(findings), MAX_FINDINGS_PER_RULE)
        self.assertIn("7 further finding(s)", findings[-1]["detail"])


class IntegrationTests(unittest.TestCase):
    def test_analyze_with_rules_writes_findings_to_all_reports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence"
            evidence.mkdir()
            device = [{"event_id": f"smart-lock-{i}", "sequence": i, "device": "smart-lock", "event": "lock_released",
                       "timestamp": 1000.0 + 60 * i} for i in range(1, 4)]
            gateway = [{**d, "device": "gateway", "peer": "smart-lock", "timestamp": d["timestamp"] + 0.01} for d in device]
            (evidence / "smart-lock.jsonl").write_text("".join(json.dumps(d) + "\n" for d in device), encoding="utf-8")
            (evidence / "gateway.jsonl").write_text("".join(json.dumps(g) + "\n" for g in gateway), encoding="utf-8")
            report = analyze(evidence, root / "out", rules_path=ROOT / "rules" / "smart_home.json")
            r1 = [f for f in report["rule_findings"] if f["rule_id"] == "R1"]
            self.assertEqual(len(r1), 3)
            self.assertEqual(report["rules"]["rules"][0]["id"], "R1")
            self.assertTrue(any("Rule findings come from" in x for x in report["limitations"]))
            markdown = (root / "out" / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Rule findings", markdown)
            self.assertIn("R1: Lock released with no motion nearby", markdown)
            html = render_report(report)
            self.assertIn("id=rules", html)
            self.assertIn("href='#row-", html)

    def test_analyze_without_rules_has_no_rule_keys(self):
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence"
            evidence.mkdir()
            (evidence / "a.jsonl").write_text(json.dumps({"event_id": "a-1", "sequence": 1, "device": "a", "event": "boot",
                                                          "timestamp": 1}) + "\n", encoding="utf-8")
            report = analyze(evidence, Path(td) / "out")
            self.assertNotIn("rule_findings", report)
            self.assertNotIn("id=rules", render_report(report))


if __name__ == "__main__":
    unittest.main()
