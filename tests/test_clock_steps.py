"""Backward clock steps and capture jitter must not read as log tampering."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from nexus_iot.pipeline import analyze
from nexus_iot.timeline import validate

START = 1_800_000_000.0


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def make_case(root: Path, step_at: int, step_s: float, edit_record: int | None = None) -> None:
    """Ten device events 3 s apart; the device clock is +2 s and jumps by step_s from event step_at on."""
    device, gateway = [], []
    for i in range(1, 11):
        true_time = START + 3.0 * i
        device_time = true_time + 2.0 + (step_s if i >= step_at else 0.0)
        if edit_record == i:
            device_time -= 40.0  # an edited line, not a clock change
        event = "heartbeat"
        device.append({"event_id": f"sensor-A-{i:03d}", "sequence": i, "device": "sensor-A",
                       "event": event, "timestamp": device_time})
        gateway.append({"event_id": f"sensor-A-{i:03d}", "sequence": i, "peer": "sensor-A",
                        "event": event, "timestamp": true_time + 0.01})
    write_jsonl(root / "sensor-A.jsonl", device)
    write_jsonl(root / "gateway.jsonl", gateway)


class BackwardClockStepTests(unittest.TestCase):
    def run_case(self, **kwargs) -> dict:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "evidence"
            evidence.mkdir()
            make_case(evidence, **kwargs)
            return analyze(evidence, Path(td) / "out", compare_previous=False)

    def test_backward_step_is_modelled_and_not_reported_as_editing(self):
        report = self.run_case(step_at=6, step_s=-30.0)
        model = report["clock_estimates"]["sensor-A.jsonl"]
        self.assertTrue(model["applied"])
        self.assertEqual(len(model["segments"]), 2)
        issues = report["validation_issues"]
        self.assertFalse(any("timestamps move backwards" in i for i in issues), issues)
        self.assertTrue(any("device time jumps back once" in i for i in issues), issues)
        self.assertTrue(any("step change detected" in i for i in issues), issues)
        for row in report["timeline"]:
            if row.get("event_id", "").startswith("sensor-A-"):
                number = int(row["event_id"].rsplit("-", 1)[1])
                self.assertAlmostEqual(row["timestamp"], START + 3.0 * number + 0.01, delta=0.1)

    def test_forward_step_behaviour_is_unchanged(self):
        report = self.run_case(step_at=6, step_s=30.0)
        model = report["clock_estimates"]["sensor-A.jsonl"]
        self.assertTrue(model["applied"])
        self.assertEqual(len(model["segments"]), 2)
        self.assertNotIn("end_record", model["segments"][0])

    def test_single_edited_timestamp_is_still_flagged(self):
        report = self.run_case(step_at=99, step_s=0.0, edit_record=5)
        issues = report["validation_issues"]
        self.assertIn("sensor-A.jsonl: timestamps move backwards in file order", issues)
        self.assertFalse(any("device time jumps back once" in i for i in issues))


def capture_rows(source: str, times: list[float]) -> list[dict]:
    return [{"timestamp": t, "event": "network_packet", "device": "gateway", "source_file": source,
             "source_id": source, "record": n, "event_id": "", "sequence": None, "peer": "", "metadata": {}}
            for n, t in enumerate(times, 1)]


class CaptureJitterTests(unittest.TestCase):
    def test_microsecond_reordering_is_a_note(self):
        issues = validate(capture_rows("gw.pcap", [10.0, 10.000002, 10.000001, 11.0]), [], {})
        self.assertFalse(any("timestamps move backwards" in i for i in issues))
        self.assertTrue(any("normal capture jitter" in i for i in issues))

    def test_large_capture_regression_is_flagged(self):
        issues = validate(capture_rows("gw.pcap", [10.0, 12.0, 11.0]), [], {})
        self.assertIn("gw.pcap: timestamps move backwards in file order", issues)

    def test_log_files_get_no_jitter_allowance(self):
        rows = capture_rows("sensor.jsonl", [10.0, 10.000002, 10.000001])
        issues = validate(rows, [], {})
        self.assertIn("sensor.jsonl: timestamps move backwards in file order", issues)


if __name__ == "__main__":
    unittest.main()
