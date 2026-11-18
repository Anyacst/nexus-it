"""Tests for testbed.runner.truth (pure ground-truth builder)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from testbed.runner.scenarios import SCENARIOS, Scenario, TamperOp
from testbed.runner.truth import build_truth, load_jsonl


def truth_row(device: str, sequence: int, event: str, true_time: float, published: bool = True) -> dict:
    return {
        "event_id": f"{device}-{sequence:05d}",
        "sequence": sequence,
        "device": device,
        "event": event,
        "true_time": true_time,
        "device_time": true_time + 3.0,
        "published": published,
    }


def gateway_row(event_id: str, event: str, sequence: int, arrival: float) -> dict:
    device = event_id.rsplit("-", 1)[0]
    return {
        "timestamp": arrival,
        "event": event,
        "event_id": event_id,
        "sequence": sequence,
        "peer": device,
        "topic": f"nexus/{device}/{event}",
        "device_timestamp": arrival - 0.1,
    }


class BuildTruthTests(unittest.TestCase):
    def setUp(self) -> None:
        # Deliberately out of time order across devices.
        self.rows = [
            truth_row("door-sensor", 1, "boot", 100.0),
            truth_row("door-sensor", 2, "door_open", 103.0),
            truth_row("temp-sensor", 1, "boot", 100.5),
            truth_row("temp-sensor", 2, "temperature_reading", 102.5, published=False),
            truth_row("smart-plug", 1, "boot", 99.0),
        ]
        self.gateway = [
            gateway_row("smart-plug-00001", "boot", 1, 99.1),
            gateway_row("door-sensor-00001", "boot", 2, 100.1),
            gateway_row("temp-sensor-00001", "boot", 3, 100.6),
            gateway_row("door-sensor-00002", "door_open", 4, 103.1),
            # QoS 1 redelivery: the first gateway sequence must win.
            gateway_row("door-sensor-00002", "door_open", 5, 103.2),
            # Unknown event_id in the gateway log is ignored.
            gateway_row("ghost-00001", "boot", 6, 104.0),
        ]

    def test_events_sorted_by_true_time(self) -> None:
        truth = build_truth(SCENARIOS["S1"], self.rows, self.gateway)
        times = [e["timestamp"] for e in truth["events"]]
        self.assertEqual(times, sorted(times))
        self.assertEqual(truth["events"][0]["event_id"], "smart-plug-00001")
        self.assertEqual(len(truth["events"]), 5)

    def test_event_fields(self) -> None:
        truth = build_truth(SCENARIOS["S1"], self.rows, self.gateway)
        event = next(e for e in truth["events"] if e["event_id"] == "door-sensor-00002")
        self.assertEqual(
            event,
            {
                "event_id": "door-sensor-00002",
                "timestamp": 103.0,
                "device": "door-sensor",
                "event": "door_open",
                "expected_sources": ["door-sensor.jsonl", "gateway.jsonl"],
                "source_sequences": {"door-sensor.jsonl": 2, "gateway.jsonl": 4},
            },
        )

    def test_event_without_gateway_receipt(self) -> None:
        truth = build_truth(SCENARIOS["S2"], self.rows, self.gateway)
        event = next(e for e in truth["events"] if e["event_id"] == "temp-sensor-00002")
        self.assertEqual(event["expected_sources"], ["temp-sensor.jsonl"])
        self.assertEqual(event["source_sequences"], {"temp-sensor.jsonl": 2})

    def test_expected_record_count(self) -> None:
        truth = build_truth(SCENARIOS["S1"], self.rows, self.gateway)
        self.assertEqual(truth["expected_record_count"], 9)
        self.assertEqual(truth["expected_record_count"], sum(len(e["expected_sources"]) for e in truth["events"]))

    def test_flags_for_normal_run(self) -> None:
        truth = build_truth(SCENARIOS["S1"], self.rows, self.gateway)
        self.assertEqual(truth["condition"], "Normal operation")
        self.assertFalse(truth["tampering_seeded"])
        self.assertEqual(truth["tamper_mechanisms"], [])
        self.assertFalse(truth["clock_manipulated"])

    def test_flags_for_combined_run(self) -> None:
        truth = build_truth(SCENARIOS["S7"], self.rows, self.gateway)
        self.assertEqual(truth["condition"], "Combined")
        self.assertTrue(truth["tampering_seeded"])
        self.assertEqual(truth["tamper_mechanisms"], ["delete", "edit", "insert"])
        self.assertTrue(truth["clock_manipulated"])

    def test_tamper_mechanisms_unique_in_order(self) -> None:
        scenario = Scenario(
            id="X",
            title="Custom",
            tamper=[
                TamperOp("insert", "door-sensor.jsonl", 2, "door_open"),
                TamperOp("delete", "smart-plug.jsonl", 1),
                TamperOp("insert", "door-sensor.jsonl", 4),
            ],
        )
        truth = build_truth(scenario, self.rows, self.gateway)
        self.assertEqual(truth["tamper_mechanisms"], ["insert", "delete"])

    def test_key_set_matches_evaluator_format(self) -> None:
        truth = build_truth(SCENARIOS["S1"], self.rows, [])
        self.assertEqual(
            set(truth),
            {"condition", "events", "tampering_seeded", "tamper_mechanisms", "clock_manipulated", "expected_record_count"},
        )
        self.assertEqual(truth["expected_record_count"], 5)
        json.dumps(truth)  # serialisable

    def test_seeded_parameters_key(self) -> None:
        parameters = {"seed": 3, "duration_s": 40.0, "clock_drift": {"device": "smart-lock", "drift_ppm": -4000}}
        scenario = Scenario(id="S4", title="Clock drift", clock_manipulated=True, parameters=parameters)
        truth = build_truth(scenario, self.rows, self.gateway)
        self.assertEqual(truth["parameters"], parameters)
        json.dumps(truth)

    def test_empty_inputs(self) -> None:
        truth = build_truth(SCENARIOS["S1"], [], [])
        self.assertEqual(truth["events"], [])
        self.assertEqual(truth["expected_record_count"], 0)


class LoadJsonlTests(unittest.TestCase):
    def test_reads_rows_and_skips_blank_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text('{"a": 1}\n\n{"a": 2}\n', encoding="utf-8")
            self.assertEqual(load_jsonl(path), [{"a": 1}, {"a": 2}])

    def test_invalid_line_raises_with_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text('{"a": 1}\nnot json\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, ":2:"):
                load_jsonl(path)

    def test_non_object_line_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text("[1, 2]\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_jsonl(path)


if __name__ == "__main__":
    unittest.main()
