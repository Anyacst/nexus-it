"""Scoring of Unknown gaps against ground truth, including a deleted final log line."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from nexus_iot.evaluate import score_case


def write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


class GapScoringTests(unittest.TestCase):
    def score(self, delete: set[int], extra_gateway: bool = False) -> dict:
        """Five door-sensor events logged by device and gateway; delete device lines by sequence."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = root / "evidence"
            evidence.mkdir()
            events, device, gateway = [], [], []
            for n in range(1, 6):
                event_id, t = f"door-sensor-{n:05d}", 1000.0 + 3 * n
                events.append({"event_id": event_id, "timestamp": t, "device": "door-sensor", "event": "door_open",
                               "expected_sources": ["door-sensor.jsonl", "gateway.jsonl"],
                               "source_sequences": {"door-sensor.jsonl": n, "gateway.jsonl": n}})
                if n not in delete:
                    device.append({"event_id": event_id, "sequence": n, "device": "door-sensor", "event": "door_open", "timestamp": t})
                gateway.append({"event_id": event_id, "sequence": n, "peer": "door-sensor", "event": "door_open", "timestamp": t + 0.01})
            if extra_gateway:  # a gateway record for an event that never happened
                gateway.append({"event_id": "door-sensor-00099", "sequence": 6, "peer": "door-sensor", "event": "door_open",
                                "timestamp": 1030.0})
            write(evidence / "door-sensor.jsonl", device)
            write(evidence / "gateway.jsonl", gateway)
            truth = {"condition": "t", "events": events, "tampering_seeded": bool(delete)}
            return score_case(evidence, truth, root / "out", "T", "test")

    def test_deleted_middle_line_is_a_sequence_gap(self):
        result = self.score({3})
        self.assertEqual((result["unknown_gap_precision"], result["unknown_gap_recall"]), (1.0, 1.0))

    def test_deleted_last_line_is_credited_from_the_missing_log_gap(self):
        result = self.score({5})
        self.assertEqual((result["unknown_gap_precision"], result["unknown_gap_recall"]), (1.0, 1.0))

    def test_missing_log_gap_for_an_unknown_event_is_a_false_gap(self):
        result = self.score({5}, extra_gateway=True)
        self.assertEqual(result["unknown_gap_recall"], 1.0)
        self.assertEqual(result["unknown_gap_precision"], 0.5)

    def test_no_deletion_scores_perfect(self):
        result = self.score(set())
        self.assertEqual((result["unknown_gap_precision"], result["unknown_gap_recall"]), (1.0, 1.0))


if __name__ == "__main__":
    unittest.main()
