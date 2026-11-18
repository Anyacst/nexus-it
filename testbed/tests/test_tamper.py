"""Tests for testbed.runner.tamper."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from testbed.runner.scenarios import SCENARIOS, TamperOp
from testbed.runner.tamper import (
    apply_tamper,
    delete_line,
    edit_event,
    insert_fabricated,
    tamper_lines,
)


def make_lines(device: str = "door-sensor", count: int = 8) -> list[str]:
    events = ["boot"] + [("door_open", "door_close")[i % 2] for i in range(count - 1)]
    return [
        json.dumps(
            {
                "event_id": f"{device}-{seq:05d}",
                "sequence": seq,
                "device": device,
                "event": event,
                "timestamp": 1000.0 + 3 * (seq - 1),
            }
        )
        for seq, event in enumerate(events, start=1)
    ]


def ids(lines: list[str]) -> list[str]:
    return [json.loads(line)["event_id"] for line in lines]


class HelperTests(unittest.TestCase):
    def test_delete_line(self) -> None:
        lines = make_lines(count=4)
        result = delete_line(lines, 1)
        self.assertEqual(ids(result), ["door-sensor-00001", "door-sensor-00003", "door-sensor-00004"])
        self.assertEqual(len(lines), 4, "input must not be mutated")

    def test_edit_event_changes_event_only(self) -> None:
        lines = make_lines(count=4)
        result = edit_event(lines, 2, "door_close_forced")
        before = json.loads(lines[2])
        after = json.loads(result[2])
        self.assertEqual(after["event"], "door_close_forced")
        del before["event"], after["event"]
        self.assertEqual(before, after)
        self.assertEqual(result[:2] + result[3:], lines[:2] + lines[3:])
        self.assertEqual(json.loads(lines[2])["event"], "door_close", "input must not be mutated")

    def test_insert_fabricated_copies_previous(self) -> None:
        lines = make_lines(count=7)
        result = insert_fabricated(lines, 6, "door-sensor", "door_open")
        self.assertEqual(len(result), 8)
        fab = json.loads(result[6])
        previous = json.loads(lines[5])
        self.assertEqual(fab["event_id"], "door-sensor-fab01")
        self.assertEqual(fab["sequence"], previous["sequence"], "sequence must be duplicated")
        self.assertEqual(fab["timestamp"], previous["timestamp"] + 0.5)
        self.assertEqual(fab["event"], "door_open")
        self.assertEqual(fab["device"], "door-sensor")
        self.assertEqual(result[7], lines[6])

    def test_insert_defaults(self) -> None:
        lines = make_lines(count=3)
        fab = json.loads(insert_fabricated(lines, 3, fab_number=2)[3])
        self.assertEqual(fab["event_id"], "door-sensor-fab02")
        self.assertEqual(fab["event"], json.loads(lines[2])["event"])

    def test_out_of_range(self) -> None:
        lines = make_lines(count=4)
        with self.assertRaises(ValueError):
            delete_line(lines, 4)
        with self.assertRaises(ValueError):
            delete_line(lines, -1)
        with self.assertRaises(ValueError):
            edit_event(lines, 10, "x")
        with self.assertRaises(ValueError):
            insert_fabricated(lines, 0)
        with self.assertRaises(ValueError):
            insert_fabricated(lines, 5)
        # Inserting at the end (after the last line) is allowed.
        self.assertEqual(len(insert_fabricated(lines, 4)), 5)


class TamperLinesTests(unittest.TestCase):
    def test_multiple_ops_use_original_indices(self) -> None:
        lines = make_lines(count=8)
        ops = [
            TamperOp("delete", "door-sensor.jsonl", 1),
            TamperOp("edit", "door-sensor.jsonl", 4, "door_close_forced"),
            TamperOp("insert", "door-sensor.jsonl", 6, "door_open"),
        ]
        result, log = tamper_lines(lines, ops, "door-sensor")
        self.assertEqual(
            ids(result),
            [
                "door-sensor-00001",
                "door-sensor-00003",
                "door-sensor-00004",
                "door-sensor-00005",
                "door-sensor-00006",
                "door-sensor-fab01",
                "door-sensor-00007",
                "door-sensor-00008",
            ],
        )
        records = {json.loads(line)["event_id"]: json.loads(line) for line in result}
        self.assertEqual(records["door-sensor-00005"]["event"], "door_close_forced")
        self.assertEqual(records["door-sensor-fab01"]["sequence"], 6)
        self.assertEqual([entry["kind"] for entry in log], ["delete", "edit", "insert"])
        self.assertEqual(log[0]["before"], lines[1])
        self.assertIsNone(log[0]["after"])
        self.assertEqual(log[1]["before"], lines[4])
        self.assertIsNone(log[2]["before"])

    def test_same_index_delete_and_insert(self) -> None:
        lines = make_lines(count=5)
        ops = [
            TamperOp("insert", "door-sensor.jsonl", 2),
            TamperOp("delete", "door-sensor.jsonl", 2),
        ]
        result, _ = tamper_lines(lines, ops, "door-sensor")
        self.assertEqual(
            ids(result),
            ["door-sensor-00001", "door-sensor-00002", "door-sensor-fab01", "door-sensor-00004", "door-sensor-00005"],
        )

    def test_insert_copies_unedited_original_previous_line(self) -> None:
        lines = make_lines(count=5)
        ops = [
            TamperOp("edit", "door-sensor.jsonl", 2, "door_close_forced"),
            TamperOp("insert", "door-sensor.jsonl", 3),
        ]
        result, _ = tamper_lines(lines, ops, "door-sensor")
        self.assertEqual(json.loads(result[2])["event"], "door_close_forced")
        self.assertEqual(json.loads(result[3])["event"], json.loads(lines[2])["event"])

    def test_multiple_inserts_numbered_by_position(self) -> None:
        lines = make_lines(count=6)
        ops = [
            TamperOp("insert", "door-sensor.jsonl", 5),
            TamperOp("insert", "door-sensor.jsonl", 2),
        ]
        result, log = tamper_lines(lines, ops, "door-sensor")
        self.assertEqual(ids(result)[2], "door-sensor-fab01")
        self.assertEqual(ids(result)[6], "door-sensor-fab02")
        self.assertEqual(json.loads(log[0]["after"])["event_id"], "door-sensor-fab02")

    def test_out_of_range_op_changes_nothing(self) -> None:
        lines = make_lines(count=4)
        ops = [TamperOp("delete", "door-sensor.jsonl", 1), TamperOp("edit", "door-sensor.jsonl", 9, "x")]
        with self.assertRaises(ValueError):
            tamper_lines(lines, ops, "door-sensor")

    def test_double_delete_rejected(self) -> None:
        lines = make_lines(count=4)
        ops = [TamperOp("delete", "door-sensor.jsonl", 1), TamperOp("edit", "door-sensor.jsonl", 1, "x")]
        with self.assertRaises(ValueError):
            tamper_lines(lines, ops, "door-sensor")


class ApplyTamperTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.case = Path(self._tmp.name)
        self.evidence = self.case / "evidence"
        self.original = self.case / "original"
        self.evidence.mkdir()
        self.original.mkdir()
        for device, count in (("door-sensor", 8), ("smart-plug", 5), ("temp-sensor", 4)):
            text = "".join(line + "\n" for line in make_lines(device, count))
            (self.evidence / f"{device}.jsonl").write_text(text, encoding="utf-8")
            (self.original / f"{device}.jsonl").write_text(text, encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _snapshot(self, folder: Path) -> dict[str, bytes]:
        return {p.name: p.read_bytes() for p in folder.iterdir()}

    def test_s6_ops(self) -> None:
        before_original = self._snapshot(self.original)
        before_temp = (self.evidence / "temp-sensor.jsonl").read_bytes()
        log = apply_tamper(self.evidence, SCENARIOS["S6"].tamper)

        self.assertEqual(self._snapshot(self.original), before_original, "original/ must not change")
        self.assertEqual((self.evidence / "temp-sensor.jsonl").read_bytes(), before_temp)
        self.assertEqual([(e["kind"], e["file"], e["index"]) for e in log],
                         [("delete", "smart-plug.jsonl", 3), ("edit", "door-sensor.jsonl", 4),
                          ("insert", "door-sensor.jsonl", 6)])

        plug = (self.evidence / "smart-plug.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(plug), 4)
        self.assertNotIn("smart-plug-00004", ids(plug))

        door = [json.loads(line) for line in (self.evidence / "door-sensor.jsonl").read_text().splitlines()]
        self.assertEqual(len(door), 9)
        self.assertEqual(door[4]["event"], "door_close_forced")
        self.assertEqual(door[6]["event_id"], "door-sensor-fab01")
        self.assertEqual(door[6]["sequence"], door[5]["sequence"])
        self.assertEqual(door[6]["event"], "door_open")
        self.assertTrue((self.evidence / "door-sensor.jsonl").read_text().endswith("\n"))

    def test_out_of_range_leaves_file_untouched(self) -> None:
        before = self._snapshot(self.evidence)
        with self.assertRaises(ValueError):
            apply_tamper(self.evidence, [TamperOp("delete", "smart-plug.jsonl", 5)])
        self.assertEqual(self._snapshot(self.evidence), before)

    def test_refuses_original_folder(self) -> None:
        before = self._snapshot(self.original)
        with self.assertRaises(ValueError):
            apply_tamper(self.original, SCENARIOS["S6"].tamper)
        self.assertEqual(self._snapshot(self.original), before)

    def test_no_ops_is_noop(self) -> None:
        before = self._snapshot(self.evidence)
        self.assertEqual(apply_tamper(self.evidence, []), [])
        self.assertEqual(self._snapshot(self.evidence), before)


if __name__ == "__main__":
    unittest.main()
