"""Tests for testbed.runner.collect (no Docker needed).

`make_fake_run` is also used by test_scenarios.py to fake a finished Docker run.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from testbed.runner.collect import DEVICE_EVENTS, collect_case, devices_config
from testbed.runner.scenarios import SCENARIOS

BASE_TIME = 1_800_000_000.0
FAKE_COUNTS = {"door-sensor": 8, "temp-sensor": 6, "smart-plug": 5, "motion-sensor": 5, "smart-lock": 4}
FAKE_INTERVALS = {"door-sensor": 3.0, "temp-sensor": 2.0, "smart-plug": 4.0, "motion-sensor": 5.0, "smart-lock": 6.0}
DEFAULT_UNPUBLISHED = frozenset({("temp-sensor", 3), ("temp-sensor", 4)})


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def make_fake_run(run_dir: Path, unpublished: frozenset = DEFAULT_UNPUBLISHED, counts: dict[str, int] | None = None) -> dict:
    """Write a fake finished run (logs, truth, capture, broker) like the containers would.

    `unpublished` holds (device, sequence) pairs that never reached the gateway.
    `counts` overrides the number of log lines per device (default FAKE_COUNTS).
    Returns {"device_rows": {...}, "truth_rows": [...], "gateway_rows": [...]}.
    """
    for name in ("logs", "truth", "capture", "broker"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)

    device_rows: dict[str, list[dict]] = {}
    truth_rows: list[dict] = []
    published: list[dict] = []
    for device, count in (counts or FAKE_COUNTS).items():
        events = ["boot"] + [DEVICE_EVENTS[device][i % len(DEVICE_EVENTS[device])] for i in range(count - 1)]
        rows, truths = [], []
        for sequence, event in enumerate(events, start=1):
            true_time = BASE_TIME + (sequence - 1) * FAKE_INTERVALS[device] + 0.1 * len(device)
            record = {
                "event_id": f"{device}-{sequence:05d}",
                "sequence": sequence,
                "device": device,
                "event": event,
                "timestamp": true_time + 0.01,
            }
            rows.append(record)
            is_published = (device, sequence) not in unpublished
            truths.append({**record, "true_time": true_time, "device_time": true_time + 0.01, "published": is_published})
            if is_published:
                published.append(record)
        for truth in truths:
            del truth["timestamp"]
        device_rows[device] = rows
        truth_rows.extend(truths)
        _write_jsonl(run_dir / "logs" / f"{device}.jsonl", rows)
        _write_jsonl(run_dir / "truth" / f"{device}.truth.jsonl", truths)

    published.sort(key=lambda r: r["timestamp"])
    gateway_rows = [
        {
            "timestamp": record["timestamp"] + 0.05,
            "event": record["event"],
            "event_id": record["event_id"],
            "sequence": counter,
            "peer": record["device"],
            "topic": f"nexus/{record['device']}/{record['event']}",
            "device_timestamp": record["timestamp"],
        }
        for counter, record in enumerate(published, start=1)
    ]
    _write_jsonl(run_dir / "logs" / "gateway.jsonl", gateway_rows)

    (run_dir / "logs" / "notes.txt").write_text("not evidence\n", encoding="utf-8")
    (run_dir / "logs" / "debug.jsonl").write_text("{}\n", encoding="utf-8")
    (run_dir / "capture" / "gateway-1000.pcap").write_bytes(b"\xd4\xc3\xb2\xa1first")
    (run_dir / "capture" / "gateway-2000.pcap").write_bytes(b"\xd4\xc3\xb2\xa1second")
    (run_dir / "capture" / "other.pcap").write_bytes(b"ignored")
    (run_dir / "broker" / "mosquitto.log").write_text("2026-01-01T00:00:00: started\n", encoding="utf-8")
    return {"device_rows": device_rows, "truth_rows": truth_rows, "gateway_rows": gateway_rows}


EXPECTED_EVIDENCE = {
    "door-sensor.jsonl",
    "temp-sensor.jsonl",
    "smart-plug.jsonl",
    "motion-sensor.jsonl",
    "smart-lock.jsonl",
    "gateway.jsonl",
    "gateway-1000.pcap",
    "gateway-2000.pcap",
    "devices.json",
}


class DevicesConfigTests(unittest.TestCase):
    def test_device_ips(self) -> None:
        config = devices_config()
        self.assertEqual(
            config["device_ips"],
            {
                "door-sensor": ["172.30.0.21"],
                "temp-sensor": ["172.30.0.22"],
                "smart-plug": ["172.30.0.23"],
                "motion-sensor": ["172.30.0.24"],
                "smart-lock": ["172.30.0.25"],
            },
        )

    def test_one_rule_per_device_event_including_boot(self) -> None:
        rules = devices_config()["correlation_rules"]
        expected = {(d, e) for d, events in DEVICE_EVENTS.items() for e in ["boot", *events]}
        self.assertEqual({(r["device"], r["event"]) for r in rules}, expected)
        self.assertEqual(len(rules), len(expected))
        self.assertEqual(len(rules), 14)
        rule = next(r for r in rules if r["device"] == "door-sensor" and r["event"] == "boot")
        self.assertEqual(
            rule,
            {
                "id": "door-sensor-boot-mqtt",
                "device": "door-sensor",
                "event": "boot",
                "protocol": "tcp",
                "direction": "outbound",
                "destination_port": 1883,
                "window_seconds": 2.0,
            },
        )


class CollectCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.run_dir = self.root / "runs" / "r1" / "S6"
        self.fake = make_fake_run(self.run_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _collect(self, scenario_id: str) -> Path:
        case_dir = self.root / "cases" / "r1" / scenario_id
        meta = {"run_id": "r1", "params": {"duration_s": 40}}
        return collect_case(self.run_dir, case_dir, SCENARIOS[scenario_id], meta)

    def test_layout_and_evidence_set(self) -> None:
        case = self._collect("S1")
        self.assertEqual({p.name for p in (case / "evidence").iterdir()}, EXPECTED_EVIDENCE)
        self.assertEqual({p.name for p in (case / "original").iterdir()}, EXPECTED_EVIDENCE | {"SHA256SUMS"})
        self.assertTrue((case / "ground_truth" / "truth.json").is_file())
        self.assertEqual({p.name for p in (case / "extra").iterdir()}, {"mosquitto.log", "run.json"})
        self.assertFalse((case / "evidence" / "truth.json").exists())

    def test_devices_json_written(self) -> None:
        case = self._collect("S1")
        written = json.loads((case / "evidence" / "devices.json").read_text(encoding="utf-8"))
        self.assertEqual(written, devices_config())

    def test_sha256sums_match_original(self) -> None:
        case = self._collect("S6")
        original = case / "original"
        lines = (original / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), len(EXPECTED_EVIDENCE))
        for line in lines:
            digest, name = line.split(maxsplit=1)
            self.assertEqual(hashlib.sha256((original / name).read_bytes()).hexdigest(), digest, name)

    def test_untampered_case_evidence_equals_original(self) -> None:
        case = self._collect("S1")
        for name in EXPECTED_EVIDENCE:
            self.assertEqual((case / "evidence" / name).read_bytes(), (case / "original" / name).read_bytes(), name)
        for name in ("door-sensor.jsonl", "gateway.jsonl"):
            self.assertEqual((case / "evidence" / name).read_bytes(), (self.run_dir / "logs" / name).read_bytes())

    def test_truth_written_from_pre_tamper_logs(self) -> None:
        case = self._collect("S6")
        truth = json.loads((case / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        self.assertEqual(truth["condition"], "Post-collection tampering")
        self.assertTrue(truth["tampering_seeded"])
        self.assertEqual(truth["tamper_mechanisms"], ["delete", "edit", "insert"])
        self.assertEqual(len(truth["events"]), sum(FAKE_COUNTS.values()))
        by_id = {e["event_id"]: e for e in truth["events"]}
        # Deleted smart-plug index 3 is still expected (it existed before tampering).
        self.assertIn("gateway.jsonl", by_id["smart-plug-00004"]["expected_sources"])
        # Edited event keeps its true name.
        self.assertEqual(by_id["door-sensor-00005"]["event"], "door_close")
        self.assertNotIn("door-sensor-fab01", by_id)
        self.assertEqual(by_id["temp-sensor-00003"]["expected_sources"], ["temp-sensor.jsonl"])
        unpublished = len(DEFAULT_UNPUBLISHED)
        self.assertEqual(truth["expected_record_count"], 2 * sum(FAKE_COUNTS.values()) - unpublished)

    def test_tamper_applied_to_evidence_only(self) -> None:
        case = self._collect("S6")
        evidence = case / "evidence"
        original = case / "original"
        for name in ("door-sensor.jsonl", "smart-plug.jsonl"):
            self.assertNotEqual((evidence / name).read_bytes(), (original / name).read_bytes(), name)
            self.assertEqual((original / name).read_bytes(), (self.run_dir / "logs" / name).read_bytes(), name)
        for name in ("temp-sensor.jsonl", "motion-sensor.jsonl", "smart-lock.jsonl", "gateway.jsonl"):
            self.assertEqual((evidence / name).read_bytes(), (original / name).read_bytes(), name)

        plug = [json.loads(line) for line in (evidence / "smart-plug.jsonl").read_text().splitlines()]
        self.assertEqual(len(plug), FAKE_COUNTS["smart-plug"] - 1)
        self.assertNotIn("smart-plug-00004", [r["event_id"] for r in plug])

        door = [json.loads(line) for line in (evidence / "door-sensor.jsonl").read_text().splitlines()]
        self.assertEqual(len(door), FAKE_COUNTS["door-sensor"] + 1)
        self.assertEqual(door[4]["event"], "door_close_forced")
        self.assertEqual(door[6]["event_id"], "door-sensor-fab01")
        self.assertEqual(door[6]["sequence"], door[5]["sequence"])
        self.assertEqual(door[6]["event"], "door_open")

        meta = json.loads((case / "extra" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["scenario_id"], "S6")
        self.assertEqual(meta["run_id"], "r1")
        self.assertEqual([entry["kind"] for entry in meta["tamper_log"]], ["delete", "edit", "insert"])

    def test_seeded_parameters_recorded_in_truth_and_run_json(self) -> None:
        from testbed.runner.variation import build_scenario

        scenario = build_scenario("S2", 5, 30.0)
        case = collect_case(self.run_dir, self.root / "cases" / "r1" / "S2", scenario, {"run_id": "r1"})
        truth = json.loads((case / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        meta = json.loads((case / "extra" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(truth["parameters"], scenario.parameters)
        self.assertEqual(meta["parameters"], scenario.parameters)
        self.assertIn("disconnect", truth["parameters"])

    def test_refuses_non_empty_case_dir(self) -> None:
        case_dir = self.root / "cases" / "r1" / "S1"
        case_dir.mkdir(parents=True)
        (case_dir / "something").write_text("x", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            collect_case(self.run_dir, case_dir, SCENARIOS["S1"], {})


if __name__ == "__main__":
    unittest.main()
