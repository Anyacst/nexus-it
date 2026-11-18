"""End-to-end tests: run real Docker scenarios, then check evidence, ground truth and analyzer output.

These tests start containers and take several minutes, so they run only when
NEXUS_DOCKER_TESTS=1 is set and a Docker daemon is reachable:

    NEXUS_DOCKER_TESTS=1 python3 -m unittest testbed.tests.test_integration_docker -v
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DURATION = os.environ.get("NEXUS_DOCKER_DURATION", "30")
DEVICES = ("door-sensor", "temp-sensor", "smart-plug", "motion-sensor", "smart-lock")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


ENABLED = os.environ.get("NEXUS_DOCKER_TESTS") == "1" and _docker_available()


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@unittest.skipUnless(ENABLED, "set NEXUS_DOCKER_TESTS=1 with a running Docker daemon")
class DockerScenarioTests(unittest.TestCase):
    """Runs S1, S2, S3 and S6 once, then checks each case folder."""

    cases: dict[str, Path] = {}
    scores: dict[str, dict] = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="nexus-tb-it-"))
        command = [sys.executable, "-m", "testbed.runner.run_scenario", "S1", "S2", "S3", "S6",
                   "--duration", DURATION, "--cases-root", str(cls.tmp / "cases")]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1800)
        if result.returncode != 0:
            raise AssertionError(f"runner failed ({result.returncode}):\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
        from nexus_iot.evaluate import score_case

        for sid in ("S1", "S2", "S3", "S6"):
            matches = sorted((cls.tmp / "cases").glob(f"*/{sid}"))
            if not matches:
                raise AssertionError(f"no case folder for {sid} under {cls.tmp / 'cases'}")
            case = matches[-1]
            cls.cases[sid] = case
            truth = json.loads((case / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
            cls.scores[sid] = score_case(case / "evidence", truth, cls.tmp / "derived" / sid, sid, truth["condition"])

    @classmethod
    def tearDownClass(cls) -> None:
        if os.environ.get("NEXUS_KEEP_IT_OUTPUT") != "1":
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- evidence shape -------------------------------------------------

    def test_case_folder_has_expected_evidence(self) -> None:
        evidence = self.cases["S1"] / "evidence"
        for name in [f"{d}.jsonl" for d in DEVICES] + ["gateway.jsonl", "devices.json"]:
            self.assertTrue((evidence / name).is_file(), name)
            self.assertGreater((evidence / name).stat().st_size, 0, name)
        self.assertTrue(list(evidence.glob("gateway-*.pcap")), "no packet capture collected")
        self.assertFalse((evidence / "truth.json").exists(), "ground truth leaked into evidence")

    def test_gateway_event_ids_come_from_devices(self) -> None:
        evidence = self.cases["S1"] / "evidence"
        device_ids = {r["event_id"] for d in DEVICES for r in _read_jsonl(evidence / f"{d}.jsonl")}
        gateway_ids = {r["event_id"] for r in _read_jsonl(evidence / "gateway.jsonl")}
        self.assertTrue(gateway_ids)
        self.assertLessEqual(gateway_ids, device_ids)

    def test_capture_is_parsed_by_nexus(self) -> None:
        from nexus_iot.capture import packets

        pcaps = sorted((self.cases["S1"] / "evidence").glob("gateway-*.pcap"))
        count = sum(1 for p in pcaps for _ in packets(p))
        self.assertGreater(count, 0)

    def test_original_copy_matches_sha256sums(self) -> None:
        original = self.cases["S6"] / "original"
        for line in (original / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            name = name.lstrip("*")
            self.assertEqual(hashlib.sha256((original / name).read_bytes()).hexdigest(), digest, name)

    # ---- ground truth -----------------------------------------------------

    def test_truth_format_matches_evaluator(self) -> None:
        truth = json.loads((self.cases["S1"] / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        for key in ("condition", "events", "tampering_seeded", "tamper_mechanisms", "clock_manipulated", "expected_record_count"):
            self.assertIn(key, truth)
        times = [e["timestamp"] for e in truth["events"]]
        self.assertEqual(times, sorted(times))
        self.assertEqual(truth["expected_record_count"], sum(len(e["expected_sources"]) for e in truth["events"]))
        self.assertFalse(truth["tampering_seeded"])

    def test_normal_run_delivers_every_event_to_gateway(self) -> None:
        truth = json.loads((self.cases["S1"] / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        missing = [e["event_id"] for e in truth["events"] if "gateway.jsonl" not in e["expected_sources"]]
        self.assertEqual(missing, [])

    def test_disconnect_leaves_device_only_events(self) -> None:
        truth = json.loads((self.cases["S2"] / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        target = truth["parameters"]["disconnect"]["device"]  # seeded: any of the five devices
        offline = [e for e in truth["events"] if e["device"] == target and "gateway.jsonl" not in e["expected_sources"]]
        self.assertGreater(len(offline), 0, f"disconnect produced no undelivered {target} events")
        others = [e for e in truth["events"] if e["device"] != target and "gateway.jsonl" not in e["expected_sources"]]
        self.assertEqual(others, [], "devices that stayed online lost events")

    # ---- analyzer results -------------------------------------------------

    def test_normal_run_scores_cleanly(self) -> None:
        s = self.scores["S1"]
        self.assertGreaterEqual(s["event_f1"], 0.99)
        self.assertGreaterEqual(s["timing_within_tolerance"], 0.95)
        self.assertFalse(s["tamper_alert"])
        self.assertFalse(s["clock_anomaly_alert"])

    def test_clock_step_is_flagged(self) -> None:
        self.assertTrue(self.scores["S3"]["clock_anomaly_alert"])

    def test_tampering_is_flagged_and_originals_kept(self) -> None:
        self.assertTrue(self.scores["S6"]["tamper_alert"])
        case = self.cases["S6"]
        truth = json.loads((case / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        tampered = sorted({op["file"] for op in truth["parameters"]["tamper"]})  # seeded target files
        changed = [f"{d}.jsonl" for d in DEVICES
                   if (case / "evidence" / f"{d}.jsonl").read_bytes() != (case / "original" / f"{d}.jsonl").read_bytes()]
        self.assertEqual(sorted(changed), tampered)


if __name__ == "__main__":
    unittest.main()
