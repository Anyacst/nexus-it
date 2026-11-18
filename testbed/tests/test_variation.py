"""Tests for testbed.runner.variation: seeded scenario parameters (no Docker).

The bounds checks use the real device schedule (devicecore.schedule) for the
same seed, so they prove the faults fit what the devices will actually do.
"""
from __future__ import annotations

import json
import unittest

from testbed.device.devicecore import schedule
from testbed.runner.scenarios import CAPTURE_CONTAINER, DEVICE_CONTAINERS, ENV_PREFIXES, SCENARIOS, TamperOp
from testbed.runner.tamper import tamper_lines
from testbed.runner.variation import (
    CLOCK_ANCHORS_PER_SIDE,
    EDGE_MARGIN_S,
    build_scenario,
    derive_parameters,
    guaranteed_record_count,
)

SEEDS = range(0, 201)
DURATIONS = (30.0, 45.0, 60.0, 120.0)
SCENARIO_IDS = tuple(SCENARIOS)


def _offsets(device: str, duration: float, seed: int) -> list[float]:
    return [entry["offset_s"] for entry in schedule(device, duration, seed)]


def _is_tenth(value: float) -> bool:
    return abs(value * 10 - round(value * 10)) < 1e-9


class DeterminismTests(unittest.TestCase):
    def test_same_seed_same_parameters(self) -> None:
        for sid in SCENARIO_IDS:
            for seed in (0, 7, 123):
                self.assertEqual(derive_parameters(sid, seed, 45.0), derive_parameters(sid, seed, 45.0), (sid, seed))
                self.assertEqual(build_scenario(sid, seed, 45.0), build_scenario(sid, seed, 45.0), (sid, seed))

    def test_parameters_differ_across_seeds(self) -> None:
        for sid in ("S2", "S3", "S4", "S5", "S6", "S7"):
            variants = {json.dumps(build_scenario(sid, seed, 45.0).parameters | {"seed": None}, sort_keys=True) for seed in SEEDS}
            # Effectively every seed gives a new variant (a few collisions are allowed for coarse grids).
            self.assertGreater(len(variants), 150, sid)

    def test_scenarios_use_independent_streams(self) -> None:
        # S7's clock step is not a copy of S3's for the same seed.
        same = sum(
            build_scenario("S7", seed, 45.0).parameters["clock_step"] == build_scenario("S3", seed, 45.0).parameters["clock_step"]
            for seed in SEEDS
        )
        self.assertLess(same, 5)

    def test_default_seed_gives_valid_s1_to_s7(self) -> None:
        for sid in SCENARIO_IDS:
            scenario = build_scenario(sid, 7, 40.0)
            self.assertEqual(scenario.id, sid)
            self.assertEqual(scenario.title, SCENARIOS[sid].title)
            self.assertEqual(scenario.clock_manipulated, SCENARIOS[sid].clock_manipulated)
            self.assertEqual(bool(scenario.tamper), bool(SCENARIOS[sid].tamper))
            self.assertEqual(scenario.parameters["seed"], 7)
            json.dumps(scenario.parameters)

    def test_s1_has_no_faults(self) -> None:
        scenario = build_scenario("S1", 7, 40.0)
        self.assertEqual((scenario.env, scenario.actions, scenario.tamper), ({}, [], []))
        self.assertEqual(scenario.parameters, {"seed": 7, "duration_s": 40.0})

    def test_invalid_inputs(self) -> None:
        with self.assertRaises(ValueError):
            derive_parameters("S9", 7, 40.0)
        with self.assertRaises(ValueError):
            derive_parameters("S2", 7, 29.9)


class BoundsTests(unittest.TestCase):
    """Property-style: every seed 0..200 at several durations stays inside the documented bounds."""

    def check_disconnect(self, params: dict, duration: float, seed: int) -> None:
        d = params["disconnect"]
        self.assertEqual(d["container"], DEVICE_CONTAINERS[d["device"]])
        self.assertGreaterEqual(d["start_s"], EDGE_MARGIN_S)
        self.assertLessEqual(d["end_s"], duration - EDGE_MARGIN_S)
        self.assertTrue(_is_tenth(d["start_s"]) and _is_tenth(d["end_s"]))
        offline = [o for o in _offsets(d["device"], duration, seed) if d["start_s"] <= o < d["end_s"]]
        self.assertGreaterEqual(len(offline), 1, "the disconnect window must cover at least one event")

    def check_clock_step(self, params: dict, duration: float, seed: int) -> None:
        c = params["clock_step"]
        self.assertLessEqual(abs(c["offset_s"]), 10.0)
        self.assertTrue(5.0 <= abs(c["step_s"]) <= 120.0)
        self.assertTrue(0 < c["step_at_s"] < duration)
        offsets = _offsets(c["device"], duration, seed)[1:]  # boot excluded
        before = [o for o in offsets if o < c["step_at_s"]]
        after = [o for o in offsets if o >= c["step_at_s"]]
        self.assertGreaterEqual(len(before), CLOCK_ANCHORS_PER_SIDE)
        self.assertGreaterEqual(len(after), CLOCK_ANCHORS_PER_SIDE)
        # Real sleeps wake late, never early: keep a margin before the step for the last pre-step event.
        self.assertLess(before[CLOCK_ANCHORS_PER_SIDE - 1], c["step_at_s"] - 0.25)

    def check_capture_gap(self, params: dict, duration: float) -> None:
        g = params["capture_gap"]
        self.assertGreaterEqual(g["start_s"], EDGE_MARGIN_S)
        self.assertLessEqual(g["end_s"], duration - EDGE_MARGIN_S)
        self.assertTrue(5.0 <= round(g["end_s"] - g["start_s"], 6) <= 15.0)

    def check_tamper(self, tamper: list[dict], duration: float, seed: int) -> None:
        self.assertEqual([op["kind"] for op in tamper], ["delete", "edit", "insert"])
        self.assertNotEqual(tamper[0]["file"], tamper[1]["file"])
        self.assertEqual(tamper[1]["file"], tamper[2]["file"])
        for op in tamper:
            device = op["file"].removesuffix(".jsonl")
            actual_lines = len(schedule(device, duration, seed))
            self.assertLessEqual(guaranteed_record_count(device, duration), actual_lines)
            self.assertTrue(1 <= op["index"] < actual_lines, op)
        edit, insert = tamper[1], tamper[2]
        self.assertGreaterEqual(insert["index"], 2)
        self.assertNotIn(insert["index"], (edit["index"], edit["index"] + 1))

    def test_all_seeds_within_bounds(self) -> None:
        for duration in DURATIONS:
            for seed in SEEDS:
                for sid in SCENARIO_IDS:
                    with self.subTest(duration=duration, seed=seed, sid=sid):
                        scenario = build_scenario(sid, seed, duration)
                        params = scenario.parameters
                        for action in scenario.actions:
                            self.assertTrue(0 < action.at_s < duration)
                        if "disconnect" in params:
                            self.check_disconnect(params, duration, seed)
                        if "clock_step" in params:
                            self.check_clock_step(params, duration, seed)
                        if "clock_drift" in params:
                            self.assertTrue(2000 <= abs(params["clock_drift"]["drift_ppm"]) <= 20000)
                        if "capture_gap" in params:
                            self.check_capture_gap(params, duration)
                        if "tamper" in params:
                            self.check_tamper(params["tamper"], duration, seed)
                        if sid == "S7":
                            self.assertNotEqual(params["disconnect"]["device"], params["clock_step"]["device"])

    def test_tamper_ops_apply_to_real_line_counts(self) -> None:
        for seed in range(0, 60):
            for sid in ("S6", "S7"):
                ops = build_scenario(sid, seed, 30.0).tamper
                by_file: dict[str, list[TamperOp]] = {}
                for op in ops:
                    by_file.setdefault(op.file, []).append(op)
                for file_name, file_ops in by_file.items():
                    device = file_name.removesuffix(".jsonl")
                    entries = schedule(device, 30.0, seed)
                    lines = [json.dumps({"event_id": f"{device}-{i:05d}", "sequence": i, "event": e["event"],
                                         "timestamp": e["offset_s"]}) for i, e in enumerate(entries, start=1)]
                    new_lines, _ = tamper_lines(lines, file_ops, device)  # raises if an index is invalid
                    for op in file_ops:
                        if op.kind == "edit":
                            self.assertNotEqual(op.new_event, entries[op.index]["event"])
                        if op.kind == "insert":
                            self.assertEqual(op.new_event, entries[op.index - 1]["event"])
                    self.assertTrue(new_lines)


class ScenarioMappingTests(unittest.TestCase):
    def test_env_and_actions_follow_parameters(self) -> None:
        for seed in range(0, 50):
            s3 = build_scenario("S3", seed, 45.0)
            step = s3.parameters["clock_step"]
            prefix = ENV_PREFIXES[step["device"]]
            self.assertEqual(set(s3.env), {f"{prefix}_CLOCK_OFFSET_S", f"{prefix}_CLOCK_STEP_AT_S", f"{prefix}_CLOCK_STEP_S"})
            self.assertEqual(float(s3.env[f"{prefix}_CLOCK_STEP_S"]), step["step_s"])
            self.assertEqual(float(s3.env[f"{prefix}_CLOCK_STEP_AT_S"]), step["step_at_s"])

            s4 = build_scenario("S4", seed, 45.0)
            drift = s4.parameters["clock_drift"]
            self.assertEqual(s4.env, {f"{ENV_PREFIXES[drift['device']]}_CLOCK_DRIFT_PPM": str(drift["drift_ppm"])})

            s2 = build_scenario("S2", seed, 45.0)
            d = s2.parameters["disconnect"]
            self.assertEqual([(a.at_s, a.kind, a.target) for a in s2.actions],
                             [(d["start_s"], "disconnect", d["container"]), (d["end_s"], "reconnect", d["container"])])

            s5 = build_scenario("S5", seed, 45.0)
            self.assertEqual([a.target for a in s5.actions], [CAPTURE_CONTAINER, CAPTURE_CONTAINER])

            s7 = build_scenario("S7", seed, 45.0)
            self.assertTrue(s7.clock_manipulated)
            self.assertEqual(len(s7.actions), 2)
            self.assertEqual(len(s7.tamper), 3)

    def test_every_device_is_used(self) -> None:
        disconnected = {build_scenario("S2", seed, 45.0).parameters["disconnect"]["device"] for seed in SEEDS}
        stepped = {build_scenario("S3", seed, 45.0).parameters["clock_step"]["device"] for seed in SEEDS}
        drifted = {build_scenario("S4", seed, 45.0).parameters["clock_drift"]["device"] for seed in SEEDS}
        for used in (disconnected, stepped, drifted):
            self.assertEqual(used, set(DEVICE_CONTAINERS))

    def test_step_sign_varies(self) -> None:
        signs = {build_scenario("S3", seed, 45.0).parameters["clock_step"]["step_s"] > 0 for seed in SEEDS}
        self.assertEqual(signs, {True, False})


if __name__ == "__main__":
    unittest.main()
