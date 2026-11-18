"""Tests for testbed.runner.scenarios and testbed.runner.run_scenario (fake Docker, fake clock)."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from testbed.runner import run_scenario
from testbed.runner.run_scenario import analyze_case, execute_scenario, main
from testbed.runner.scenarios import SCENARIOS, Action, Scenario, TamperOp, get_scenarios
from testbed.tests.test_collect import make_fake_run

DEVICE_CONTAINERS = [
    "nexus-tb-door-sensor",
    "nexus-tb-temp-sensor",
    "nexus-tb-smart-plug",
    "nexus-tb-motion-sensor",
    "nexus-tb-smart-lock",
]


class ScenarioTableTests(unittest.TestCase):
    def test_ids_and_titles(self) -> None:
        self.assertEqual(
            {sid: s.title for sid, s in SCENARIOS.items()},
            {
                "S1": "Normal operation",
                "S2": "Device disconnection",
                "S3": "Clock step",
                "S4": "Clock drift",
                "S5": "Capture gap",
                "S6": "Post-collection tampering",
                "S7": "Combined",
            },
        )
        for sid, scenario in SCENARIOS.items():
            self.assertEqual(scenario.id, sid)

    def test_clock_flags(self) -> None:
        flagged = {sid for sid, s in SCENARIOS.items() if s.clock_manipulated}
        self.assertEqual(flagged, {"S3", "S4", "S7"})

    def test_normal_operation_is_empty(self) -> None:
        s1 = SCENARIOS["S1"]
        self.assertEqual((s1.env, s1.actions, s1.tamper), ({}, [], []))

    def test_disconnect_actions(self) -> None:
        self.assertEqual(
            SCENARIOS["S2"].actions,
            [Action(12.0, "disconnect", "nexus-tb-temp-sensor"), Action(22.0, "reconnect", "nexus-tb-temp-sensor")],
        )

    def test_clock_envs(self) -> None:
        self.assertEqual(
            SCENARIOS["S3"].env,
            {"DOOR_CLOCK_OFFSET_S": "5", "DOOR_CLOCK_STEP_AT_S": "20", "DOOR_CLOCK_STEP_S": "90"},
        )
        self.assertEqual(SCENARIOS["S4"].env, {"PLUG_CLOCK_DRIFT_PPM": "5000"})

    def test_capture_gap(self) -> None:
        self.assertEqual(
            [(a.at_s, a.kind) for a in SCENARIOS["S5"].actions],
            [(12.0, "stop_capture"), (22.0, "start_capture")],
        )

    def test_tamper_ops(self) -> None:
        self.assertEqual(
            SCENARIOS["S6"].tamper,
            [
                TamperOp("delete", "smart-plug.jsonl", 3),
                TamperOp("edit", "door-sensor.jsonl", 4, "door_close_forced"),
                TamperOp("insert", "door-sensor.jsonl", 6, "door_open"),
            ],
        )
        for sid in ("S1", "S2", "S3", "S4", "S5"):
            self.assertEqual(SCENARIOS[sid].tamper, [], sid)

    def test_combined_composition(self) -> None:
        s7 = SCENARIOS["S7"]
        self.assertEqual(s7.actions, SCENARIOS["S2"].actions)
        self.assertEqual(s7.env, SCENARIOS["S3"].env)
        self.assertEqual(s7.tamper, SCENARIOS["S6"].tamper)
        self.assertTrue(s7.clock_manipulated)
        self.assertIsNot(s7.env, SCENARIOS["S3"].env, "S7 must not share mutable env with S3")

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            Action(1.0, "explode", None)
        with self.assertRaises(ValueError):
            Action(1.0, "disconnect", "nexus-tb-broker")
        with self.assertRaises(ValueError):
            TamperOp("rewrite", "door-sensor.jsonl", 1)
        with self.assertRaises(ValueError):
            TamperOp("edit", "door-sensor.jsonl", 1)
        with self.assertRaises(ValueError):
            TamperOp("insert", "door-sensor.jsonl", 0)
        with self.assertRaises(ValueError):
            TamperOp("delete", "gateway.jsonl", 1)


class GetScenariosTests(unittest.TestCase):
    def test_all(self) -> None:
        self.assertEqual([s.id for s in get_scenarios(["all"])], ["S1", "S2", "S3", "S4", "S5", "S6", "S7"])

    def test_selection_keeps_order_and_dedupes(self) -> None:
        self.assertEqual([s.id for s in get_scenarios(["S3", "s1", "S3"])], ["S3", "S1"])

    def test_unknown_id(self) -> None:
        with self.assertRaises(ValueError):
            get_scenarios(["S1", "S9"])
        with self.assertRaises(ValueError):
            get_scenarios([])

    def test_without_seed_returns_reference_table(self) -> None:
        self.assertIs(get_scenarios(["S3"])[0], SCENARIOS["S3"])
        self.assertEqual(SCENARIOS["S3"].parameters, {})

    def test_with_seed_returns_seeded_variants(self) -> None:
        seeded = get_scenarios(["all"], seed=7, duration=40.0)
        self.assertEqual([s.id for s in seeded], list(SCENARIOS))
        for scenario in seeded:
            self.assertEqual(scenario.title, SCENARIOS[scenario.id].title)
            self.assertEqual(scenario.clock_manipulated, SCENARIOS[scenario.id].clock_manipulated)
            self.assertEqual(scenario.parameters["seed"], 7)
        with self.assertRaises(ValueError):
            get_scenarios(["S2"], seed=7, duration=10.0)

    def test_new_devices_in_topology(self) -> None:
        self.assertEqual(Action(5.0, "disconnect", "nexus-tb-smart-lock").target, "nexus-tb-smart-lock")
        self.assertEqual(TamperOp("delete", "motion-sensor.jsonl", 1).file, "motion-sensor.jsonl")


# ---------------------------------------------------------------------------
# run_scenario with fakes
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self, start: float = 1_900_000_000.25) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.now += seconds


class FakeDocker:
    """Records calls with the fake time; compose_up writes a fake finished run into RUN_DIR."""

    def __init__(self, clock: FakeClock, fail_on: str | None = None) -> None:
        self.clock = clock
        self.fail_on = fail_on
        self.calls: list[tuple] = []
        self.envs: list[dict] = []
        self.stop_timeouts: list[int | None] = []

    def _record(self, name: str, *args) -> None:
        self.calls.append((name, *args))
        if name == self.fail_on:
            raise RuntimeError(f"fake failure in {name}")

    def compose_build(self, env: dict) -> None:
        self._record("compose_build")

    def compose_up(self, env: dict, build: bool = True) -> None:
        self.envs.append(dict(env))
        self._record("compose_up", build)
        make_fake_run(Path(env["RUN_DIR"]))

    def compose_down(self, env: dict) -> None:
        self._record("compose_down")

    def network_disconnect(self, container: str) -> None:
        self._record("network_disconnect", container, self.clock.now)

    def network_connect(self, container: str, ip: str) -> None:
        self._record("network_connect", container, ip, self.clock.now)

    def stop(self, container: str, timeout: int | None = None) -> None:
        self._record("stop", container, self.clock.now)
        self.stop_timeouts.append(timeout)

    def start(self, container: str) -> None:
        self._record("start", container, self.clock.now)

    def wait(self, container: str, timeout: float) -> int | None:
        self._record("wait", container)
        return 0


class RunScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.clock = FakeClock()
        self.docker = FakeDocker(self.clock)
        self.messages: list[str] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _execute(self, scenario: Scenario, **kwargs) -> Path:
        options = {
            "docker": self.docker,
            "run_id": "r1",
            "duration": 40.0,
            "seed": 7,
            "runs_root": self.root / "runs",
            "cases_root": self.root / "cases",
            "clock": self.clock.time,
            "sleep": self.clock.sleep,
            "log": self.messages.append,
        }
        options.update(kwargs)
        return execute_scenario(scenario, **options)

    def test_call_order_and_action_times(self) -> None:
        start_at = int(self.clock.now) + run_scenario.START_DELAY_S
        # Actions given out of order must still run in time order.
        scenario = Scenario(
            id="S2",
            title="Device disconnection",
            actions=[
                Action(22.0, "reconnect", "nexus-tb-temp-sensor"),
                Action(12.0, "disconnect", "nexus-tb-temp-sensor"),
                Action(15.0, "stop_capture", "nexus-tb-capture"),
            ],
        )
        case = self._execute(scenario)
        self.assertEqual(
            self.docker.calls,
            [
                ("compose_build",),
                ("compose_up", False),
                ("network_disconnect", "nexus-tb-temp-sensor", start_at + 12.0),
                ("stop", "nexus-tb-capture", start_at + 15.0),
                ("network_connect", "nexus-tb-temp-sensor", "172.30.0.22", start_at + 22.0),
                *[("wait", c) for c in DEVICE_CONTAINERS],
                ("stop", "nexus-tb-capture", start_at + 22.0 + run_scenario.CAPTURE_FLUSH_S),
                ("compose_down",),
            ],
        )
        env = self.docker.envs[0]
        self.assertEqual(env["START_AT"], str(start_at))
        self.assertEqual(env["DURATION_S"], "40")
        self.assertEqual(env["SEED"], "7")
        self.assertTrue(Path(env["RUN_DIR"]).is_absolute())

        self.assertEqual(case, self.root / "cases" / "r1" / "S2")
        self.assertTrue((case / "ground_truth" / "truth.json").is_file())
        meta = json.loads((case / "extra" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual([a["kind"] for a in meta["actions_performed"]], ["disconnect", "stop_capture", "reconnect"])
        self.assertEqual(meta["params"]["start_at"], start_at)
        self.assertEqual(meta["device_exit_codes"], {c: 0 for c in DEVICE_CONTAINERS})
        self.assertFalse((self.root / "runs" / "r1" / "S2").exists(), "run dir removed without --keep-run")

    def test_capture_stopped_gracefully_after_devices_and_before_down(self) -> None:
        case = self._execute(SCENARIOS["S1"])
        names = [call[0] for call in self.docker.calls]
        last_wait = max(i for i, name in enumerate(names) if name == "wait")
        self.assertEqual(names[last_wait + 1:], ["stop", "compose_down"])
        stop_call = self.docker.calls[last_wait + 1]
        self.assertEqual(stop_call[1], "nexus-tb-capture")
        # The flush pause comes after every device has exited (the fake wait does not advance the clock).
        self.assertGreaterEqual(run_scenario.CAPTURE_FLUSH_S, 2.0)
        self.assertEqual(stop_call[2], FakeClock().now + run_scenario.CAPTURE_FLUSH_S)
        # docker stop with a SIGTERM grace period, not an immediate kill.
        self.assertEqual(self.docker.stop_timeouts, [run_scenario.CAPTURE_STOP_TIMEOUT_S])
        self.assertGreater(run_scenario.CAPTURE_STOP_TIMEOUT_S, 0)
        meta = json.loads((case / "extra" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["capture_stopped_at"], stop_call[2])

    def test_docker_stop_command_has_grace_period(self) -> None:
        commands: list[list[str]] = []

        def fake_run(args, **kwargs):
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        ops = run_scenario.DockerOps(runner=fake_run)
        ops.stop("nexus-tb-capture", timeout=10)
        ops.stop("nexus-tb-capture")
        self.assertEqual(commands, [["docker", "stop", "-t", "10", "nexus-tb-capture"], ["docker", "stop", "nexus-tb-capture"]])

    def test_scenario_env_passed_and_no_build(self) -> None:
        self._execute(SCENARIOS["S3"], build=False, keep_run=True)
        self.assertEqual(self.docker.calls[0], ("compose_up", False))
        self.assertEqual(self.docker.envs[0]["DOOR_CLOCK_STEP_S"], "90")
        self.assertTrue((self.root / "runs" / "r1" / "S3" / "logs").is_dir(), "--keep-run keeps the run dir")

    def test_down_runs_even_when_action_fails(self) -> None:
        self.docker.fail_on = "network_disconnect"
        with self.assertRaises(RuntimeError):
            self._execute(SCENARIOS["S2"])
        names = [call[0] for call in self.docker.calls]
        self.assertEqual(names, ["compose_build", "compose_up", "network_disconnect", "compose_down"])
        self.assertFalse((self.root / "cases" / "r1" / "S2").exists())

    def test_down_runs_when_wait_fails(self) -> None:
        self.docker.fail_on = "wait"
        with self.assertRaises(RuntimeError):
            self._execute(SCENARIOS["S1"])
        self.assertEqual(self.docker.calls[-1], ("compose_down",))

    def test_actions_beyond_duration_are_skipped(self) -> None:
        self._execute(SCENARIOS["S2"], duration=10.0)
        names = [call[0] for call in self.docker.calls]
        self.assertNotIn("network_disconnect", names)
        self.assertIn("compose_down", names)

    def test_tampered_case(self) -> None:
        case = self._execute(SCENARIOS["S6"])
        self.assertNotEqual(
            (case / "evidence" / "door-sensor.jsonl").read_bytes(),
            (case / "original" / "door-sensor.jsonl").read_bytes(),
        )

    def test_analyze_uses_score_case_with_derived_folder(self) -> None:
        case = self._execute(SCENARIOS["S1"])
        captured: dict = {}

        def fake_score_case(evdir, truth, outdir, case_name, title):
            captured.update(evdir=evdir, truth=truth, outdir=outdir, case=case_name, title=title)
            return {
                "event_f1": 1.0,
                "timing_within_tolerance": 0.95,
                "evidence_completeness": 1.0,
                "tamper_alert": False,
                "clock_anomaly_alert": False,
            }

        fake_module = types.ModuleType("nexus_iot.evaluate")
        fake_module.score_case = fake_score_case
        with mock.patch.dict(sys.modules, {"nexus_iot.evaluate": fake_module}):
            result = analyze_case(case, SCENARIOS["S1"], log=self.messages.append)
        self.assertEqual(result["event_f1"], 1.0)
        self.assertEqual(captured["evdir"], case / "evidence")
        self.assertEqual(captured["outdir"], case / "derived")
        self.assertEqual((captured["case"], captured["title"]), ("S1", "Normal operation"))
        self.assertEqual(captured["truth"]["condition"], "Normal operation")
        summary = self.messages[-1]
        for text in ("F1=1.000", "time<=1s=95.0%", "completeness=100.0%", "tamper_alert=False", "clock_anomaly_alert=False"):
            self.assertIn(text, summary)


class MainTests(unittest.TestCase):
    def test_main_runs_selected_scenarios(self) -> None:
        clock = FakeClock()
        docker = FakeDocker(clock)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            argv = ["S1", "S5", "--no-build", "--duration", "30", "--seed", "3", "--cases-root", str(root / "cases")]
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(argv, docker=docker, clock=clock.time, sleep=clock.sleep, runs_root=root / "runs")
            self.assertEqual(code, 0)
            self.assertEqual(sorted(p.name for p in (root / "cases").glob("*/*")), ["S1", "S5"])
        self.assertEqual(docker.envs[0]["SEED"], "3")
        self.assertEqual(docker.envs[0]["DURATION_S"], "30")
        self.assertEqual([c[0] for c in docker.calls].count("compose_down"), 2)
        # S5 is seeded: the capture gap comes from seed 3, not the reference 12..22 s.
        from testbed.runner.variation import build_scenario

        gap = build_scenario("S5", 3, 30.0).parameters["capture_gap"]
        stops = [c for c in docker.calls if c[0] in ("stop", "start")]
        start_at = int(docker.envs[1]["START_AT"])
        # S1 and S5 each end with the graceful capture stop; S5's gap actions sit between them.
        gap_calls = stops[1:3]
        self.assertEqual([c[0] for c in gap_calls], ["stop", "start"])
        self.assertEqual([round(c[2] - start_at, 6) for c in gap_calls], [gap["start_s"], gap["end_s"]])
        self.assertEqual(len(stops), 4)

    def test_unknown_scenario_exit_code(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["S9"], docker=FakeDocker(FakeClock())), 2)


if __name__ == "__main__":
    unittest.main()
