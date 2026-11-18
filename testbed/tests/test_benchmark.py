"""Tests for testbed.runner.benchmark: pure aggregation, Markdown rendering and the CLI with fakes."""
from __future__ import annotations

import contextlib
import io
import json
import math
import statistics
import tempfile
import time
import unittest
from pathlib import Path

from testbed.runner import benchmark
from testbed.runner.benchmark import (
    SUMMARY_METRICS,
    alert_summary,
    build_metrics,
    describe,
    describe_parameters,
    format_stat,
    per_scenario_summary,
    render_markdown,
)
from testbed.runner.scenarios import DEVICE_CONTAINERS, SCENARIOS
from testbed.runner.variation import build_scenario, guaranteed_record_count
from testbed.tests.test_collect import make_fake_run
from testbed.tests.test_scenarios import FakeClock, FakeDocker


def score(f1: float = 1.0, tamper: bool = False, clock: bool = False, **extra) -> dict:
    """A score dict with the keys the benchmark reads."""
    base = {key: f1 for key, _ in SUMMARY_METRICS}
    base.update(tamper_alert=tamper, clock_anomaly_alert=clock, median_absolute_time_error_seconds=0.01)
    base.update(extra)
    return base


def row(sid: str, seed: int, status: str = "ok", tampered: bool = False, clocked: bool = False, **score_kwargs) -> dict:
    return {
        "scenario_id": sid,
        "title": SCENARIOS[sid].title if sid in SCENARIOS else sid,
        "seed": seed,
        "status": status,
        "tampering_seeded": tampered,
        "clock_manipulated": clocked,
        "parameters": {},
        "wall_seconds": 1.0,
        "case_dir": None,
        "score": score(**score_kwargs) if status == "ok" else {},
        "error": None if status == "ok" else "RuntimeError: boom",
    }


class DescribeTests(unittest.TestCase):
    def test_mean_sample_std_min(self) -> None:
        stat = describe([0.9, 1.0, 0.8])
        self.assertEqual(stat["n"], 3)
        self.assertAlmostEqual(stat["mean"], 0.9)
        self.assertAlmostEqual(stat["std"], statistics.stdev([0.9, 1.0, 0.8]))
        self.assertAlmostEqual(stat["std"], 0.1)
        self.assertEqual(stat["min"], 0.8)

    def test_single_value_has_no_std(self) -> None:
        self.assertEqual(describe([0.5]), {"n": 1, "mean": 0.5, "std": None, "min": 0.5})

    def test_empty_and_non_numeric_values(self) -> None:
        self.assertEqual(describe([]), {"n": 0, "mean": None, "std": None, "min": None})
        self.assertEqual(describe([None, True, math.nan, "x"])["n"], 0)
        self.assertEqual(describe([None, 1.0, 0.0])["n"], 2)

    def test_identical_values_zero_std(self) -> None:
        self.assertEqual(describe([1.0, 1.0, 1.0])["std"], 0.0)

    def test_format_stat(self) -> None:
        self.assertEqual(format_stat(describe([0.9, 1.0, 0.8])), "0.900 ± 0.100 (min 0.800)")
        self.assertEqual(format_stat(describe([0.5])), "0.500 (min 0.500)")
        self.assertEqual(format_stat(describe([])), "n/a")


class PerScenarioTests(unittest.TestCase):
    def test_failed_runs_counted_but_excluded(self) -> None:
        rows = [row("S1", 1, f1=1.0), row("S1", 2, f1=0.8), row("S1", 3, status="failed"), row("S2", 1, f1=0.5)]
        summary = per_scenario_summary(rows)
        self.assertEqual(list(summary), ["S1", "S2"])
        s1 = summary["S1"]
        self.assertEqual((s1["runs"], s1["successful_runs"], s1["failed_runs"]), (3, 2, 1))
        self.assertEqual(s1["seeds"], [1, 2, 3])
        self.assertAlmostEqual(s1["metrics"]["event_f1"]["mean"], 0.9)
        self.assertAlmostEqual(s1["metrics"]["event_f1"]["std"], statistics.stdev([1.0, 0.8]))
        self.assertEqual(s1["metrics"]["event_f1"]["min"], 0.8)
        self.assertEqual(set(s1["metrics"]), {key for key, _ in SUMMARY_METRICS})
        self.assertIsNone(summary["S2"]["metrics"]["event_recall"]["std"])

    def test_all_failed_scenario(self) -> None:
        summary = per_scenario_summary([row("S3", 1, status="failed")])
        self.assertEqual(summary["S3"]["metrics"]["event_f1"], {"n": 0, "mean": None, "std": None, "min": None})


class AlertSummaryTests(unittest.TestCase):
    def test_rates(self) -> None:
        rows = [
            row("S6", 1, tampered=True, tamper=True),
            row("S6", 2, tampered=True, tamper=False),
            row("S7", 1, tampered=True, tamper=True),
            row("S1", 1, tamper=True),
            row("S2", 1),
            row("S3", 1),
            row("S4", 1),
            row("S6", 3, status="failed", tampered=True),
        ]
        result = alert_summary(rows, "tampering_seeded", "tamper_alert")
        self.assertEqual(
            result,
            {
                "positive_runs": 3,
                "negative_runs": 4,
                "true_positives": 2,
                "false_positives": 1,
                "false_negatives": 1,
                "true_negatives": 3,
                "recall": 2 / 3,
                "false_positive_rate": 1 / 4,
                "precision": 2 / 3,
            },
        )

    def test_zero_division_cases(self) -> None:
        no_positives = alert_summary([row("S1", 1), row("S2", 1)], "clock_manipulated", "clock_anomaly_alert")
        self.assertIsNone(no_positives["recall"])
        self.assertEqual(no_positives["false_positive_rate"], 0.0)
        self.assertIsNone(no_positives["precision"], "no alerts at all: precision undefined")

        no_negatives = alert_summary([row("S3", 1, clocked=True)], "clock_manipulated", "clock_anomaly_alert")
        self.assertEqual(no_negatives["recall"], 0.0)
        self.assertIsNone(no_negatives["false_positive_rate"])
        self.assertIsNone(no_negatives["precision"])

        empty = alert_summary([row("S3", 1, status="failed", clocked=True)], "clock_manipulated", "clock_anomaly_alert")
        self.assertEqual((empty["positive_runs"], empty["negative_runs"]), (0, 0))
        self.assertIsNone(empty["recall"])
        self.assertIsNone(empty["false_positive_rate"])

    def test_missing_alert_key_counts_as_no_alert(self) -> None:
        r = row("S3", 1, clocked=True)
        del r["score"]["clock_anomaly_alert"]
        self.assertEqual(alert_summary([r], "clock_manipulated", "clock_anomaly_alert")["true_positives"], 0)


class MetricsAndMarkdownTests(unittest.TestCase):
    def make_metrics(self) -> dict:
        rows = []
        for seed in (1, 2):
            for sid, scenario in SCENARIOS.items():
                r = row(sid, seed, tampered=bool(scenario.tamper), clocked=scenario.clock_manipulated, f1=0.9 + seed / 100)
                r["parameters"] = build_scenario(sid, seed, 40.0).parameters
                rows.append(r)
        rows.append(row("S2", 3, status="failed"))
        return build_metrics(
            rows,
            benchmark_id="bench-test",
            config={"seeds": [1, 2, 3], "scenarios": list(SCENARIOS), "duration_s": 40.0},
            wall_seconds=123.4,
            created_at="2026-01-01T00:00:00+00:00",
        )

    def test_counts(self) -> None:
        metrics = self.make_metrics()
        self.assertEqual((metrics["total_runs"], metrics["successful_runs"], metrics["failed_runs"]), (15, 14, 1))
        self.assertEqual(metrics["per_scenario"]["S2"]["failed_runs"], 1)
        self.assertEqual(metrics["alerts"]["tamper"]["positive_runs"], 4)
        self.assertEqual(metrics["alerts"]["clock"]["positive_runs"], 6)
        self.assertTrue(metrics["limits"])
        json.dumps(metrics)

    def test_markdown_contains_every_scenario_and_sections(self) -> None:
        text = render_markdown(self.make_metrics())
        for sid, scenario in SCENARIOS.items():
            self.assertIn(f"| {sid} | {scenario.title} |", text)
        for heading in ("## Per-scenario summary", "## Alert detection", "## Runs", "## Failed runs", "## Limits"):
            self.assertIn(heading, text)
        self.assertIn("| tamper |", text)
        self.assertIn("| clock |", text)
        self.assertIn("RuntimeError: boom", text)
        self.assertIn("0.915 ± 0.007 (min 0.910)", text)

    def test_describe_parameters(self) -> None:
        self.assertEqual(describe_parameters({"seed": 1}), "none")
        text = describe_parameters(
            {
                "disconnect": {"device": "smart-lock", "container": "x", "start_s": 6.5, "end_s": 20.0},
                "clock_step": {"device": "door-sensor", "offset_s": -1.5, "step_at_s": 20.9, "step_s": -71.8},
                "clock_drift": {"device": "motion-sensor", "drift_ppm": 4000},
                "capture_gap": {"start_s": 7.0, "end_s": 12.5},
                "tamper": [{"kind": "edit", "file": "smart-plug.jsonl", "index": 3, "new_event": "plug_on"}],
            }
        )
        for part in ("disconnect smart-lock 6.5-20s", "step door-sensor -71.8s at 20.9s, offset -1.5s",
                     "drift motion-sensor +4000 ppm", "capture gap 7-12.5s", "edit smart-plug[3]->plug_on"):
            self.assertIn(part, text)


class DurationFakeDocker(FakeDocker):
    """FakeDocker whose fake device logs are long enough for the seeded tamper indices."""

    def compose_up(self, env: dict, build: bool = True) -> None:
        self.envs.append(dict(env))
        self._record("compose_up", build)
        duration = float(env["DURATION_S"])
        counts = {device: guaranteed_record_count(device, duration) for device in DEVICE_CONTAINERS}
        make_fake_run(Path(env["RUN_DIR"]), counts=counts)


class BenchmarkCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.clock = FakeClock()
        self.docker = DurationFakeDocker(self.clock)
        self.scored: list[tuple[str, dict]] = []
        self.messages: list[str] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def fake_score(self, evdir: Path, truth: dict, outdir: Path, case: str, title: str) -> dict:
        self.scored.append((case, truth))
        if case == "S4" and truth["parameters"]["seed"] == 2:
            raise RuntimeError("analyzer crashed")
        return score(f1=0.95, tamper=truth["tampering_seeded"], clock=False, unrelated_key="ignored")

    def run_main(self, *extra: str) -> int:
        argv = ["--seeds", "1", "2", "--scenarios", "all", "--duration", "30", "--no-build",
                "--out", str(self.root / "results"), "--cases-root", str(self.root / "cases"), *extra]
        return benchmark.main(
            argv,
            docker=self.docker,
            score_fn=self.fake_score,
            clock=self.clock.time,
            sleep=self.clock.sleep,
            runs_root=self.root / "runs",
            log=self.messages.append,
        )

    def test_cli_writes_both_files_and_survives_a_failure(self) -> None:
        started = time.monotonic()
        code = self.run_main()
        self.assertLess(time.monotonic() - started, 30.0)
        self.assertEqual(code, 1, "a failed run gives exit code 1")

        out_dirs = list((self.root / "results").iterdir())
        self.assertEqual(len(out_dirs), 1)
        self.assertTrue(out_dirs[0].name.startswith("bench-"))
        metrics = json.loads((out_dirs[0] / "metrics.json").read_text(encoding="utf-8"))
        markdown = (out_dirs[0] / "metrics.md").read_text(encoding="utf-8")

        self.assertEqual((metrics["total_runs"], metrics["successful_runs"], metrics["failed_runs"]), (14, 13, 1))
        self.assertEqual([(r["seed"], r["scenario_id"]) for r in metrics["runs"]][:8],
                         [(1, sid) for sid in SCENARIOS] + [(2, "S1")])
        failed = [r for r in metrics["runs"] if r["status"] == "failed"]
        self.assertEqual([(r["scenario_id"], r["seed"]) for r in failed], [("S4", 2)])
        self.assertIn("analyzer crashed", failed[0]["error"])
        ok = [r for r in metrics["runs"] if r["status"] == "ok"]
        self.assertNotIn("unrelated_key", ok[0]["score"])
        self.assertEqual(metrics["alerts"]["tamper"]["recall"], 1.0)
        self.assertEqual(metrics["alerts"]["tamper"]["false_positive_rate"], 0.0)
        self.assertEqual(metrics["alerts"]["clock"]["recall"], 0.0)
        self.assertIsNone(metrics["alerts"]["clock"]["precision"])
        self.assertEqual(metrics["per_scenario"]["S4"]["successful_runs"], 1)
        for sid in SCENARIOS:
            self.assertIn(f"| {sid} |", markdown)

        # Truth carries the seeded parameters; cases are grouped by benchmark and seed.
        self.assertEqual(len(self.scored), 14)
        s2_truth = next(t for case, t in self.scored if case == "S2" and t["parameters"]["seed"] == 1)
        self.assertEqual(s2_truth["parameters"], build_scenario("S2", 1, 30.0).parameters)
        self.assertTrue((self.root / "cases" / out_dirs[0].name / "seed-1" / "S2" / "ground_truth" / "truth.json").is_file())
        names = [call[0] for call in self.docker.calls]
        self.assertNotIn("compose_build", names)
        self.assertEqual(names.count("compose_down"), 14)

    def test_docker_failure_is_recorded_not_raised(self) -> None:
        self.docker.fail_on = "network_disconnect"
        code = self.run_main("--seeds", "3")
        self.assertEqual(code, 1)
        out_dir = next((self.root / "results").iterdir())
        metrics = json.loads((out_dir / "metrics.json").read_text(encoding="utf-8"))
        failed = {r["scenario_id"] for r in metrics["runs"] if r["status"] == "failed"}
        self.assertEqual(failed, {"S2", "S7"})
        self.assertEqual(metrics["total_runs"], 7, "the later --seeds 3 replaces --seeds 1 2")

    def test_build_runs_once(self) -> None:
        argv = ["--seeds", "1", "--scenarios", "S1", "S5", "--duration", "30",
                "--out", str(self.root / "results"), "--cases-root", str(self.root / "cases")]
        code = benchmark.main(argv, docker=self.docker, score_fn=self.fake_score, clock=self.clock.time,
                              sleep=self.clock.sleep, runs_root=self.root / "runs", log=self.messages.append)
        self.assertEqual(code, 0)
        self.assertEqual([c[0] for c in self.docker.calls].count("compose_build"), 1)
        self.assertEqual(self.docker.calls[0][0], "compose_build")

    def test_invalid_arguments(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_main("--duration", "10"), 2)
            self.assertEqual(self.run_main("--scenarios", "S9"), 2)
        self.assertFalse((self.root / "results").exists())


if __name__ == "__main__":
    unittest.main()
