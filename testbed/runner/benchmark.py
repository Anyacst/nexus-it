"""CLI: run every scenario x seed in Docker, score each case, and aggregate the results.

    python -m testbed.runner.benchmark --seeds 1 2 3 --scenarios all --duration 60
        [--out testbed/results] [--cases-root testbed/cases] [--no-build]

Writes <out>/<benchmark_id>/metrics.json and metrics.md (rewritten after every run,
so a long benchmark leaves usable partial results). A failed run is recorded as
failed and the benchmark continues. The aggregation functions are pure and take
plain run dicts, so they can be tested without Docker.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .run_scenario import DEFAULT_CASES_ROOT, DEFAULT_RUNS_ROOT, REPO_ROOT, DockerOps, execute_scenario
from .scenarios import get_scenarios
from .variation import build_scenario

DEFAULT_OUT = REPO_ROOT / "testbed" / "results"
DEFAULT_SEEDS = (1, 2, 3)
DEFAULT_DURATION_S = 60.0
METRICS_JSON = "metrics.json"
METRICS_MD = "metrics.md"
STATUS_OK = "ok"
STATUS_FAILED = "failed"

# (score key, column label) of the metrics summarised per scenario across seeds.
SUMMARY_METRICS: tuple[tuple[str, str], ...] = (
    ("event_f1", "Event F1"),
    ("event_precision", "Precision"),
    ("event_recall", "Recall"),
    ("timing_within_tolerance", "Time <= 1 s"),
    ("evidence_completeness", "Completeness"),
    ("unknown_gap_precision", "Gap precision"),
    ("unknown_gap_recall", "Gap recall"),
)

# Every score_case key the benchmark keeps per run (nothing else is relied upon).
RUN_SCORE_KEYS: tuple[str, ...] = tuple(key for key, _ in SUMMARY_METRICS) + (
    "true_positive_events",
    "false_positive_events",
    "missed_events",
    "median_absolute_time_error_seconds",
    "maximum_absolute_time_error_seconds",
    "processing_seconds",
    "tamper_alert",
    "clock_anomaly_alert",
)

# (name, truth flag that makes a run positive, score key of the alert)
ALERTS: tuple[tuple[str, str, str], ...] = (
    ("tamper", "tampering_seeded", "tamper_alert"),
    ("clock", "clock_manipulated", "clock_anomaly_alert"),
)

LIMITS: tuple[str, ...] = (
    "Synthetic testbed: simulated devices publish scripted telemetry on a closed Docker network; "
    "scores describe tool behaviour on this testbed, not on real IoT hardware or traffic.",
    "All containers share the host clock. Device clock faults (offset, drift, step) are simulated in software "
    "and the gateway clock is taken as true time.",
    "Small samples: each scenario is run once per seed, so a std over a few seeds is a rough spread, "
    "not a confidence interval. Alert rates are per run (scenario level), not per event.",
    "Seeds vary fault parameters, device jitter and values; the seven fault families are fixed and only S7 combines faults.",
    "Ground truth for delivery comes from the pre-tamper gateway log, so a missed source row means one the gateway "
    "actually logged. Docker timing (disconnect detection, reconnect delay) adds variance the seed does not control.",
    "Clock steps may be negative (clock set back). Backward device timestamps can also be read as tampering; "
    "such an alert counts as a tamper false positive here.",
)

ScoreFn = Callable[[Path, dict, Path, str, str], dict]


@dataclass
class RunResult:
    """Outcome of one scenario x seed run."""

    scenario_id: str
    title: str
    seed: int
    status: str
    tampering_seeded: bool
    clock_manipulated: bool
    parameters: dict = field(default_factory=dict)
    wall_seconds: float = 0.0
    case_dir: str | None = None
    score: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Pure aggregation (input: run dicts as produced by RunResult.to_dict)
# ---------------------------------------------------------------------------


def select_score(score: dict) -> dict:
    """Keep only the score keys the benchmark relies on (missing keys become None)."""
    return {key: score.get(key) for key in RUN_SCORE_KEYS}


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def describe(values: Iterable[object]) -> dict:
    """n, mean, sample std (n-1; None for n < 2) and min of the numeric values; non-numbers are skipped."""
    numbers = [float(v) for v in values if _is_number(v)]
    if not numbers:
        return {"n": 0, "mean": None, "std": None, "min": None}
    return {
        "n": len(numbers),
        "mean": statistics.fmean(numbers),
        "std": statistics.stdev(numbers) if len(numbers) >= 2 else None,
        "min": min(numbers),
    }


def successful(rows: Iterable[dict]) -> list[dict]:
    """Runs that finished and were scored."""
    return [row for row in rows if row.get("status") == STATUS_OK]


def per_scenario_summary(rows: list[dict]) -> dict[str, dict]:
    """Per scenario (in first-seen order): run counts and describe() of every SUMMARY_METRICS key.

    Failed runs are counted but excluded from the statistics.
    """
    summary: dict[str, dict] = {}
    for row in rows:
        entry = summary.setdefault(
            row["scenario_id"],
            {"title": row.get("title", ""), "runs": 0, "successful_runs": 0, "failed_runs": 0, "seeds": [], "_ok": []},
        )
        entry["runs"] += 1
        entry["seeds"].append(row.get("seed"))
        if row.get("status") == STATUS_OK:
            entry["successful_runs"] += 1
            entry["_ok"].append(row)
        else:
            entry["failed_runs"] += 1
    for entry in summary.values():
        ok_rows = entry.pop("_ok")
        entry["metrics"] = {key: describe(row["score"].get(key) for row in ok_rows) for key, _ in SUMMARY_METRICS}
    return summary


def alert_summary(rows: list[dict], positive_key: str, alert_key: str) -> dict:
    """Scenario-level detection rates over successful runs.

    A run is positive when ``row[positive_key]`` is true; it is alerted when
    ``row["score"][alert_key]`` is true. Recall, false-positive rate and precision
    are None when their denominator is zero.
    """
    ok_rows = successful(rows)
    positives = [row for row in ok_rows if row.get(positive_key)]
    negatives = [row for row in ok_rows if not row.get(positive_key)]
    tp = sum(1 for row in positives if row["score"].get(alert_key))
    fp = sum(1 for row in negatives if row["score"].get(alert_key))
    return {
        "positive_runs": len(positives),
        "negative_runs": len(negatives),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": len(positives) - tp,
        "true_negatives": len(negatives) - fp,
        "recall": tp / len(positives) if positives else None,
        "false_positive_rate": fp / len(negatives) if negatives else None,
        "precision": tp / (tp + fp) if tp + fp else None,
    }


def build_metrics(rows: list[dict], *, benchmark_id: str, config: dict, wall_seconds: float, created_at: str) -> dict:
    """The full metrics.json payload."""
    ok_count = len(successful(rows))
    return {
        "benchmark_id": benchmark_id,
        "created_at": created_at,
        "config": config,
        "total_runs": len(rows),
        "successful_runs": ok_count,
        "failed_runs": len(rows) - ok_count,
        "wall_seconds": wall_seconds,
        "per_scenario": per_scenario_summary(rows),
        "alerts": {name: alert_summary(rows, positive, alert) for name, positive, alert in ALERTS},
        "runs": rows,
        "limits": list(LIMITS),
    }


# ---------------------------------------------------------------------------
# Markdown rendering (pure)
# ---------------------------------------------------------------------------


def _num(value: object, digits: int = 3) -> str:
    return f"{value:.{digits}f}" if _is_number(value) else "n/a"


def format_stat(stat: dict) -> str:
    """'mean ± std (min x)'; std omitted for n < 2; 'n/a' without values."""
    if not stat.get("n"):
        return "n/a"
    spread = f" ± {_num(stat['std'])}" if stat.get("std") is not None else ""
    return f"{_num(stat['mean'])}{spread} (min {_num(stat['min'])})"


def _signed(value: float, unit: str) -> str:
    return f"{value:+g}{unit}"


def describe_parameters(parameters: dict) -> str:
    """One-line human summary of a run's seeded fault parameters."""
    parts: list[str] = []
    if "disconnect" in parameters:
        d = parameters["disconnect"]
        parts.append(f"disconnect {d['device']} {d['start_s']:g}-{d['end_s']:g}s")
    if "clock_step" in parameters:
        c = parameters["clock_step"]
        parts.append(f"step {c['device']} {_signed(c['step_s'], 's')} at {c['step_at_s']:g}s, offset {_signed(c['offset_s'], 's')}")
    if "clock_drift" in parameters:
        c = parameters["clock_drift"]
        parts.append(f"drift {c['device']} {_signed(c['drift_ppm'], ' ppm')}")
    if "capture_gap" in parameters:
        g = parameters["capture_gap"]
        parts.append(f"capture gap {g['start_s']:g}-{g['end_s']:g}s")
    for op in parameters.get("tamper", []):
        target = f"{op['file'].removesuffix('.jsonl')}[{op['index']}]"
        suffix = f"->{op['new_event']}" if op["kind"] == "edit" else ""
        parts.append(f"{op['kind']} {target}{suffix}")
    return "; ".join(parts) or "none"


def _md(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _flag(value: object) -> str:
    if value is None:
        return "n/a"
    return "yes" if value else "no"


def render_markdown(metrics: dict) -> str:
    """Render metrics.json as a readable Markdown report."""
    config = metrics["config"]
    lines = [
        f"# NEXUS-IoT testbed benchmark `{metrics['benchmark_id']}`",
        "",
        f"- Created: {metrics['created_at']}",
        f"- Seeds: {', '.join(str(s) for s in config.get('seeds', []))}",
        f"- Scenarios: {', '.join(config.get('scenarios', []))}",
        f"- Duration per run: {config.get('duration_s', 0):g} s",
        f"- Runs: {metrics['total_runs']} total, {metrics['successful_runs']} scored, {metrics['failed_runs']} failed",
        f"- Wall time: {metrics['wall_seconds']:.0f} s",
        "",
        "## Per-scenario summary",
        "",
        "Mean ± sample std (min) across seeds; failed runs excluded.",
        "",
        "| Scenario | Title | Runs ok/total | " + " | ".join(label for _, label in SUMMARY_METRICS) + " |",
        "| --- | --- | --- | " + " | ".join("---" for _ in SUMMARY_METRICS) + " |",
    ]
    for sid, entry in metrics["per_scenario"].items():
        cells = [format_stat(entry["metrics"][key]) for key, _ in SUMMARY_METRICS]
        lines.append(f"| {sid} | {_md(entry['title'])} | {entry['successful_runs']}/{entry['runs']} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## Alert detection (scenario level)",
        "",
        "Over all scored runs. Tamper positives: `tampering_seeded`; clock positives: `clock_manipulated`.",
        "",
        "| Alert | Positive runs | Negative runs | TP | FP | FN | TN | Recall | False-positive rate | Precision |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, summary in metrics["alerts"].items():
        lines.append(
            f"| {name} | {summary['positive_runs']} | {summary['negative_runs']} | {summary['true_positives']}"
            f" | {summary['false_positives']} | {summary['false_negatives']} | {summary['true_negatives']}"
            f" | {_num(summary['recall'])} | {_num(summary['false_positive_rate'])} | {_num(summary['precision'])} |"
        )

    lines += [
        "",
        "## Runs",
        "",
        "| Scenario | Seed | Status | F1 | Precision | Recall | Time <= 1 s | Completeness | Gap P | Gap R"
        " | Median error (s) | Tamper alert | Clock alert | Parameters |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in metrics["runs"]:
        score = row.get("score") or {}
        values = [
            _num(score.get(key))
            for key in (
                "event_f1",
                "event_precision",
                "event_recall",
                "timing_within_tolerance",
                "evidence_completeness",
                "unknown_gap_precision",
                "unknown_gap_recall",
                "median_absolute_time_error_seconds",
            )
        ]
        ok = row["status"] == STATUS_OK
        alerts = [_flag(score.get("tamper_alert")) if ok else "n/a", _flag(score.get("clock_anomaly_alert")) if ok else "n/a"]
        lines.append(
            f"| {row['scenario_id']} | {row['seed']} | {row['status']} | "
            + " | ".join(values + alerts)
            + f" | {_md(describe_parameters(row.get('parameters') or {}))} |"
        )

    failed = [row for row in metrics["runs"] if row["status"] != STATUS_OK]
    if failed:
        lines += ["", "## Failed runs", ""]
        for row in failed:
            lines.append(f"- {row['scenario_id']} seed {row['seed']}: {_md(row.get('error') or 'unknown error')}")

    lines += ["", "## Limits", ""]
    lines += [f"- {limit}" for limit in metrics["limits"]]
    return "\n".join(lines) + "\n"


def write_outputs(out_dir: Path, metrics: dict) -> None:
    """Write metrics.json and metrics.md into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / METRICS_JSON).write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (out_dir / METRICS_MD).write_text(render_markdown(metrics), encoding="utf-8")


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def default_score_fn(evdir: Path, truth: dict, outdir: Path, case: str, title: str) -> dict:
    """nexus_iot.evaluate.score_case, imported lazily so the runner works without it."""
    from nexus_iot.evaluate import score_case

    return score_case(evdir, truth, outdir, case, title)


def _error_text(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    stderr = getattr(exc, "stderr", None)
    if isinstance(exc, subprocess.CalledProcessError) and stderr:
        text += f" | stderr: {str(stderr).strip()[-500:]}"
    return text


@dataclass
class BenchmarkConfig:
    """Everything one benchmark needs besides its injectable dependencies."""

    benchmark_id: str
    scenario_ids: list[str]
    seeds: list[int]
    duration_s: float
    out_root: Path
    cases_root: Path
    runs_root: Path
    build: bool = True

    @property
    def out_dir(self) -> Path:
        return self.out_root / self.benchmark_id

    def to_dict(self) -> dict:
        return {
            "seeds": self.seeds,
            "scenarios": self.scenario_ids,
            "duration_s": self.duration_s,
            "out_dir": str(self.out_dir),
            "cases_root": str(self.cases_root / self.benchmark_id),
            "build": self.build,
        }


def run_one(
    config: BenchmarkConfig,
    scenario_id: str,
    seed: int,
    *,
    docker: DockerOps,
    score_fn: ScoreFn,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    log: Callable[[str], None],
) -> RunResult:
    """Run, collect and score one scenario for one seed. Never raises for a run failure."""
    started = clock()
    scenario = build_scenario(scenario_id, seed, config.duration_s)
    result = RunResult(
        scenario_id=scenario_id,
        title=scenario.title,
        seed=seed,
        status=STATUS_FAILED,
        tampering_seeded=bool(scenario.tamper),
        clock_manipulated=scenario.clock_manipulated,
        parameters=scenario.parameters,
    )
    try:
        case_dir = execute_scenario(
            scenario,
            docker=docker,
            run_id=f"seed-{seed}",
            duration=config.duration_s,
            seed=seed,
            build=False,
            runs_root=config.runs_root / config.benchmark_id,
            cases_root=config.cases_root / config.benchmark_id,
            clock=clock,
            sleep=sleep,
            log=log,
        )
        result.case_dir = str(case_dir)
        truth = json.loads((case_dir / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
        result.tampering_seeded = bool(truth.get("tampering_seeded", result.tampering_seeded))
        result.clock_manipulated = bool(truth.get("clock_manipulated", result.clock_manipulated))
        score = score_fn(case_dir / "evidence", truth, case_dir / "derived", scenario_id, scenario.title)
        result.score = select_score(score)
        result.status = STATUS_OK
    except Exception as exc:  # noqa: BLE001 - one bad run must not stop the benchmark
        result.error = _error_text(exc)
        log(f"[{scenario_id}] seed {seed} FAILED: {result.error}")
    result.wall_seconds = clock() - started
    return result


def run_benchmark(
    config: BenchmarkConfig,
    *,
    docker: DockerOps,
    score_fn: ScoreFn = default_score_fn,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = print,
) -> dict:
    """Run every seed x scenario, writing metrics after each run; return the final metrics."""
    started = clock()
    created_at = datetime.fromtimestamp(started, timezone.utc).isoformat(timespec="seconds")
    if config.build:
        log("building images")
        docker.compose_build({"RUN_DIR": str((config.runs_root / config.benchmark_id / "_build").resolve())})

    rows: list[dict] = []
    metrics: dict = {}
    total = len(config.seeds) * len(config.scenario_ids)
    for seed in config.seeds:
        for scenario_id in config.scenario_ids:
            log(f"=== run {len(rows) + 1}/{total}: {scenario_id} seed {seed} ===")
            result = run_one(config, scenario_id, seed, docker=docker, score_fn=score_fn, clock=clock, sleep=sleep, log=log)
            rows.append(result.to_dict())
            metrics = build_metrics(
                rows,
                benchmark_id=config.benchmark_id,
                config=config.to_dict(),
                wall_seconds=clock() - started,
                created_at=created_at,
            )
            write_outputs(config.out_dir, metrics)
    return metrics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m testbed.runner.benchmark",
        description="Run testbed scenarios across seeds, score every case and aggregate the metrics.",
    )
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS), help="seeds (default 1 2 3)")
    parser.add_argument("--scenarios", nargs="+", default=["all"], help="scenario ids (S1..S7) or 'all' (default)")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_S, help="seconds per run (default 60, min 30)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="results root (default testbed/results)")
    parser.add_argument("--cases-root", type=Path, default=DEFAULT_CASES_ROOT, help="case folders root (default testbed/cases)")
    parser.add_argument("--no-build", action="store_true", help="do not build the Docker images first")
    return parser


def main(
    argv: list[str] | None = None,
    docker: DockerOps | None = None,
    score_fn: ScoreFn | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    runs_root: Path = DEFAULT_RUNS_ROOT,
    log: Callable[[str], None] = print,
) -> int:
    args = build_parser().parse_args(argv)
    seeds = list(dict.fromkeys(args.seeds))
    try:
        scenario_ids = [scenario.id for scenario in get_scenarios(args.scenarios)]
        for seed in seeds:
            for scenario_id in scenario_ids:
                build_scenario(scenario_id, seed, args.duration)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    config = BenchmarkConfig(
        benchmark_id=time.strftime("bench-%Y%m%d-%H%M%S", time.localtime(clock())),
        scenario_ids=scenario_ids,
        seeds=seeds,
        duration_s=args.duration,
        out_root=args.out.resolve(),
        cases_root=args.cases_root.resolve(),
        runs_root=runs_root,
        build=not args.no_build,
    )
    log(f"benchmark {config.benchmark_id}: {len(seeds)} seed(s) x {len(scenario_ids)} scenario(s), {args.duration:g} s each")
    try:
        metrics = run_benchmark(
            config,
            docker=docker or DockerOps(),
            score_fn=score_fn or default_score_fn,
            clock=clock,
            sleep=sleep,
            log=log,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"error: benchmark aborted: {_error_text(exc)}", file=sys.stderr)
        return 1
    log(f"wrote {config.out_dir / METRICS_JSON} and {config.out_dir / METRICS_MD}")
    log(f"{metrics['successful_runs']}/{metrics['total_runs']} run(s) scored, {metrics['failed_runs']} failed")
    return 1 if metrics["failed_runs"] else 0


if __name__ == "__main__":
    sys.exit(main())
