"""CLI: run testbed scenarios in Docker, collect case folders, optionally score them.

    python -m testbed.runner.run_scenario S1 [S2 ...|all] [--duration 40] [--seed 7]
        [--cases-root testbed/cases] [--analyze] [--no-build] [--keep-run]

--seed drives both the device RNG and the seeded fault parameters
(testbed.runner.variation.build_scenario).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from .collect import collect_case
from .scenarios import (
    CAPTURE_CONTAINER,
    CONTAINER_IPS,
    DEVICE_CONTAINERS,
    NETWORK_NAME,
    Action,
    Scenario,
    get_scenarios,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "testbed" / "docker-compose.yml"
DEFAULT_RUNS_ROOT = REPO_ROOT / "testbed" / "runs"
DEFAULT_CASES_ROOT = REPO_ROOT / "testbed" / "cases"
RUN_SUBDIRS = ("logs", "truth", "capture", "broker")
START_DELAY_S = 8
WAIT_GRACE_S = 60.0
DOWN_TIMEOUT_S = 5
# After the last device exits, let its final PUBLISH/DISCONNECT reach the wire, then stop
# tcpdump with SIGTERM (it flushes the pcap) before compose down tears the network away.
CAPTURE_FLUSH_S = 2.0
CAPTURE_STOP_TIMEOUT_S = 10

Runner = Callable[..., subprocess.CompletedProcess]


class DockerOps:
    """Thin wrapper around the docker CLI so tests can replace it with a fake."""

    def __init__(self, compose_file: Path = COMPOSE_FILE, runner: Runner = subprocess.run) -> None:
        self.compose_file = Path(compose_file)
        self.runner = runner

    def _run(self, args: list[str], env: dict[str, str] | None = None, timeout: float | None = None) -> str:
        full_env = {**os.environ, **env} if env else None
        result = self.runner(args, check=True, capture_output=True, text=True, env=full_env, timeout=timeout)
        return result.stdout or ""

    def _compose(self, *args: str) -> list[str]:
        return ["docker", "compose", "-f", str(self.compose_file), *args]

    def compose_build(self, env: dict[str, str]) -> None:
        self._run(self._compose("build"), env=env)

    def compose_up(self, env: dict[str, str], build: bool = True) -> None:
        args = self._compose("up", "-d")
        if build:
            args.append("--build")
        self._run(args, env=env)

    def compose_down(self, env: dict[str, str]) -> None:
        self._run(self._compose("down", "-t", str(DOWN_TIMEOUT_S)), env=env)

    def network_disconnect(self, container: str) -> None:
        self._run(["docker", "network", "disconnect", NETWORK_NAME, container])

    def network_connect(self, container: str, ip: str) -> None:
        self._run(["docker", "network", "connect", "--ip", ip, NETWORK_NAME, container])

    def stop(self, container: str, timeout: int | None = None) -> None:
        """docker stop: SIGTERM, then SIGKILL after ``timeout`` seconds (docker default when None)."""
        args = ["docker", "stop"]
        if timeout is not None:
            args += ["-t", str(timeout)]
        self._run([*args, container])

    def start(self, container: str) -> None:
        self._run(["docker", "start", container])

    def wait(self, container: str, timeout: float) -> int | None:
        """Block until the container exits; return its exit code, or None on timeout."""
        try:
            output = self._run(["docker", "wait", container], timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        return int(output.strip().splitlines()[-1])


def perform_action(docker: DockerOps, action: Action) -> None:
    """Translate one scenario action into a docker command."""
    if action.kind == "disconnect":
        docker.network_disconnect(action.target)
    elif action.kind == "reconnect":
        docker.network_connect(action.target, CONTAINER_IPS[action.target])
    elif action.kind == "stop_capture":
        docker.stop(action.target or CAPTURE_CONTAINER)
    elif action.kind == "start_capture":
        docker.start(action.target or CAPTURE_CONTAINER)
    else:
        raise ValueError(f"unknown action kind {action.kind!r}")


def stop_capture_after_flush(
    docker: DockerOps,
    sid: str,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    log: Callable[[str], None],
) -> float | None:
    """Wait CAPTURE_FLUSH_S, then stop the capture container gracefully; return when it was stopped.

    A failing docker stop is only logged: compose down stops the container anyway.
    """
    sleep(CAPTURE_FLUSH_S)
    log(f"[{sid}] stopping {CAPTURE_CONTAINER} (SIGTERM, flushes the pcap)")
    try:
        docker.stop(CAPTURE_CONTAINER, timeout=CAPTURE_STOP_TIMEOUT_S)
    except subprocess.CalledProcessError as exc:
        log(f"[{sid}] WARNING: could not stop {CAPTURE_CONTAINER}: {exc}")
        return None
    return clock()


def prepare_run_dir(run_dir: Path) -> None:
    """Create RUN_DIR and its bind-mount subfolders, writable by container users."""
    for name in RUN_SUBDIRS:
        sub = run_dir / name
        sub.mkdir(parents=True, exist_ok=True)
        # Mosquitto drops to a non-root user; on Linux it must still write broker/.
        sub.chmod(0o777)


def compose_env(scenario: Scenario, run_dir: Path, start_at: int, duration: float, seed: int) -> dict[str, str]:
    """Environment passed to docker compose for one scenario."""
    return {
        "RUN_DIR": str(run_dir.resolve()),
        "START_AT": str(start_at),
        "DURATION_S": f"{duration:g}",
        "SEED": str(seed),
        **scenario.env,
    }


def execute_scenario(
    scenario: Scenario,
    *,
    docker: DockerOps,
    run_id: str,
    duration: float = 40.0,
    seed: int = 7,
    build: bool = True,
    keep_run: bool = False,
    analyze: bool = False,
    runs_root: Path = DEFAULT_RUNS_ROOT,
    cases_root: Path = DEFAULT_CASES_ROOT,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = print,
) -> Path:
    """Run one scenario end to end and return its case folder."""
    sid = scenario.id
    run_dir = Path(runs_root) / run_id / sid
    case_dir = Path(cases_root) / run_id / sid
    prepare_run_dir(run_dir)

    log(f"[{sid}] {scenario.title}: run dir {run_dir}")
    if build:
        # Build before fixing START_AT so a slow image build cannot eat the start delay.
        log(f"[{sid}] building images")
        docker.compose_build(compose_env(scenario, run_dir, 0, duration, seed))

    start_at = int(clock()) + START_DELAY_S
    env = compose_env(scenario, run_dir, start_at, duration, seed)
    performed: list[dict] = []
    exit_codes: dict[str, int | None] = {}
    capture_stopped_at: float | None = None
    started_at = clock()
    log(f"[{sid}] compose up (START_AT={start_at}, duration={duration:g}s, seed={seed})")
    try:
        docker.compose_up(env, build=False)
        for action in sorted(scenario.actions, key=lambda a: a.at_s):
            if action.at_s >= duration:
                log(f"[{sid}] skip {action.kind} at +{action.at_s:g}s (beyond duration {duration:g}s)")
                continue
            delay = start_at + action.at_s - clock()
            if delay > 0:
                sleep(delay)
            log(f"[{sid}] +{action.at_s:g}s {action.kind} {action.target or ''}".rstrip())
            perform_action(docker, action)
            performed.append({"at_s": action.at_s, "kind": action.kind, "target": action.target, "performed_at": clock()})
        deadline = start_at + duration + WAIT_GRACE_S
        for container in DEVICE_CONTAINERS.values():
            timeout = max(1.0, deadline - clock())
            log(f"[{sid}] waiting for {container} (timeout {timeout:.0f}s)")
            exit_codes[container] = docker.wait(container, timeout)
            if exit_codes[container] is None:
                log(f"[{sid}] WARNING: {container} did not exit in time")
        capture_stopped_at = stop_capture_after_flush(docker, sid, clock=clock, sleep=sleep, log=log)
    finally:
        log(f"[{sid}] compose down")
        docker.compose_down(env)

    run_meta = {
        "run_id": run_id,
        "scenario_id": sid,
        "title": scenario.title,
        "params": {"duration_s": duration, "seed": seed, "start_at": start_at, "env": env},
        "parameters": scenario.parameters,
        "started_at": started_at,
        "ended_at": clock(),
        "actions_performed": performed,
        "device_exit_codes": exit_codes,
        "capture_stopped_at": capture_stopped_at,
    }
    log(f"[{sid}] collecting case -> {case_dir}")
    collect_case(run_dir, case_dir, scenario, run_meta)
    if scenario.tamper:
        log(f"[{sid}] applied {len(scenario.tamper)} tamper op(s) to evidence/")

    if not keep_run:
        shutil.rmtree(run_dir, ignore_errors=True)
        if run_dir.exists():
            log(f"[{sid}] WARNING: could not fully remove {run_dir}")

    if analyze:
        analyze_case(case_dir, scenario, log=log)
    log(f"[{sid}] done: {case_dir}")
    return case_dir


def format_summary(sid: str, result: dict) -> str:
    """One-line score summary for a case."""
    return (
        f"[{sid}] event F1={result['event_f1']:.3f}"
        f" time<=1s={result['timing_within_tolerance']:.1%}"
        f" completeness={result['evidence_completeness']:.1%}"
        f" tamper_alert={result['tamper_alert']}"
        f" clock_anomaly_alert={result['clock_anomaly_alert']}"
    )


def analyze_case(case_dir: Path, scenario: Scenario, log: Callable[[str], None] = print) -> dict:
    """Score the case with NEXUS-IoT. Output goes to <case>/derived/ (outside evidence/)."""
    from nexus_iot.evaluate import score_case  # lazy: keep the runner importable without it

    truth = json.loads((case_dir / "ground_truth" / "truth.json").read_text(encoding="utf-8"))
    log(f"[{scenario.id}] analyzing evidence")
    result = score_case(case_dir / "evidence", truth, case_dir / "derived", scenario.id, scenario.title)
    log(format_summary(scenario.id, result))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m testbed.runner.run_scenario",
        description="Run NEXUS-IoT Docker testbed scenarios and collect case folders.",
    )
    parser.add_argument("scenarios", nargs="+", help="scenario ids (S1..S7) or 'all'")
    parser.add_argument("--duration", type=float, default=40.0, help="seconds of event generation (default 40)")
    parser.add_argument("--seed", type=int, default=7, help="device RNG and scenario-parameter seed (default 7)")
    parser.add_argument("--cases-root", type=Path, default=DEFAULT_CASES_ROOT, help="where case folders go (default testbed/cases)")
    parser.add_argument("--analyze", action="store_true", help="score each case with nexus_iot.evaluate.score_case")
    parser.add_argument("--no-build", action="store_true", help="do not pass --build to docker compose up")
    parser.add_argument("--keep-run", action="store_true", help="keep the raw run folder under testbed/runs/")
    return parser


def main(
    argv: list[str] | None = None,
    docker: DockerOps | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    runs_root: Path = DEFAULT_RUNS_ROOT,
) -> int:
    args = build_parser().parse_args(argv)
    if args.duration <= 0:
        print("error: --duration must be > 0", file=sys.stderr)
        return 2
    try:
        scenarios = get_scenarios(args.scenarios, seed=args.seed, duration=args.duration)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    docker = docker or DockerOps()
    run_id = time.strftime("%Y%m%d-%H%M%S", time.localtime(clock()))
    print(f"run {run_id}: {', '.join(s.id for s in scenarios)}")
    failures: list[str] = []
    for scenario in scenarios:
        try:
            execute_scenario(
                scenario,
                docker=docker,
                run_id=run_id,
                duration=args.duration,
                seed=args.seed,
                build=not args.no_build,
                keep_run=args.keep_run,
                analyze=args.analyze,
                runs_root=runs_root,
                cases_root=args.cases_root.resolve(),
                clock=clock,
                sleep=sleep,
            )
        except (subprocess.CalledProcessError, OSError, ValueError) as exc:
            detail = getattr(exc, "stderr", None) or ""
            print(f"[{scenario.id}] FAILED: {exc}\n{detail}".rstrip(), file=sys.stderr)
            failures.append(scenario.id)
    if failures:
        print(f"failed scenarios: {', '.join(failures)}", file=sys.stderr)
        return 1
    print(f"all {len(scenarios)} scenario(s) collected under {args.cases_root.resolve() / run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
