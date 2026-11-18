"""Seeded scenario parameters: every seed gives a different, valid variant of S1..S7.

The fault parameters (which device is disconnected and when, the clock step,
the drift, the capture gap, the tampered files and lines) are drawn from
``random.Random(f"{seed}:{scenario_id}")``, so a (seed, scenario, duration)
triple always gives the same scenario. Bounds keep every fault inside the run
and leave at least three clock anchors on each side of a clock step. See the
"Seeded variation" section of testbed/CONTRACT.md.
"""
from __future__ import annotations

import math
import random
from dataclasses import asdict, dataclass, field

from .scenarios import (
    CAPTURE_CONTAINER,
    DEVICE_CONTAINERS,
    DEVICE_EVENTS,
    DEVICE_INTERVALS,
    ENV_PREFIXES,
    SCENARIOS,
    Action,
    Scenario,
    TamperOp,
)

# Mirrors devicecore.JITTER_S: each scheduled event moves by up to +/-0.2 s.
JITTER_S = 0.2

MIN_DURATION_S = 30.0
EDGE_MARGIN_S = 6.0  # no fault starts before this many seconds or ends later than duration minus this

DISCONNECT_MIN_S = 6.0
DISCONNECT_EXTRA_S = 10.0

CAPTURE_GAP_MIN_S = 5.0
CAPTURE_GAP_MAX_S = 15.0

CLOCK_ANCHORS_PER_SIDE = 3
CLOCK_STEP_MARGIN_S = 0.5
CLOCK_OFFSET_MAX_S = 10.0
CLOCK_STEP_MIN_S = 5.0
CLOCK_STEP_MAX_S = 120.0

DRIFT_MIN_PPM = 2000
DRIFT_MAX_PPM = 20000

FORCED_SUFFIX = "_forced"


# ---------------------------------------------------------------------------
# Fault parameter records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisconnectFault:
    """Device removed from the network from ``start_s`` to ``end_s`` (schedule-relative)."""

    device: str
    container: str
    start_s: float
    end_s: float


@dataclass(frozen=True)
class ClockStepFault:
    """Device clock with a constant offset that jumps by ``step_s`` at ``step_at_s``."""

    device: str
    offset_s: float
    step_at_s: float
    step_s: float


@dataclass(frozen=True)
class ClockDriftFault:
    """Device clock that drifts linearly by ``drift_ppm``."""

    device: str
    drift_ppm: int


@dataclass(frozen=True)
class CaptureGapFault:
    """Packet capture stopped from ``start_s`` to ``end_s`` (schedule-relative)."""

    start_s: float
    end_s: float


@dataclass
class ScenarioParameters:
    """All concrete parameters of one seeded scenario run."""

    seed: int
    duration_s: float
    disconnect: DisconnectFault | None = None
    clock_step: ClockStepFault | None = None
    clock_drift: ClockDriftFault | None = None
    capture_gap: CaptureGapFault | None = None
    tamper: list[TamperOp] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON-friendly dict with only the faults that are present."""
        result: dict = {"seed": self.seed, "duration_s": self.duration_s}
        for name in ("disconnect", "clock_step", "clock_drift", "capture_gap"):
            value = getattr(self, name)
            if value is not None:
                result[name] = asdict(value)
        if self.tamper:
            result["tamper"] = [asdict(op) for op in self.tamper]
        return result


# ---------------------------------------------------------------------------
# Schedule arithmetic (host-side, conservative w.r.t. jitter)
# ---------------------------------------------------------------------------


def guaranteed_record_count(device: str, duration_s: float) -> int:
    """Lines the device log is certain to hold: boot plus every k >= 1 with k*I + J < duration."""
    interval = DEVICE_INTERVALS[device]
    k = 0
    while (k + 1) * interval + JITTER_S < duration_s:
        k += 1
    return 1 + k


def event_at_index(device: str, index: int) -> str:
    """Event name of 0-based log line ``index`` (line 0 is boot)."""
    if index == 0:
        return "boot"
    events = DEVICE_EVENTS[device]
    return events[(index - 1) % len(events)]


def clock_step_bounds(device: str, duration_s: float) -> tuple[float, float]:
    """Allowed step time range that keeps >= 3 non-boot events on each side of the step."""
    interval = DEVICE_INTERVALS[device]
    span = CLOCK_ANCHORS_PER_SIDE * interval + JITTER_S + CLOCK_STEP_MARGIN_S
    return span, duration_s - span


def clock_step_devices(duration_s: float) -> list[str]:
    """Devices whose interval leaves room for a clock step in a run of ``duration_s``."""
    eligible = []
    for device in DEVICE_CONTAINERS:
        low, high = clock_step_bounds(device, duration_s)
        if low <= high:
            eligible.append(device)
    return eligible


def disconnect_min_length(device: str) -> float:
    """Shortest disconnect window; 2 intervals always cover at least one scheduled event."""
    return max(DISCONNECT_MIN_S, 2 * DEVICE_INTERVALS[device])


# ---------------------------------------------------------------------------
# Random draws
# ---------------------------------------------------------------------------


def _tenths(rng: random.Random, low: float, high: float) -> float:
    """Uniform draw on the 0.1 s grid inside [low, high] (both ends inclusive)."""
    low_10 = math.ceil(round(low * 10, 6))
    high_10 = math.floor(round(high * 10, 6))
    if low_10 > high_10:
        raise ValueError(f"empty range [{low}, {high}]")
    return rng.randint(low_10, high_10) / 10


def _sign(rng: random.Random) -> int:
    return 1 if rng.random() < 0.5 else -1


def _window(rng: random.Random, duration_s: float, min_length: float, max_length: float) -> tuple[float, float]:
    """A (start, end) window inside [EDGE_MARGIN_S, duration - EDGE_MARGIN_S]."""
    room = duration_s - 2 * EDGE_MARGIN_S
    length = _tenths(rng, min_length, min(max_length, room))
    start = _tenths(rng, EDGE_MARGIN_S, duration_s - EDGE_MARGIN_S - length)
    return start, round(start + length, 1)


def draw_disconnect(rng: random.Random, duration_s: float, exclude: str | None = None) -> DisconnectFault:
    """Pick a device (not ``exclude``) and a disconnect window for it."""
    devices = [d for d in DEVICE_CONTAINERS if d != exclude]
    device = rng.choice(devices)
    min_length = disconnect_min_length(device)
    start, end = _window(rng, duration_s, min_length, min_length + DISCONNECT_EXTRA_S)
    return DisconnectFault(device=device, container=DEVICE_CONTAINERS[device], start_s=start, end_s=end)


def draw_clock_step(rng: random.Random, duration_s: float, exclude: str | None = None) -> ClockStepFault:
    """Pick an eligible device, an offset, a step size (either sign) and a step time."""
    devices = [d for d in clock_step_devices(duration_s) if d != exclude]
    if not devices:
        raise ValueError(f"no device fits a clock step in {duration_s:g} s")
    device = rng.choice(devices)
    offset = _tenths(rng, -CLOCK_OFFSET_MAX_S, CLOCK_OFFSET_MAX_S)
    step = _sign(rng) * _tenths(rng, CLOCK_STEP_MIN_S, CLOCK_STEP_MAX_S)
    low, high = clock_step_bounds(device, duration_s)
    step_at = _tenths(rng, low, high)
    return ClockStepFault(device=device, offset_s=offset, step_at_s=step_at, step_s=step)


def draw_clock_drift(rng: random.Random) -> ClockDriftFault:
    """Pick any device and a drift of 2,000..20,000 ppm with a random sign."""
    device = rng.choice(list(DEVICE_CONTAINERS))
    return ClockDriftFault(device=device, drift_ppm=_sign(rng) * rng.randint(DRIFT_MIN_PPM, DRIFT_MAX_PPM))


def draw_capture_gap(rng: random.Random, duration_s: float) -> CaptureGapFault:
    """A capture stop/start window of 5..15 s inside the run."""
    start, end = _window(rng, duration_s, CAPTURE_GAP_MIN_S, CAPTURE_GAP_MAX_S)
    return CaptureGapFault(start_s=start, end_s=end)


def _edited_event(device: str, index: int) -> str:
    """A wrong but plausible event for line ``index``: the next event in the cycle, or ``<event>_forced``."""
    events = DEVICE_EVENTS[device]
    current = event_at_index(device, index)
    if len(events) >= 2:
        return events[(events.index(current) + 1) % len(events)]
    return current + FORCED_SUFFIX


def draw_tamper(rng: random.Random, duration_s: float) -> list[TamperOp]:
    """Delete one line of device A; edit one line and insert one fabricated line in device B."""
    delete_device, edit_device = rng.sample(list(DEVICE_CONTAINERS), 2)
    delete_count = guaranteed_record_count(delete_device, duration_s)
    edit_count = guaranteed_record_count(edit_device, duration_s)

    delete_index = rng.randint(1, delete_count - 1)
    edit_index = rng.randint(1, edit_count - 1)
    insert_choices = [i for i in range(2, edit_count) if i not in (edit_index, edit_index + 1)]
    if not insert_choices:
        raise ValueError(f"{edit_device} has too few lines for edit + insert in {duration_s:g} s")
    insert_index = rng.choice(insert_choices)

    edit_file = f"{edit_device}.jsonl"
    return [
        TamperOp(kind="delete", file=f"{delete_device}.jsonl", index=delete_index),
        TamperOp(kind="edit", file=edit_file, index=edit_index, new_event=_edited_event(edit_device, edit_index)),
        TamperOp(kind="insert", file=edit_file, index=insert_index, new_event=event_at_index(edit_device, insert_index - 1)),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def derive_parameters(scenario_id: str, seed: int, duration_s: float) -> ScenarioParameters:
    """Deterministically derive the fault parameters of one scenario for one seed.

    Raises ValueError for an unknown scenario id or a duration below 30 s.
    """
    if scenario_id not in SCENARIOS:
        raise ValueError(f"unknown scenario id {scenario_id!r}")
    if duration_s < MIN_DURATION_S:
        raise ValueError(f"seeded scenarios need a duration of at least {MIN_DURATION_S:g} s, got {duration_s:g}")
    rng = random.Random(f"{seed}:{scenario_id}")
    params = ScenarioParameters(seed=seed, duration_s=float(duration_s))
    if scenario_id == "S2":
        params.disconnect = draw_disconnect(rng, duration_s)
    elif scenario_id == "S3":
        params.clock_step = draw_clock_step(rng, duration_s)
    elif scenario_id == "S4":
        params.clock_drift = draw_clock_drift(rng)
    elif scenario_id == "S5":
        params.capture_gap = draw_capture_gap(rng, duration_s)
    elif scenario_id == "S6":
        params.tamper = draw_tamper(rng, duration_s)
    elif scenario_id == "S7":
        params.clock_step = draw_clock_step(rng, duration_s)
        params.disconnect = draw_disconnect(rng, duration_s, exclude=params.clock_step.device)
        params.tamper = draw_tamper(rng, duration_s)
    return params


def _fmt(value: float) -> str:
    """Compose env value: shortest exact form, e.g. 5.0 -> "5", -12.3 -> "-12.3"."""
    return f"{value:g}"


def scenario_from_parameters(scenario_id: str, params: ScenarioParameters) -> Scenario:
    """Turn derived parameters into a runnable Scenario (env, actions, tamper)."""
    reference = SCENARIOS[scenario_id]
    env: dict[str, str] = {}
    actions: list[Action] = []
    if params.clock_step is not None:
        prefix = ENV_PREFIXES[params.clock_step.device]
        env[f"{prefix}_CLOCK_OFFSET_S"] = _fmt(params.clock_step.offset_s)
        env[f"{prefix}_CLOCK_STEP_AT_S"] = _fmt(params.clock_step.step_at_s)
        env[f"{prefix}_CLOCK_STEP_S"] = _fmt(params.clock_step.step_s)
    if params.clock_drift is not None:
        env[f"{ENV_PREFIXES[params.clock_drift.device]}_CLOCK_DRIFT_PPM"] = str(params.clock_drift.drift_ppm)
    if params.disconnect is not None:
        actions.append(Action(at_s=params.disconnect.start_s, kind="disconnect", target=params.disconnect.container))
        actions.append(Action(at_s=params.disconnect.end_s, kind="reconnect", target=params.disconnect.container))
    if params.capture_gap is not None:
        actions.append(Action(at_s=params.capture_gap.start_s, kind="stop_capture", target=CAPTURE_CONTAINER))
        actions.append(Action(at_s=params.capture_gap.end_s, kind="start_capture", target=CAPTURE_CONTAINER))
    return Scenario(
        id=scenario_id,
        title=reference.title,
        env=env,
        actions=actions,
        tamper=list(params.tamper),
        clock_manipulated=reference.clock_manipulated,
        parameters=params.to_dict(),
    )


def build_scenario(scenario_id: str, seed: int, duration_s: float) -> Scenario:
    """Seeded variant of one reference scenario (see derive_parameters)."""
    return scenario_from_parameters(scenario_id, derive_parameters(scenario_id, seed, duration_s))
