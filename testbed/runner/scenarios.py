"""Scenario definitions S1..S7 for the NEXUS-IoT Docker testbed.

Each scenario describes extra compose environment (clock faults), timed Docker
actions (network disconnect, capture stop/start) and post-collection tamper
operations applied to evidence copies. See testbed/CONTRACT.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Testbed topology (mirrors the contract table; container side owns the compose file)
# ---------------------------------------------------------------------------

NETWORK_NAME = "nexus-iotnet"
CAPTURE_CONTAINER = "nexus-tb-capture"

DEVICE_CONTAINERS: dict[str, str] = {
    "door-sensor": "nexus-tb-door-sensor",
    "temp-sensor": "nexus-tb-temp-sensor",
    "smart-plug": "nexus-tb-smart-plug",
    "motion-sensor": "nexus-tb-motion-sensor",
    "smart-lock": "nexus-tb-smart-lock",
}

CONTAINER_IPS: dict[str, str] = {
    "nexus-tb-door-sensor": "172.30.0.21",
    "nexus-tb-temp-sensor": "172.30.0.22",
    "nexus-tb-smart-plug": "172.30.0.23",
    "nexus-tb-motion-sensor": "172.30.0.24",
    "nexus-tb-smart-lock": "172.30.0.25",
}

# Host-side mirror of devicecore.DEVICE_PROFILES (events after boot, cycled; interval in seconds).
# Kept here so the host runner does not depend on the container-side package.
DEVICE_EVENTS: dict[str, list[str]] = {
    "door-sensor": ["door_open", "door_close"],
    "temp-sensor": ["temperature_reading"],
    "smart-plug": ["plug_on", "plug_off"],
    "motion-sensor": ["motion_detected", "motion_cleared"],
    "smart-lock": ["lock_engaged", "lock_released"],
}

DEVICE_INTERVALS: dict[str, float] = {
    "door-sensor": 3.0,
    "temp-sensor": 2.0,
    "smart-plug": 4.0,
    "motion-sensor": 5.0,
    "smart-lock": 6.0,
}

# Compose env prefix per device: <PREFIX>_CLOCK_OFFSET_S, <PREFIX>_CLOCK_STEP_S, ...
ENV_PREFIXES: dict[str, str] = {
    "door-sensor": "DOOR",
    "temp-sensor": "TEMP",
    "smart-plug": "PLUG",
    "motion-sensor": "MOTION",
    "smart-lock": "LOCK",
}

ACTION_KINDS = ("disconnect", "reconnect", "stop_capture", "start_capture")
TAMPER_KINDS = ("delete", "edit", "insert")
TAMPERABLE_FILES = tuple(f"{device}.jsonl" for device in DEVICE_CONTAINERS)


@dataclass(frozen=True)
class Action:
    """A Docker action performed `at_s` seconds after the schedule start (START_AT)."""

    at_s: float
    kind: str
    target: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ACTION_KINDS:
            raise ValueError(f"unknown action kind {self.kind!r}; expected one of {ACTION_KINDS}")
        if self.at_s < 0:
            raise ValueError(f"action time must be >= 0, got {self.at_s}")
        if self.kind in ("disconnect", "reconnect") and self.target not in CONTAINER_IPS:
            raise ValueError(f"{self.kind} needs a device container target, got {self.target!r}")
        if self.kind in ("stop_capture", "start_capture") and self.target not in (None, CAPTURE_CONTAINER):
            raise ValueError(f"{self.kind} target must be {CAPTURE_CONTAINER!r} or None, got {self.target!r}")


@dataclass(frozen=True)
class TamperOp:
    """A post-collection change to one device log in evidence/.

    `index` is the 0-based record line in the ORIGINAL (pre-tamper) file.
    """

    kind: str
    file: str
    index: int
    new_event: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in TAMPER_KINDS:
            raise ValueError(f"unknown tamper kind {self.kind!r}; expected one of {TAMPER_KINDS}")
        if self.file not in TAMPERABLE_FILES:
            raise ValueError(f"tamper file must be one of {TAMPERABLE_FILES}, got {self.file!r}")
        if self.index < 0:
            raise ValueError(f"tamper index must be >= 0, got {self.index}")
        if self.kind == "edit" and not self.new_event:
            raise ValueError("edit needs new_event")
        if self.kind == "insert" and self.index < 1:
            raise ValueError("insert needs index >= 1 (it copies the previous line)")


@dataclass
class Scenario:
    """One testbed run configuration."""

    id: str
    title: str
    env: dict[str, str] = field(default_factory=dict)
    actions: list[Action] = field(default_factory=list)
    tamper: list[TamperOp] = field(default_factory=list)
    clock_manipulated: bool = False
    # Concrete seeded fault parameters (JSON-friendly); empty for the reference table.
    parameters: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key, value in self.env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError(f"scenario env must be str -> str, got {key!r}: {value!r}")


# ---------------------------------------------------------------------------
# Building blocks shared by S7
# ---------------------------------------------------------------------------

_DISCONNECT_ACTIONS = [
    Action(at_s=12.0, kind="disconnect", target="nexus-tb-temp-sensor"),
    Action(at_s=22.0, kind="reconnect", target="nexus-tb-temp-sensor"),
]

_CAPTURE_GAP_ACTIONS = [
    Action(at_s=12.0, kind="stop_capture", target=CAPTURE_CONTAINER),
    Action(at_s=22.0, kind="start_capture", target=CAPTURE_CONTAINER),
]

_CLOCK_STEP_ENV = {
    "DOOR_CLOCK_OFFSET_S": "5",
    "DOOR_CLOCK_STEP_AT_S": "20",
    "DOOR_CLOCK_STEP_S": "90",
}

_CLOCK_DRIFT_ENV = {"PLUG_CLOCK_DRIFT_PPM": "5000"}

_TAMPER_OPS = [
    TamperOp(kind="delete", file="smart-plug.jsonl", index=3),
    TamperOp(kind="edit", file="door-sensor.jsonl", index=4, new_event="door_close_forced"),
    TamperOp(kind="insert", file="door-sensor.jsonl", index=6, new_event="door_open"),
]


SCENARIOS: dict[str, Scenario] = {
    "S1": Scenario(id="S1", title="Normal operation"),
    "S2": Scenario(id="S2", title="Device disconnection", actions=list(_DISCONNECT_ACTIONS)),
    "S3": Scenario(id="S3", title="Clock step", env=dict(_CLOCK_STEP_ENV), clock_manipulated=True),
    "S4": Scenario(id="S4", title="Clock drift", env=dict(_CLOCK_DRIFT_ENV), clock_manipulated=True),
    "S5": Scenario(id="S5", title="Capture gap", actions=list(_CAPTURE_GAP_ACTIONS)),
    "S6": Scenario(id="S6", title="Post-collection tampering", tamper=list(_TAMPER_OPS)),
    "S7": Scenario(
        id="S7",
        title="Combined",
        env=dict(_CLOCK_STEP_ENV),
        actions=list(_DISCONNECT_ACTIONS),
        tamper=list(_TAMPER_OPS),
        clock_manipulated=True,
    ),
}


def get_scenarios(ids: list[str], seed: int | None = None, duration: float | None = None) -> list[Scenario]:
    """Return scenarios for the given ids, in the order given, without duplicates.

    "all" (anywhere in the list) selects S1..S7. Ids are case-insensitive.
    Without ``seed`` the fixed reference definitions are returned. With ``seed``
    (and ``duration``, default 40 s) each scenario is rebuilt with seeded fault
    parameters by ``testbed.runner.variation.build_scenario``.
    Raises ValueError for an empty list, an unknown id or an unsupported duration.
    """
    if seed is not None:
        from .variation import build_scenario  # local import: variation imports this module

        reference = get_scenarios(ids)
        return [build_scenario(s.id, seed, 40.0 if duration is None else duration) for s in reference]
    if not ids:
        raise ValueError("no scenario ids given")
    normalized = [scenario_id.strip().upper() for scenario_id in ids]
    if "ALL" in normalized:
        return list(SCENARIOS.values())
    unknown = [scenario_id for scenario_id in normalized if scenario_id not in SCENARIOS]
    if unknown:
        raise ValueError(f"unknown scenario id(s) {unknown}; valid: {sorted(SCENARIOS)} or 'all'")
    selected: list[Scenario] = []
    for scenario_id in normalized:
        scenario = SCENARIOS[scenario_id]
        if scenario not in selected:
            selected.append(scenario)
    return selected
