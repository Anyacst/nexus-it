"""Pure, deterministic core of the simulated IoT device.

This module holds everything about a device that can be unit-tested without
a broker: the device clock model, the event schedule and the record builders.
It uses only the standard library and must never import paho-mqtt.
"""

from __future__ import annotations

import random

# Fixed per-device behaviour, keyed by DEVICE_ID. After a first "boot" event,
# each device emits its events in order, cycling, every ``interval_s`` seconds.
DEVICE_PROFILES: dict[str, dict] = {
    "door-sensor": {"interval_s": 3.0, "events": ["door_open", "door_close"]},
    "temp-sensor": {"interval_s": 2.0, "events": ["temperature_reading"]},
    "smart-plug": {"interval_s": 4.0, "events": ["plug_on", "plug_off"]},
    "motion-sensor": {"interval_s": 5.0, "events": ["motion_detected", "motion_cleared"]},
    "smart-lock": {"interval_s": 6.0, "events": ["lock_engaged", "lock_released"]},
}

BOOT_EVENT = "boot"
JITTER_S = 0.2
TEMPERATURE_EVENT = "temperature_reading"
TEMPERATURE_BASE_C = 21.5
TEMPERATURE_SPREAD_C = 1.5


def device_time(
    true_time: float,
    start: float,
    offset_s: float = 0.0,
    drift_ppm: float = 0.0,
    step_at_s: float = -1.0,
    step_s: float = 0.0,
) -> float:
    """Return the timestamp the device's own (imperfect) clock reports.

    The device clock is the true time plus a constant offset, a linear drift
    that grows with the time elapsed since ``start``, and an optional one-off
    step applied from ``step_at_s`` seconds after ``start`` onwards. A negative
    ``step_at_s`` disables the step.
    """
    elapsed = true_time - start
    reported = true_time + offset_s + drift_ppm * 1e-6 * elapsed
    if step_at_s >= 0 and elapsed >= step_at_s:
        reported += step_s
    return reported


def _temperature(rng: random.Random) -> float:
    """Draw one plausible indoor temperature reading in degrees Celsius."""
    spread = rng.uniform(-TEMPERATURE_SPREAD_C, TEMPERATURE_SPREAD_C)
    return round(TEMPERATURE_BASE_C + spread, 2)


def schedule(device_id: str, duration_s: float, seed: int) -> list[dict]:
    """Build the device's event schedule for one run.

    Returns a list of ``{"offset_s": float, "event": str, "value": float | None}``
    sorted by offset. The first entry is ``boot`` at offset 0.0; every later
    entry sits at ``k * interval_s`` plus uniform jitter of +/-0.2 s. Only
    offsets strictly below ``duration_s`` are included. The result depends
    only on the arguments, so the same seed always gives the same schedule.

    Raises ValueError for an unknown ``device_id``.
    """
    if device_id not in DEVICE_PROFILES:
        raise ValueError(f"unknown device_id: {device_id!r}")

    profile = DEVICE_PROFILES[device_id]
    interval_s = float(profile["interval_s"])
    events: list[str] = profile["events"]
    rng = random.Random(f"{seed}:{device_id}")

    entries: list[dict] = []
    if duration_s > 0:
        entries.append({"offset_s": 0.0, "event": BOOT_EVENT, "value": None})

    k = 1
    while k * interval_s - JITTER_S < duration_s:
        offset = k * interval_s + rng.uniform(-JITTER_S, JITTER_S)
        event = events[(k - 1) % len(events)]
        value = _temperature(rng) if event == TEMPERATURE_EVENT else None
        if 0.0 < offset < duration_s:
            entries.append({"offset_s": offset, "event": event, "value": value})
        k += 1

    entries.sort(key=lambda entry: entry["offset_s"])
    return entries


def event_id(device_id: str, sequence: int) -> str:
    """Return the stable event identifier, e.g. ``door-sensor-00001``."""
    return f"{device_id}-{sequence:05d}"


def device_record(
    device_id: str,
    sequence: int,
    event: str,
    device_ts: float,
    value: float | None = None,
) -> dict:
    """Build the device log line, which is also the MQTT payload.

    The ``value`` key is present only when a value is given.
    """
    record: dict = {
        "event_id": event_id(device_id, sequence),
        "sequence": sequence,
        "device": device_id,
        "event": event,
        "timestamp": device_ts,
    }
    if value is not None:
        record["value"] = value
    return record


def truth_record(
    device_id: str,
    sequence: int,
    event: str,
    true_time: float,
    device_ts: float,
    published: bool,
) -> dict:
    """Build the ground-truth line for one scheduled event."""
    return {
        "event_id": event_id(device_id, sequence),
        "sequence": sequence,
        "device": device_id,
        "event": event,
        "true_time": true_time,
        "device_time": device_ts,
        "published": published,
    }
