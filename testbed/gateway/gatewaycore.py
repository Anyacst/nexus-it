"""Pure core of the gateway logger: payload validation and record building.

Uses only the standard library and must never import paho-mqtt.
"""

from __future__ import annotations

import json


def _is_int(value: object) -> bool:
    """True for a real integer (bool is rejected even though it subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    """True for an int or float that is not a bool."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_payload(topic: str, payload: bytes) -> dict | None:
    """Validate a device MQTT payload and return it as a dict, or None.

    A payload is valid only if it is a JSON object with a str ``event_id``,
    an int ``sequence``, a str ``device``, a str ``event``, a numeric
    ``timestamp``, and the topic equals ``nexus/<device>/<event>``.
    """
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None

    if not isinstance(parsed.get("event_id"), str):
        return None
    if not _is_int(parsed.get("sequence")):
        return None
    if not isinstance(parsed.get("device"), str):
        return None
    if not isinstance(parsed.get("event"), str):
        return None
    if not _is_number(parsed.get("timestamp")):
        return None
    if topic != f"nexus/{parsed['device']}/{parsed['event']}":
        return None
    return parsed


def gateway_record(topic: str, payload: bytes, arrival: float, counter: int) -> dict | None:
    """Build one gateway log line, or return None for an invalid payload.

    ``sequence`` is the gateway's own counter, not the device sequence.
    """
    parsed = parse_payload(topic, payload)
    if parsed is None:
        return None
    return {
        "timestamp": arrival,
        "event": parsed["event"],
        "event_id": parsed["event_id"],
        "sequence": counter,
        "peer": parsed["device"],
        "topic": topic,
        "device_timestamp": parsed["timestamp"],
    }
