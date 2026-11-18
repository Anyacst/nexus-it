"""Ground-truth builder: device truth rows + pre-tamper gateway log -> truth.json dict.

The output matches what nexus_iot/evaluate.py expects (see testbed/CONTRACT.md).
"""
from __future__ import annotations

import json
from pathlib import Path

from .scenarios import Scenario

GATEWAY_FILE = "gateway.jsonl"


def load_jsonl(path: Path) -> list[dict]:
    """Read a JSON-lines file into a list of dicts. Blank lines are skipped.

    Raises ValueError (with the line number) for a line that is not a JSON object.
    """
    rows: list[dict] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON ({exc.msg})") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            rows.append(row)
    return rows


def _gateway_index(gateway_rows: list[dict]) -> dict[str, int]:
    """Map event_id -> gateway sequence. A redelivered event keeps its first sequence."""
    index: dict[str, int] = {}
    for row in gateway_rows:
        event_id = row.get("event_id")
        sequence = row.get("sequence")
        if isinstance(event_id, str) and isinstance(sequence, int) and event_id not in index:
            index[event_id] = sequence
    return index


def _unique_in_order(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def build_truth(scenario: Scenario, device_truth_rows: list[dict], gateway_rows: list[dict]) -> dict:
    """Build the truth.json payload for one scenario run (pure function).

    device_truth_rows: rows from /truth/<device>.truth.jsonl (all devices together).
    gateway_rows: rows from the PRE-TAMPER gateway.jsonl.
    """
    gateway_sequences = _gateway_index(gateway_rows)
    events: list[dict] = []
    for row in device_truth_rows:
        device = row["device"]
        device_file = f"{device}.jsonl"
        expected_sources = [device_file]
        source_sequences = {device_file: row["sequence"]}
        if row["event_id"] in gateway_sequences:
            expected_sources.append(GATEWAY_FILE)
            source_sequences[GATEWAY_FILE] = gateway_sequences[row["event_id"]]
        events.append(
            {
                "event_id": row["event_id"],
                "timestamp": row["true_time"],
                "device": device,
                "event": row["event"],
                "expected_sources": expected_sources,
                "source_sequences": source_sequences,
            }
        )
    events.sort(key=lambda e: (e["timestamp"], e["device"], e["source_sequences"][f"{e['device']}.jsonl"]))
    truth = {
        "condition": scenario.title,
        "events": events,
        "tampering_seeded": bool(scenario.tamper),
        "tamper_mechanisms": _unique_in_order([op.kind for op in scenario.tamper]),
        "clock_manipulated": scenario.clock_manipulated,
        "expected_record_count": sum(len(e["expected_sources"]) for e in events),
    }
    if scenario.parameters:
        # Optional key: the concrete seeded fault parameters (the evaluator ignores it).
        truth["parameters"] = scenario.parameters
    return truth
