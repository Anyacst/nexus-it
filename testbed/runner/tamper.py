"""Post-collection tampering of evidence COPIES (never original/).

Semantics (testbed/CONTRACT.md):
- delete: remove the record line.
- edit: replace the `event` field only.
- insert: put a new JSON line BEFORE line `index`, copying line `index-1` with
  event_id `<device>-fab01` (fab02, ... for further inserts), the SAME sequence
  (a duplicate) and timestamp = previous + 0.5.

All indices refer to the ORIGINAL 0-based record lines of a file, even when
several ops hit the same file.
"""
from __future__ import annotations

import json
from pathlib import Path

from .scenarios import TamperOp

INSERT_TIME_STEP_S = 0.5


# ---------------------------------------------------------------------------
# Pure per-line helpers (operate on lists of JSON strings, return new lists)
# ---------------------------------------------------------------------------


def _check_index(lines: list[str], index: int, kind: str) -> None:
    if kind == "insert":
        if not 1 <= index <= len(lines):
            raise ValueError(f"insert index {index} out of range 1..{len(lines)}")
    elif not 0 <= index < len(lines):
        raise ValueError(f"{kind} index {index} out of range 0..{len(lines) - 1}")


def delete_line(lines: list[str], index: int) -> list[str]:
    """Return a copy of `lines` without line `index`."""
    _check_index(lines, index, "delete")
    return lines[:index] + lines[index + 1:]


def edit_event(lines: list[str], index: int, new_event: str) -> list[str]:
    """Return a copy of `lines` where only the `event` field of line `index` is replaced."""
    _check_index(lines, index, "edit")
    record = json.loads(lines[index])
    record["event"] = new_event
    result = list(lines)
    result[index] = json.dumps(record)
    return result


def fabricated_record(previous: dict, device: str, fab_number: int = 1, new_event: str | None = None) -> dict:
    """Build a fabricated record from the previous one (same sequence, +0.5 s)."""
    record = dict(previous)
    record["event_id"] = f"{device}-fab{fab_number:02d}"
    record["timestamp"] = previous["timestamp"] + INSERT_TIME_STEP_S
    if new_event is not None:
        record["event"] = new_event
    return record


def insert_fabricated(
    lines: list[str],
    index: int,
    device: str | None = None,
    new_event: str | None = None,
    fab_number: int = 1,
) -> list[str]:
    """Return a copy of `lines` with a fabricated record inserted before line `index`.

    The record copies line `index - 1`. `device` defaults to that record's `device` field.
    """
    _check_index(lines, index, "insert")
    previous = json.loads(lines[index - 1])
    record = fabricated_record(previous, device or previous["device"], fab_number, new_event)
    return lines[:index] + [json.dumps(record)] + lines[index:]


# ---------------------------------------------------------------------------
# Applying ops to an evidence folder
# ---------------------------------------------------------------------------


def read_records(path: Path) -> list[str]:
    """Return the non-blank lines of a JSON-lines file (one record each)."""
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_records(path: Path, lines: list[str]) -> None:
    """Write record lines back, one per line, with a trailing newline."""
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _validate_ops(lines: list[str], ops: list[TamperOp], file_name: str) -> None:
    """Check every op against the ORIGINAL file before anything is changed."""
    touched: set[int] = set()
    for op in ops:
        try:
            _check_index(lines, op.index, op.kind)
        except ValueError as exc:
            raise ValueError(f"{file_name}: {exc}") from exc
        if op.kind in ("delete", "edit"):
            if op.index in touched:
                raise ValueError(f"{file_name}: line {op.index} is deleted/edited more than once")
            touched.add(op.index)


def tamper_lines(lines: list[str], ops: list[TamperOp], device: str) -> tuple[list[str], list[dict]]:
    """Apply ops (indices in ORIGINAL line numbers) to one file's lines. Pure.

    Ops are applied in descending index order (delete/edit before insert at the
    same index) so earlier changes never shift the lines later ops refer to.
    Returns (new_lines, log entries in the order the ops were given).
    """
    _validate_ops(lines, ops, f"{device}.jsonl")

    # Number fabricated records in ascending original position.
    inserts = sorted((op.index, position) for position, op in enumerate(ops) if op.kind == "insert")
    fab_numbers = {position: number for number, (_, position) in enumerate(inserts, start=1)}

    order = sorted(range(len(ops)), key=lambda p: (-ops[p].index, ops[p].kind == "insert", p))
    result = list(lines)
    log: dict[int, dict] = {}
    for position in order:
        op = ops[position]
        entry = {"file": op.file, "kind": op.kind, "index": op.index, "new_event": op.new_event}
        if op.kind == "delete":
            entry["before"] = lines[op.index]
            entry["after"] = None
            result = delete_line(result, op.index)
        elif op.kind == "edit":
            result = edit_event(result, op.index, op.new_event)
            entry["before"] = lines[op.index]
            entry["after"] = result[op.index]
        else:
            result = insert_fabricated(result, op.index, device, op.new_event, fab_numbers[position])
            entry["before"] = None
            entry["after"] = result[op.index]
        log[position] = entry
    return result, [log[p] for p in range(len(ops))]


def apply_tamper(evidence_dir: Path, ops: list[TamperOp]) -> list[dict]:
    """Apply tamper ops to files in `evidence_dir` and return a log of what changed.

    Each file is validated completely before it is rewritten. Refuses to work
    inside an `original/` folder.
    """
    evidence_dir = Path(evidence_dir)
    if evidence_dir.resolve().name == "original":
        raise ValueError(f"refusing to tamper inside an original/ folder: {evidence_dir}")

    positions_by_file: dict[str, list[int]] = {}
    for position, op in enumerate(ops):
        positions_by_file.setdefault(op.file, []).append(position)

    log: dict[int, dict] = {}
    for file_name, positions in positions_by_file.items():
        path = evidence_dir / file_name
        device = Path(file_name).name.removesuffix(".jsonl")
        file_ops = [ops[p] for p in positions]
        new_lines, entries = tamper_lines(read_records(path), file_ops, device)
        write_records(path, new_lines)
        log.update(zip(positions, entries))
    return [log[p] for p in range(len(ops))]
