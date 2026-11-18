"""Chain-of-custody log and examiner notes for one case output folder.

Every case output folder gets an append-only ``custody.jsonl``. Each line is one
entry: a sequence number, UTC time, action, who acted (examiner name plus the
operating-system user and host), the details of what was done, the SHA-256 of
the previous entry, and the SHA-256 of this entry. Changing, removing or
reordering any earlier entry breaks the chain, and ``verify_log`` says where.

An analysis entry records the SHA-256 of every evidence file read and of the
reports written, so the log keeps the hash history even though
``evidence_manifest.json`` and ``report.json`` are replaced on each run.

Examiner notes are entries too. A note is never edited or deleted: it is
retracted by a later entry that gives a reason, so the history stays visible.

A hash chain alone cannot stop someone with write access from rebuilding the
whole log. With an external key, ``sign_head`` writes ``custody.sig``, an
HMAC-SHA256 of the latest entry's hash; ``verify_log`` checks it, so a rebuilt
log fails verification unless the key was also compromised. Entries appended
after the last signature are reported as unsigned.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

CUSTODY_FILE = "custody.jsonl"
SIGNATURE_FILE = "custody.sig"
GENESIS = "0" * 64
MAX_NOTE_LENGTH = 4000
MAX_NAME_LENGTH = 200
ACTIONS = ("analysis", "note_added", "note_retracted", "report_exported", "report_downloaded", "case_deleted")
_LOCK = threading.Lock()


def _now() -> str:
    """UTC time with microseconds, ISO-8601."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical(entry: dict) -> bytes:
    """Canonical bytes of an entry without its own hash."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(entry: dict) -> str:
    """SHA-256 of an entry's canonical form (excluding its ``hash`` field)."""
    return hashlib.sha256(_canonical(entry)).hexdigest()


def file_sha256(path: Path) -> str | None:
    """SHA-256 of a file, or None if it does not exist."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def _actor(examiner: str) -> dict:
    """Who is acting: the stated examiner plus the local OS user and host name."""
    try:
        user = getpass.getuser()
    except Exception:  # getuser raises different errors on platforms without a login name
        user = "unknown"
    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown"
    name = " ".join(str(examiner or "").split())[:MAX_NAME_LENGTH]
    return {"examiner": name or "unspecified", "os_user": user, "host": host}


def read_log(case_dir: Path) -> tuple[list[dict], list[str]]:
    """Return (entries, problems) from a case's custody log; a missing log is an empty one."""
    path = case_dir / CUSTODY_FILE
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return [], []
    except (OSError, UnicodeDecodeError) as e:
        return [], [f"custody log cannot be read: {e}"]
    entries, problems = [], []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            problems.append(f"line {number}: blank line in custody log")
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            problems.append(f"line {number}: not valid JSON ({e.msg})")
            continue
        if not isinstance(entry, dict):
            problems.append(f"line {number}: not a JSON object")
            continue
        entries.append(entry)
    return entries, problems


def append_entry(case_dir: Path, action: str, details: dict, examiner: str = "") -> dict:
    """Append one entry to the case's custody log and return it.

    Refuses to extend a log whose chain is already broken, so a damaged log is
    never silently continued.
    """
    if action not in ACTIONS:
        raise ValueError(f"unknown custody action: {action}")
    case_dir.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        entries, problems = read_log(case_dir)
        broken = problems + _chain_issues(entries)
        if broken:
            raise ValueError("custody log failed verification; not appending: " + "; ".join(broken[:3]))
        entry = {"seq": len(entries) + 1, "time": _now(), "action": action, **_actor(examiner),
                 "tool_version": __version__, "details": details,
                 "prev_hash": entries[-1]["hash"] if entries else GENESIS}
        entry["hash"] = entry_hash(entry)
        with (case_dir / CUSTODY_FILE).open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
    return entry


def _chain_issues(entries: list[dict]) -> list[str]:
    """Check sequence numbers, back-links and entry hashes."""
    issues = []
    previous = GENESIS
    for position, entry in enumerate(entries, 1):
        label = f"entry {entry.get('seq', '?')}"
        if entry.get("seq") != position:
            issues.append(f"{label}: expected sequence number {position}")
        if entry.get("prev_hash") != previous:
            issues.append(f"{label}: does not link to the entry before it (an entry was removed, reordered or changed)")
        if entry.get("hash") != entry_hash(entry):
            issues.append(f"{label}: content does not match its hash (the entry was edited)")
        previous = str(entry.get("hash", ""))
    return issues


def _read_key(key_path: Path) -> bytes:
    """Read an external HMAC key of at least 32 bytes."""
    try:
        key = key_path.read_bytes()
    except OSError as e:
        raise ValueError(f"cannot read custody signing key: {e}") from e
    if len(key) < 32:
        raise ValueError("custody signing key must contain at least 32 bytes")
    return key


def sign_head(case_dir: Path, key_path: Path) -> dict:
    """Write ``custody.sig``: an HMAC-SHA256 of the latest entry's sequence number and hash."""
    key = _read_key(key_path)
    entries, problems = read_log(case_dir)
    issues = problems + _chain_issues(entries)
    if issues or not entries:
        raise ValueError("cannot sign: " + ("; ".join(issues[:3]) if issues else "custody log is empty"))
    head = entries[-1]
    message = f"{head['seq']}:{head['hash']}".encode("ascii")
    signature = {"algorithm": "HMAC-SHA256", "key_id": hashlib.sha256(key).hexdigest()[:16], "seq": head["seq"],
                 "head_hash": head["hash"], "signature": hmac.new(key, message, hashlib.sha256).hexdigest()}
    (case_dir / SIGNATURE_FILE).write_text(json.dumps(signature, indent=2), encoding="utf-8")
    return signature


def verify_log(case_dir: Path, key_path: Path | None = None) -> dict:
    """Verify a case's custody log; return ``{"ok", "entries", "issues", "notes", "signed_seq"}``.

    Checks the chain, that the current report and manifest match the last
    analysis entry, and (with a key) the head signature. ``notes`` lists
    observations that are not failures, such as entries added after signing.
    """
    entries, problems = read_log(case_dir)
    issues = problems + _chain_issues(entries)
    notes: list[str] = []
    if not entries and not problems:
        notes.append("no custody log for this case")
    analyses = [e for e in entries if e.get("action") == "analysis"]
    if analyses:
        recorded = analyses[-1].get("details", {}).get("outputs", {})
        for name, digest in sorted(recorded.items()):
            current = file_sha256(case_dir / name)
            if current != digest:
                state = "is missing" if current is None else "has changed"
                issues.append(f"{name} {state} since the last recorded analysis (entry {analyses[-1]['seq']})")
    signed_seq = None
    sig_path = case_dir / SIGNATURE_FILE
    if key_path is not None:
        key = _read_key(key_path)
        try:
            signature = json.loads(sig_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            signature = None
        if not isinstance(signature, dict):
            issues.append("no readable custody.sig to check against the key")
        else:
            seq = signature.get("seq")
            match = next((e for e in entries if e.get("seq") == seq), None)
            message = f"{seq}:{signature.get('head_hash', '')}".encode("utf-8")
            valid = (signature.get("key_id") == hashlib.sha256(key).hexdigest()[:16] and
                     hmac.compare_digest(str(signature.get("signature", "")), hmac.new(key, message, hashlib.sha256).hexdigest()))
            if not valid:
                issues.append("custody.sig does not verify with this key")
            elif match is None or match.get("hash") != signature.get("head_hash"):
                issues.append(f"signed entry {seq} is missing or differs from the signed hash (log rewritten or truncated)")
            else:
                signed_seq = seq
                if entries and seq < entries[-1].get("seq", 0):
                    notes.append(f"entries {seq + 1}-{entries[-1]['seq']} were added after the last signature")
    elif sig_path.exists():
        notes.append("custody.sig present; pass the key to check it")
    return {"ok": not issues, "entries": len(entries), "issues": issues, "notes": notes, "signed_seq": signed_seq}


def record_analysis(case_dir: Path, result: dict, *, examiner: str = "", case_number: str = "",
                    hash_findings: list[str] | None = None, rules_sha256: str | None = None) -> dict:
    """Append an ``analysis`` entry: evidence file hashes read and report hashes written."""
    outputs = {name: file_sha256(case_dir / name) for name in ("report.json", "report.md", "evidence_manifest.json")}
    details = {
        "evidence_directory": result.get("evidence_directory", ""),
        "case_number": " ".join(str(case_number or "").split())[:MAX_NAME_LENGTH],
        "evidence_files": [{"path": m.get("relative_path"), "sha256": m.get("sha256"), "bytes": m.get("bytes")}
                           for m in result.get("evidence_manifest", [])],
        "hash_changes_since_previous_run": list(hash_findings or []),
        "rules_sha256": rules_sha256,
        "timeline_rows": len(result.get("timeline", [])),
        "validation_issues": len(result.get("validation_issues", [])),
        "outputs": {k: v for k, v in outputs.items() if v},
    }
    return append_entry(case_dir, "analysis", details, examiner)


def _timeline_ids(case_dir: Path) -> set[str]:
    """Event IDs of the case's current timeline rows."""
    try:
        report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"case has no readable report.json: {e}") from e
    return {str(r.get("event_id")) for r in report.get("timeline", []) if isinstance(r, dict) and r.get("event_id")}


def _clean_text(text: str, what: str) -> str:
    """Normalise note text: printable characters and newlines only, non-empty, bounded."""
    cleaned = "".join(ch for ch in str(text) if ch.isprintable() or ch == "\n").strip()
    if not cleaned:
        raise ValueError(f"{what} must not be empty")
    if len(cleaned) > MAX_NOTE_LENGTH:
        raise ValueError(f"{what} is longer than {MAX_NOTE_LENGTH} characters")
    return cleaned


def add_note(case_dir: Path, event_id: str, text: str, examiner: str = "") -> dict:
    """Attach an examiner note to a timeline row (by event ID) of the case's current report."""
    if event_id not in _timeline_ids(case_dir):
        raise ValueError(f"no timeline row with event ID {event_id!r} in this case")
    return append_entry(case_dir, "note_added", {"event_id": event_id, "text": _clean_text(text, "note")}, examiner)


def retract_note(case_dir: Path, note_seq: int, reason: str, examiner: str = "") -> dict:
    """Retract an earlier note; the note stays in the log and the retraction records why."""
    entries, _ = read_log(case_dir)
    note = next((e for e in entries if e.get("seq") == note_seq and e.get("action") == "note_added"), None)
    if note is None:
        raise ValueError(f"entry {note_seq} is not a note")
    if any(e.get("action") == "note_retracted" and e.get("details", {}).get("note_seq") == note_seq for e in entries):
        raise ValueError(f"note {note_seq} is already retracted")
    return append_entry(case_dir, "note_retracted", {"note_seq": note_seq, "event_id": note["details"].get("event_id"),
                                                      "reason": _clean_text(reason, "retraction reason")}, examiner)


def notes_by_event(entries: list[dict]) -> dict[str, list[dict]]:
    """Map event ID to its notes in log order, each with ``retracted`` (the retraction entry or None)."""
    retractions = {e["details"].get("note_seq"): e for e in entries
                   if e.get("action") == "note_retracted" and isinstance(e.get("details"), dict)}
    out: dict[str, list[dict]] = {}
    for e in entries:
        if e.get("action") == "note_added" and isinstance(e.get("details"), dict):
            out.setdefault(str(e["details"].get("event_id")), []).append({**e, "retracted": retractions.get(e.get("seq"))})
    return out


def custody_view(case_dir: Path, key_path: Path | None = None) -> dict | None:
    """Everything the HTML report needs about custody, or None when the case has no log."""
    if not (case_dir / CUSTODY_FILE).exists():
        return None
    entries, _ = read_log(case_dir)
    return {"entries": entries, "verification": verify_log(case_dir, key_path), "notes": notes_by_event(entries)}


def case_info_from_log(entries: list[dict]) -> dict[str, str]:
    """Case number and examiner from the latest analysis entry, for report headers."""
    for e in reversed(entries):
        if e.get("action") == "analysis":
            info = {}
            if e.get("details", {}).get("case_number"):
                info["Case number"] = str(e["details"]["case_number"])
            if e.get("examiner") and e["examiner"] != "unspecified":
                info["Examiner"] = str(e["examiner"])
            return info
    return {}


CUSTODY_LIMITATION = ("The chain-of-custody log is hash-chained, so edits, removals and reordering of entries are detected; "
                      "without the external HMAC key a person with write access could rebuild the whole log, and entries "
                      "added after the last signature are not covered by it. Examiner names are as entered, and OS user "
                      "and host names are as reported by the analysis machine.")
