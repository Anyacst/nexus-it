"""Evidence acquisition, hashing and parsing of supplied JSONL logs and captures."""
from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .capture import CaptureError, packets
from .mqtt import DEFAULT_PORTS as DEFAULT_MQTT_PORTS, mqtt_messages


SUPPORTED = {".jsonl", ".pcap", ".pcapng"}


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: Any) -> float:
    """Accept Unix seconds or ISO-8601 with timezone; reject ambiguous naive strings."""
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    if isinstance(value, (int, float)):
        v = float(value)
        if not math.isfinite(v):
            raise ValueError("timestamp must be finite")
        return v
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError("expected Unix seconds or ISO-8601 timestamp") from e
        if dt.tzinfo is None:
            raise ValueError("ISO-8601 timestamp must include a timezone")
        return dt.astimezone(timezone.utc).timestamp()
    raise ValueError("timestamp must be numeric or ISO-8601 text")


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Read a JSON Lines file; return the object rows and one error string per bad line."""
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        with path.open(encoding="utf-8-sig") as f:
            for n, raw in enumerate(f, 1):
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw)
                    if not isinstance(row, dict):
                        raise ValueError("record must be a JSON object")
                    rows.append(row)
                except (json.JSONDecodeError, ValueError) as e:
                    errors.append(f"{path.name}:{n}: malformed JSON record ({e})")
    except (OSError, UnicodeError) as e:
        errors.append(f"{path.name}: cannot read text evidence ({e})")
    return rows, errors


def acquire(evidence_dir: Path, snapshot_dir: Path, previous: list[dict] | None = None) -> tuple[list[dict], list[str]]:
    """Snapshot inputs, hashing the exact copy later parsed by the pipeline."""
    prior = {x.get("relative_path"): x.get("sha256") for x in (previous or []) if isinstance(x, dict)}
    now = utc_now()
    entries = []
    findings = []
    files = sorted(p for p in evidence_dir.rglob("*") if p.is_file() and (p.suffix.lower() in SUPPORTED or p.name == "devices.json"))
    for path in files:
        rel = path.relative_to(evidence_dir).as_posix()
        snap = snapshot_dir/Path(rel)
        snap.parent.mkdir(parents=True, exist_ok=True)
        try:
            before = path.stat()
            with path.open("rb") as source, snap.open("wb") as target:
                opened_before = os.fstat(source.fileno())
                shutil.copyfileobj(source, target, 1024*1024)
                opened_after = os.fstat(source.fileno())
            after = path.stat()
            stable = (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino) == (opened_before.st_size, opened_before.st_mtime_ns, opened_before.st_ino) == (opened_after.st_size, opened_after.st_mtime_ns, opened_after.st_ino)
            hasher = hashlib.sha256()
            with snap.open("rb") as stream:
                for chunk in iter(lambda:stream.read(1024*1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
        except OSError as e:
            findings.append(f"{rel}: could not snapshot/hash evidence ({e})")
            try:
                snap.unlink()
            except OSError:
                pass
            continue
        entries.append({"filename": path.name, "relative_path": rel, "source": path.parent.relative_to(evidence_dir).as_posix() or ".",
                        "collection_time": now, "sha256": digest, "bytes": snap.stat().st_size, "snapshot_stable":stable})
        if not stable:
            findings.append(f"{rel}: source metadata changed during snapshot; parsed snapshot may represent an unstable source")
        if rel in prior and prior[rel] != digest:
            findings.append(f"{rel}: SHA-256 differs from the prior project manifest; bytes changed since that recorded run")
    disappeared = sorted(set(prior) - {x["relative_path"] for x in entries})
    findings.extend(f"{name}: file present in prior manifest is now missing" for name in disappeared)
    return entries, findings


def _read_devices_config(root: Path) -> dict[str, Any]:
    """Load the optional devices.json from the evidence root ({} if absent, an error marker if invalid)."""
    p = root / "devices.json"
    if not p.exists():
        return {}
    try:
        value = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("expected an object")
        return value
    except (OSError, json.JSONDecodeError, ValueError) as e:
        return {"_config_error": f"devices.json: invalid configuration ({e})"}


def _normalise_json_rows(path: Path, root: Path, errors: list[str]) -> list[dict]:
    """Turn one JSONL file into normalised evidence rows, reporting invalid records in errors."""
    records, errs = read_jsonl(path)
    errors.extend(errs)
    out = []
    gateway = path.name.lower().startswith("gateway")
    for n, row in enumerate(records, 1):
        try:
            timestamp = parse_time(row["timestamp"])
            event = row.get("event", row.get("type"))
            if not isinstance(event, str) or not event.strip():
                raise ValueError("event must be non-empty text")
            device = "gateway" if gateway else row.get("device")
            if not gateway and (not isinstance(device, str) or not device.strip()):
                raise ValueError("device must be non-empty text")
            rel = path.relative_to(root).as_posix()
            out.append({"timestamp": timestamp, "raw_timestamp": row["timestamp"], "event": event.strip(),
                "device": device, "source_file": rel, "source_id": str(row.get("source_id") or rel), "record": n,
                "event_id": str(row.get("event_id") or "").strip(),
                "sequence": row.get("sequence"), "peer": str(row.get("peer") or ""),
                "metadata": {k: v for k, v in row.items() if k not in {"timestamp", "event", "type", "device", "source_id", "event_id", "sequence", "peer"}}})
        except (KeyError, TypeError, ValueError) as e:
            errors.append(f"{path.name}: record {n}: invalid evidence fields ({e})")
    return out


MQTT_CONTROL_EVENTS = {"CONNECT": "mqtt_connect", "DISCONNECT": "mqtt_disconnect", "SUBSCRIBE": "mqtt_subscribe"}


def _device_ip_map(config: dict) -> dict[str, set[str]]:
    """devices.json device_ips as {device: {ip, ...}}; malformed entries are ignored."""
    ips = config.get("device_ips", {})
    if not isinstance(ips, dict):
        return {}
    mapping = {}
    for device, values in ips.items():
        vals = [values] if isinstance(values, str) else values if isinstance(values, list) else []
        mapping[str(device)] = {str(v) for v in vals}
    return mapping


def _mqtt_ports(config: dict, errors: list[str]) -> set[int]:
    """Broker ports from devices.json ``mqtt_ports`` (default 1883)."""
    value = config.get("mqtt_ports")
    if value is None:
        return set(DEFAULT_MQTT_PORTS)
    if (isinstance(value, list) and value and
            all(isinstance(p, int) and not isinstance(p, bool) and 0 < p <= 65535 for p in value)):
        return set(value)
    errors.append("devices.json: mqtt_ports must be a non-empty list of TCP port numbers; using the default 1883")
    return set(DEFAULT_MQTT_PORTS)


def mqtt_rows(path: Path, root: Path, config: dict, errors: list[str]) -> list[dict]:
    """Turn decoded MQTT traffic in one capture into evidence rows.

    A client-to-broker PUBLISH whose JSON payload names ``event_id``, ``event`` and ``device``
    becomes a gateway-clock event row (``source_id`` = the capture file, ``peer`` = payload
    device). Broker-to-subscriber copies are skipped so one publish is counted once.
    CONNECT, DISCONNECT and SUBSCRIBE become ``mqtt_*`` network-observation rows. Decoder
    problems, topic/client/IP mismatches, and unacknowledged QoS 1/2 publishes are appended to
    ``errors`` as validation findings.
    """
    rel = path.relative_to(root).as_posix()
    messages, findings = mqtt_messages(path, _mqtt_ports(config, errors))
    errors.extend(findings)
    ip_map = _device_ip_map(config)
    rows: list[dict] = []
    seen_publishes: set[tuple[str, str]] = set()
    unacknowledged: list[str] = []
    for index, message in enumerate(messages, 1):
        kind = message["type"]
        if message["direction"] != "client_to_broker":
            continue
        flow = {k: message[k] for k in ("source_ip", "source_port", "destination_ip", "destination_port")}
        base = {"timestamp": message["timestamp"], "raw_timestamp": message["timestamp"], "device": "gateway",
                "source_file": rel, "source_id": rel, "record": message["packet"], "sequence": None,
                "capture_derived": True, "mqtt_type": kind, "mqtt_index": index}
        where = f"{rel} packet {message['packet']}"
        if kind in MQTT_CONTROL_EVENTS:
            endpoints = {message["source_ip"], message["destination_ip"]}
            details = {k: message[k] for k in ("client_id", "packet_id", "topics", "keep_alive", "clean_session",
                                               "protocol_level", "username") if message.get(k) is not None}
            rows.append({**base, **flow, "event": MQTT_CONTROL_EVENTS[kind], "event_id": "", "peer": "",
                         "protocol": "tcp", "mqtt_control": True, "mqtt": {"type": kind, **details},
                         "mapped_devices": sorted(d for d, addresses in ip_map.items() if endpoints & addresses),
                         "metadata": {"client_id": message.get("client_id"), **flow}})
            continue
        if kind != "PUBLISH":
            continue
        payload = message.get("payload") or {}
        event_id, event, device = payload.get("event_id"), payload.get("event"), payload.get("device")
        topic = message["topic"]
        if not all(isinstance(x, str) and x.strip() for x in (event_id, event, device)):
            errors.append(f"{where}: MQTT PUBLISH on topic '{topic}' has no JSON event_id/event/device payload; not used as event evidence")
            continue
        event_id, event, device = event_id.strip(), event.strip(), device.strip()
        client_id = message.get("client_id")
        if message["acknowledged"] is False:
            unacknowledged.append(event_id)
            continue
        if message["dup"] and (client_id or message["source_ip"], event_id) in seen_publishes:
            continue  # QoS redelivery of a publish already recorded from this client.
        seen_publishes.add((client_id or message["source_ip"], event_id))
        if topic != f"nexus/{device}/{event}":
            errors.append(f"{where}: MQTT topic mismatch for {event_id}: topic '{topic}' but payload names device '{device}' and event '{event}' (expected 'nexus/{device}/{event}')")
        if client_id is not None and client_id != device:
            errors.append(f"{where}: MQTT client id '{client_id}' published {event_id} for payload device '{device}'")
        if device in ip_map and message["source_ip"] not in ip_map[device]:
            errors.append(f"{where}: MQTT PUBLISH {event_id} for '{device}' came from {message['source_ip']}, which devices.json device_ips does not list for that device")
        rows.append({**base, "event": event, "event_id": event_id, "peer": device,
                     "metadata": {"topic": topic, "client_id": client_id, "mqtt_packet_id": message.get("packet_id"),
                                  "device_timestamp": payload.get("timestamp"), "qos": message["qos"], **flow}})
    if unacknowledged:
        sample = ", ".join(unacknowledged[:20]) + (" (more omitted)" if len(unacknowledged) > 20 else "")
        errors.append(f"{rel}: {len(unacknowledged)} MQTT PUBLISH message(s) were seen on the wire but not acknowledged by the broker within the capture ({sample}); "
                      "they were not used as event evidence because broker delivery and timing are unproven")
    return rows


def _load_evidence(root: Path, errors: list[str], config: dict | None = None) -> list[dict]:
    """Load every JSONL log, packet summary and MQTT row under root into one list of evidence rows."""
    out = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".jsonl"):
        out.extend(_normalise_json_rows(path, root, errors))
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}):
        try:
            for packet in packets(path, aggregate_seconds=1.0):
                packet.update({"raw_timestamp": packet["timestamp"], "device": "gateway", "source_file": path.relative_to(root).as_posix(),
                    "source_id": path.relative_to(root).as_posix(), "event_id": "", "sequence": None, "record": packet["packet"], "peer": ""})
                out.append(packet)
        except (OSError, CaptureError) as e:
            errors.append(f"{path.name}: capture parse failed ({e})")
        out.extend(mqtt_rows(path, root, config or {}, errors))
    return out
