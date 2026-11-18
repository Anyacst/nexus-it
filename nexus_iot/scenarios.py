"""Deterministic synthetic testbed, isolated from user evidence directories."""
from __future__ import annotations
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

CONDITIONS = {
    "E1": "Normal operation", "E2": "Device disconnection", "E3": "Missing log entries",
    "E4": "Timestamp manipulation", "E5": "Gateway packet loss", "E6": "Evidence tampering",
    "E7": "Multiple failures combined", "T1": "Tamper control: edit only", "T2": "Tamper control: insertion only",
    "T3": "Inference control: omitted periodic event",
}
MARKER_NAME = ".nexus-iot-generated.json"
MARKER_VERSION = "5"


def build(project_root: Path, regenerate: bool = False) -> Path:
    """Create or verify the owned synthetic dataset; never overwrite unmarked/changed files."""
    target = project_root / "data" / "synthetic"
    marker = target / MARKER_NAME
    if target.exists():
        if target.is_symlink() or marker.is_symlink():
            raise RuntimeError(f"Refusing to follow a symlink in the synthetic dataset path: {target}")
        if not marker.is_file():
            raise RuntimeError(f"Refusing to write synthetic fixtures into unmarked directory: {target}")
        try:
            manifest = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Invalid synthetic dataset marker: {marker}") from e
        expected = manifest.get("files", {})
        actual = {p.relative_to(target).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for p in target.rglob("*") if p.is_file() and p != marker}
        if actual != expected:
            raise RuntimeError(f"Synthetic dataset contains modified, missing, or untracked files; refusing to overwrite: {target}")
        if manifest.get("generator_version") == MARKER_VERSION:
            return target
        if not regenerate:
            raise RuntimeError(f"Synthetic dataset version differs. Use evaluate --regenerate after reviewing the verified generated files: {target}")
        backup = target.with_name(target.name+".verified-old")
        if backup.exists():
            raise RuntimeError(f"Refusing regeneration because backup path already exists: {backup}")
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".nexus-iot-synthetic-", dir=target.parent))
        try:
            _write_dataset(staging)
            files = {p.relative_to(staging).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in staging.rglob("*") if p.is_file()}
            (staging/MARKER_NAME).write_text(json.dumps({"generator_version":MARKER_VERSION, "files":files}, indent=2), encoding="utf-8")
            target.replace(backup)
            try:
                staging.replace(target)
            except Exception:
                backup.replace(target)
                raise
            shutil.rmtree(backup)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".nexus-iot-synthetic-", dir=target.parent))
    try:
        _write_dataset(staging)
        files = {p.relative_to(staging).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
               for p in staging.rglob("*") if p.is_file()}
        (staging/MARKER_NAME).write_text(json.dumps({"generator_version":MARKER_VERSION, "files":files}, indent=2), encoding="utf-8")
        staging.replace(target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def _write_dataset(root: Path) -> None:
    """Write all synthetic evidence folders and their separate ground-truth files."""
    evid_root, truth_root = root / "evidence", root / "ground_truth"
    base = 1_794_000_000.0
    scenario = [
        (0.0, "sensor-A", "boot"), (2.0, "sensor-A", "auth_fail"), (3.0, "sensor-B", "alert"),
        (4.0, "sensor-A", "command"), (6.0, "sensor-B", "heartbeat"), (8.0, "sensor-A", "link_down"),
        (10.0, "sensor-B", "heartbeat"), (12.0, "sensor-A", "recovery"), (14.0, "sensor-B", "heartbeat"),
        (16.0, "sensor-A", "command"), (18.0, "sensor-B", "heartbeat"), (22.0, "sensor-B", "heartbeat"),
    ]
    for case, title in CONDITIONS.items():
        evdir, truthdir = evid_root/case, truth_root/case
        evdir.mkdir(parents=True)
        truthdir.mkdir(parents=True)
        truth = []
        device_rows = {"sensor-A":[], "sensor-B":[]}
        gateway_candidates = []
        seq = {"sensor-A":0, "sensor-B":0}
        disconnect = case in {"E2", "E7"}
        for index, (delta, device, event) in enumerate(scenario, 1):
            eid = f"ev-{index:03d}"
            when = base+delta
            # In E2/E7, later sensor-A ground-truth events do not occur after disconnection.
            if disconnect and device == "sensor-A" and index > 2:
                continue
            seq[device] += 1
            truth.append({"event_id":eid, "timestamp":when, "device":device, "event":event,
                          "expected_sources":[f"{device}.jsonl", "gateway.jsonl"],
                          "source_sequences":{f"{device}.jsonl":seq[device]}})
            offset = 5.0 if device == "sensor-A" else -2.0
            if case == "E4" and device == "sensor-A" and index >= 4:
                offset += 12.0
            if case == "E7" and device == "sensor-B" and index >= 9:
                offset += 12.0
            # Disconnection removes subsequent device and gateway observations for A.
            # E3/E7 remove a B device log entry independent of the disconnect.
            if not (case in {"E3", "E7", "T3"} and eid == "ev-007"):
                device_rows[device].append({"event_id":eid, "sequence":seq[device], "timestamp":when+offset,
                                            "device":device, "event":event})
            gateway_candidates.append({"event_id":eid, "timestamp":when, "event":event, "peer":device})
        if disconnect:
            truth.append({"event_id":"disconnect-A", "timestamp":base+4.5, "device":"gateway", "event":"device_disconnected",
                          "expected_sources":["gateway.jsonl"]})
            gateway_candidates.append({"event_id":"disconnect-A", "timestamp":base+4.5, "event":"device_disconnected", "affected_device":"sensor-A"})
        gateway_candidates.sort(key=lambda r:r["timestamp"])
        for n, row in enumerate(gateway_candidates, 1):
            row["sequence"] = n
        gateway_sequences = {r["event_id"]:r["sequence"] for r in gateway_candidates}
        for expected in truth:
            if "gateway.jsonl" in expected["expected_sources"]:
                expected.setdefault("source_sequences", {})["gateway.jsonl"] = gateway_sequences[expected["event_id"]]
        dropped = {"E5":{"ev-003", "ev-004"}, "E7":{"ev-003"}}.get(case, set())
        if case == "T3":
            dropped.add("ev-007")
        gateway = [r for r in gateway_candidates if r["event_id"] not in dropped]
        if case in {"E6", "E7", "T1"}:
            existing = next((r for r in device_rows["sensor-A"] if r["event_id"] == "ev-002"), None)
            if existing:
                existing["event"] = "maintenance"
        if case in {"E6", "E7", "T2"}:
            # A plausible next sequence value is used; the out-of-order timestamp is the tamper clue.
            device_rows["sensor-A"].append({"event_id":"inject-001", "sequence":seq["sensor-A"]+1,
                "timestamp":base+5.5, "device":"sensor-A", "event":"injected_admin_login"})
        write_jsonl(evdir/"sensor-A.jsonl", device_rows["sensor-A"])
        write_jsonl(evdir/"sensor-B.jsonl", device_rows["sensor-B"])
        write_jsonl(evdir/"gateway.jsonl", gateway)
        # Ground truth contains expected evidence sources and is not passed to the pipeline.
        (truthdir/"truth.json").write_text(json.dumps({"condition":title, "events":truth,
            "tampering_seeded":case in {"E6", "E7", "T1", "T2"},
            "clock_manipulated":case in {"E4", "E7"},
            "tamper_mechanisms":(["edit", "insert"] if case in {"E6", "E7"} else ["edit"] if case == "T1" else ["insert"] if case == "T2" else []),
            "expected_record_count":sum(len(e["expected_sources"]) for e in truth)}, indent=2), encoding="utf-8")
    build_sample_capture(root)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    """Write rows as UTF-8 JSON Lines."""
    path.write_text("".join(json.dumps(r, sort_keys=True)+"\n" for r in rows), encoding="utf-8")


def build_sample_capture(root: Path) -> Path:
    """Write a tiny synthetic Ethernet/IPv4/UDP PCAP inside a caller-owned test folder."""
    import ipaddress, struct
    def frame(src, dst, sport, dport):
        udp = struct.pack("!HHHH", sport, dport, 8, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0, ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
        return bytes.fromhex("0200000000020200000000010800")+ip+udp
    path = root/"sample_inputs"/"gateway-demo.pcap"
    path.parent.mkdir(parents=True, exist_ok=True)
    frames = [(frame("192.0.2.10", "198.51.100.20", 42000, 1883), 1_794_000_000), (frame("198.51.100.20", "192.0.2.10", 1883, 42000), 1_794_000_002)]
    data = bytearray(b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for packet, ts in frames:
        data.extend(struct.pack("<IIII", ts, 0, len(packet), len(packet))+packet)
    path.write_bytes(data)
    return path
