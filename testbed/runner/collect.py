"""Copy one run's outputs into a case folder, then build ground truth and apply tampering.

Case layout (testbed/CONTRACT.md):

    <case_dir>/evidence/        device logs, gateway.jsonl, gateway-*.pcap, devices.json
    <case_dir>/ground_truth/truth.json
    <case_dir>/original/        byte-identical pre-tamper copy of evidence/ + SHA256SUMS
    <case_dir>/extra/           mosquitto.log, run.json
"""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict
from pathlib import Path

from .scenarios import CONTAINER_IPS, DEVICE_CONTAINERS, DEVICE_EVENTS, Scenario
from .tamper import apply_tamper
from .truth import GATEWAY_FILE, build_truth, load_jsonl

# DEVICE_EVENTS (re-exported here) mirrors the per-device behaviour table in the
# contract (devicecore.DEVICE_PROFILES); it lives in scenarios.py so the host
# runner does not depend on the container-side package.
__all__ = ["DEVICE_EVENTS", "collect_case", "devices_config", "sha256_file", "write_json"]

BOOT_EVENT = "boot"
MQTT_PORT = 1883
CORRELATION_WINDOW_S = 2.0

EVIDENCE_LOGS: tuple[str, ...] = tuple(f"{device}.jsonl" for device in DEVICE_EVENTS) + (GATEWAY_FILE,)
PCAP_GLOB = "gateway-*.pcap"
DEVICES_FILE = "devices.json"
SUMS_FILE = "SHA256SUMS"
BROKER_LOG = "mosquitto.log"


def devices_config() -> dict:
    """Return the devices.json payload: device IPs and one MQTT rule per (device, event) incl. boot."""
    device_ips = {device: [CONTAINER_IPS[DEVICE_CONTAINERS[device]]] for device in DEVICE_EVENTS}
    rules = []
    for device, events in DEVICE_EVENTS.items():
        for event in [BOOT_EVENT, *events]:
            rules.append(
                {
                    "id": f"{device}-{event}-mqtt",
                    "device": device,
                    "event": event,
                    "protocol": "tcp",
                    "direction": "outbound",
                    "destination_port": MQTT_PORT,
                    "window_seconds": CORRELATION_WINDOW_S,
                }
            )
    return {"device_ips": device_ips, "correlation_rules": rules}


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: object) -> None:
    """Write pretty-printed JSON with a trailing newline."""
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _copy_evidence(run_dir: Path, evidence_dir: Path) -> tuple[list[str], list[str]]:
    """Copy the device logs, gateway.jsonl and all capture files. Returns (copied names, missing names)."""
    copied: list[str] = []
    missing: list[str] = []
    for name in EVIDENCE_LOGS:
        source = run_dir / "logs" / name
        if source.is_file():
            shutil.copy2(source, evidence_dir / name)
            copied.append(name)
        else:
            missing.append(name)
    pcaps = sorted((run_dir / "capture").glob(PCAP_GLOB))
    if not pcaps:
        missing.append(PCAP_GLOB)
    for pcap in pcaps:
        shutil.copy2(pcap, evidence_dir / pcap.name)
        copied.append(pcap.name)
    return copied, missing


def _write_original(evidence_dir: Path, original_dir: Path) -> None:
    """Copy every evidence file byte-for-byte into original/ and write SHA256SUMS."""
    original_dir.mkdir()
    lines = []
    for path in sorted(p for p in evidence_dir.iterdir() if p.is_file()):
        shutil.copy2(path, original_dir / path.name)
        lines.append(f"{sha256_file(original_dir / path.name)}  {path.name}\n")
    (original_dir / SUMS_FILE).write_text("".join(lines), encoding="utf-8")


def _load_device_truth(truth_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(truth_dir.glob("*.truth.jsonl")):
        rows.extend(load_jsonl(path))
    return rows


def collect_case(run_dir: Path, case_dir: Path, scenario: Scenario, run_meta: dict) -> Path:
    """Build the case folder for one finished run and return its path.

    Steps: copy evidence, write devices.json, snapshot original/ + SHA256SUMS,
    build ground truth from the run's truth files and the PRE-TAMPER gateway log,
    apply the scenario's tamper ops to evidence/ only, write extra/.
    Raises FileExistsError if `case_dir` already holds files.
    """
    run_dir = Path(run_dir)
    case_dir = Path(case_dir)
    if case_dir.exists() and any(case_dir.iterdir()):
        raise FileExistsError(f"case folder is not empty: {case_dir}")

    evidence_dir = case_dir / "evidence"
    original_dir = case_dir / "original"
    truth_dir = case_dir / "ground_truth"
    extra_dir = case_dir / "extra"
    for folder in (evidence_dir, truth_dir, extra_dir):
        folder.mkdir(parents=True)

    copied, missing = _copy_evidence(run_dir, evidence_dir)
    write_json(evidence_dir / DEVICES_FILE, devices_config())
    _write_original(evidence_dir, original_dir)

    gateway_path = original_dir / GATEWAY_FILE
    gateway_rows = load_jsonl(gateway_path) if gateway_path.is_file() else []
    truth = build_truth(scenario, _load_device_truth(run_dir / "truth"), gateway_rows)
    write_json(truth_dir / "truth.json", truth)

    tamper_log = apply_tamper(evidence_dir, scenario.tamper)

    broker_log = run_dir / "broker" / BROKER_LOG
    if broker_log.is_file():
        shutil.copy2(broker_log, extra_dir / BROKER_LOG)

    meta = dict(run_meta)
    meta.setdefault("scenario_id", scenario.id)
    meta.setdefault("scenario", asdict(scenario))
    meta.setdefault("parameters", scenario.parameters)
    meta["evidence_files"] = copied + [DEVICES_FILE]
    meta["missing_evidence"] = missing
    meta["tamper_log"] = tamper_log
    write_json(extra_dir / "run.json", meta)
    return case_dir
